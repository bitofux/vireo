/* PROJECT: VIREO; FILE: auth_process.c; AUTHOR: bitofux; DATE: 2026-10-20.
 * 只组合公开owner合同，不读取其他模块私有状态。 */
#define _GNU_SOURCE
#include "auth_process.h"
#include "auth_process_internal.h"
#include "auth_worker_runtime.h"
#include "directory_move_worker_runtime.h"
#include <vireo/net/auth_service.h>
#include <vireo/net/auth_service_deadline.h>
#include <vireo/net/directory_move_reactor.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/base/secure_clear.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define MEMORY ((size_t)67108864)
#define REQUEST_TIMEOUT UINT64_C(10000000000)
#define CLEANUP_ATTEMPTS ((size_t)8192)
#define STAT_OPERATION UINT32_C(104)
#define ROOT_OPERATION UINT32_C(105)
#define LIST_OPERATION UINT32_C(106)
#define MKDIR_OPERATION UINT32_C(107)
#define MOVE_OPERATION UINT32_C(108)
/** 文件owner按实际分配尺寸擦除；尾后NUL不计入输入长度。 */
typedef struct material { unsigned char *bytes; size_t size, capacity; } material_t;
/** 仅主线程拥有；runtime发布后固定，faults为唯一并发字段。 */
typedef struct process {
    int signal_fd, listener_fd;
    material_t certificate, key, password;
    vireo_tls_context_t *tls;
    vireo_acceptor_t *listener;
    vireo_mysql_runtime_t *mysql;
    vireo_mysql_thread_t *thread;
    vireo_mysql_pool_t *database, *audit_database;
    vireo_auth_failure_audit_t *audit;
    vireo_auth_failure_writer_t audit_writer;
    vireo_auth_password_gate_t *gate;
    vireo_auth_login_verifier_t *verifier;
    vireo_tcp_server_t *server;
    vireo_inflight_store_t *store;
    vireo_auth_sessions_t *sessions;
    vireo_task_queue_t *tasks;
    vireo_thread_pool_t *workers;
    vireo_completion_queue_t *queue, *stat_queue, *root_queue, *list_queue, *mkdir_queue, *move_queue;
    vireo_page_token_key_t *page_key; /**< 全部原线程owner销毁和join后才释放。 */
    vireo_notifier_t *notifier;
    vireo_auth_login_admission_t *admission;
    vireo_auth_service_t *service;
    vireo_timer_wheel_t *deadline_wheel; /**< 本线程拥有，服务销毁后才释放。 */
    vireo_auth_worker_runtime_t runtime;
    bool runtime_initialized;
    vireo_directory_stat_worker_runtime_t mixed_runtime;
    bool mixed_runtime_initialized;
    vireo_directory_root_worker_runtime_t root_runtime;
    bool root_runtime_initialized;
    vireo_directory_list_worker_runtime_t list_runtime;
    bool list_runtime_initialized;
    vireo_directory_mkdir_worker_runtime_t mkdir_runtime;
    bool mkdir_runtime_initialized;
    vireo_directory_move_worker_runtime_t move_runtime;
    bool move_runtime_initialized;
} process_t;
/** 只有本进程应用层负责无法安全返回的残留owner。 */
static void fatal(void) { _Exit(EXIT_FAILURE); }
static void wipe(material_t *m)
{
    if (m->bytes) { (void)vireo_secure_clear(m->bytes,m->capacity); free(m->bytes); }
    *m=(material_t){0};
}
/** 不打开阻塞FIFO；每次read有界，增长文件亦不能越界，close不在EINTR后重试。 */
static vireo_result_t load(char const *path,size_t limit,material_t *m)
{
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NONBLOCK);
    if (fd<0) return VIREO_RESULT_INTERNAL;
    struct stat st;
    vireo_result_t rc=VIREO_OK;
    if (fstat(fd,&st)!=0 || !S_ISREG(st.st_mode)) rc=VIREO_RESULT_INVALID_ARGUMENT;
    if (rc==VIREO_OK && (st.st_size<0 || (uintmax_t)st.st_size>limit)) rc=VIREO_RESULT_RANGE;
    if (rc==VIREO_OK) {
        m->capacity=limit+2; m->bytes=calloc(m->capacity,1);
        if (!m->bytes) rc=VIREO_RESULT_NO_MEMORY;
    }
    while (rc==VIREO_OK) {
        ssize_t n=read(fd,m->bytes+m->size,limit+1-m->size);
        if (n<0 && errno==EINTR) continue;
        if (n<0) { rc=VIREO_RESULT_INTERNAL; break; }
        if (!n) break;
        m->size+=(size_t)n;
        if (m->size>limit) rc=VIREO_RESULT_RANGE;
    }
    if (close(fd)!=0 && rc==VIREO_OK) rc=VIREO_RESULT_INTERNAL;
    return rc;
}
static vireo_result_t signals(process_t *p)
{
    struct sigaction action={0}; action.sa_handler=SIG_IGN;
    sigset_t mask;
    if (sigemptyset(&action.sa_mask)!=0 || sigaction(SIGPIPE,&action,NULL)!=0 ||
        sigemptyset(&mask)!=0 || sigaddset(&mask,SIGINT)!=0 || sigaddset(&mask,SIGTERM)!=0 ||
        pthread_sigmask(SIG_BLOCK,&mask,NULL)!=0) return VIREO_RESULT_INTERNAL;
    p->signal_fd=signalfd(-1,&mask,SFD_NONBLOCK|SFD_CLOEXEC);
    return p->signal_fd<0?VIREO_RESULT_INTERNAL:VIREO_OK;
}
/** 一次读取只保存首停止信号；信号不是异步资源操作。 */
static vireo_result_t stop_signal(process_t *p,vireo_auth_process_report_t *r)
{
    struct signalfd_siginfo info;
    ssize_t n;
    do { n=read(p->signal_fd,&info,sizeof info); } while (n<0 && errno==EINTR);
    if (n<0 && errno==EAGAIN) return VIREO_OK;
    if (n!=(ssize_t)sizeof info) return VIREO_RESULT_INTERNAL;
    if (!r->stop_signal) r->stop_signal=(int)info.ssi_signo;
    return VIREO_OK;
}
/**
 * @brief 按实际初始化阶段读取已初始化的独立故障域，不访问未初始化原子
 * @param[in] p 必需主线程存活装配对象；初始化标志仅本线程写，context寿命覆盖采样。
 * @return 六个独立永久位样本（未启用域为0）；尚未初始化的域为0，不是同时性或工作完成证明。
 * @note inspect意外失败无法可靠执行故障政策，沿应用fatal退出；正常路径保持errno。
 */
static vireo_directory_move_worker_faults_t faults(process_t const *p)
{
    vireo_directory_move_worker_faults_t bits={0};
    if (p->move_runtime_initialized) {
        if (vireo_directory_move_worker_runtime_inspect_faults(&p->move_runtime,&bits)!=VIREO_OK) fatal();
    } else if (p->mkdir_runtime_initialized) {
        vireo_directory_mkdir_worker_faults_t before={0};
        if (vireo_directory_mkdir_worker_runtime_inspect_faults(&p->mkdir_runtime,&before)!=VIREO_OK) fatal();
        bits.auth=before.auth; bits.stat=before.stat; bits.root=before.root; bits.list=before.list; bits.mkdir=before.mkdir;
    } else if (p->list_runtime_initialized) {
        vireo_directory_list_worker_faults_t before={0};
        if (vireo_directory_list_worker_runtime_inspect_faults(&p->list_runtime,&before)!=VIREO_OK) fatal();
        bits.auth=before.auth; bits.stat=before.stat; bits.root=before.root; bits.list=before.list;
    } else if (p->root_runtime_initialized) {
        vireo_directory_root_worker_faults_t before={0};
        if (vireo_directory_root_worker_runtime_inspect_faults(&p->root_runtime,&before)!=VIREO_OK) fatal();
        bits.auth=before.auth; bits.stat=before.stat; bits.root=before.root;
    } else if (p->mixed_runtime_initialized) {
        vireo_directory_stat_worker_faults_t before={0};
        if (vireo_directory_stat_worker_runtime_inspect_faults(&p->mixed_runtime,&before)!=VIREO_OK) fatal();
        bits.auth=before.auth; bits.stat=before.stat;
    } else if (p->runtime_initialized && vireo_auth_worker_runtime_inspect_faults(&p->runtime,&bits.auth)!=VIREO_OK) fatal();
    return bits;
}
/** 有界竞争期间保持Reactor进度；不把一次BUSY当作close广播成功。 */
static vireo_result_t progress(process_t *p)
{
    vireo_result_t rc=VIREO_OK;
    if (p->service) { vireo_auth_service_report_t report; rc=vireo_auth_service_once(p->service,0,&report); }
    (void)sched_yield(); return rc;
}
/** 记录清理首错，owner残留由调用者独立检查。 */
static void cleanup_result(vireo_auth_process_report_t *r,vireo_result_t rc)
{ if (r->cleanup_result==VIREO_OK && rc!=VIREO_OK) r->cleanup_result=rc; }
vireo_result_t vireo_auth_process_join_with(vireo_thread_pool_t *pool,size_t attempts,
    vireo_result_t (*join)(vireo_thread_pool_t *,vireo_thread_pool_report_t *),vireo_thread_pool_report_t *out)
{
    int const saved=errno; vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(pool && attempts && join && out) {
        for(size_t i=0;i<attempts;++i) {
            vireo_thread_pool_report_t report={0}; rc=join(pool,&report); *out=report;
            if(rc!=VIREO_RESULT_BUSY || report.stage!=VIREO_THREAD_POOL_STAGE_CHECK_QUEUE) break;
            (void)sched_yield();
        }
    }
    errno=saved; return rc;
}
/** 所有启用提交端分别确认关闭后才join；不依据总rc或closed快照推导广播/线程回收事实。 */
static void shutdown_workers(process_t *p,vireo_auth_process_report_t *r)
{
    if (p->audit && vireo_auth_failure_audit_close(p->audit,VIREO_AUTH_FAILURE_STOP)!=VIREO_OK) fatal();
    if (p->service) cleanup_result(r,vireo_auth_service_quiesce(p->service));
    if (p->server) cleanup_result(r,vireo_tcp_server_request_stop(p->server,NULL));
    bool tasks_closed=p->tasks==NULL,queue_closed=p->queue==NULL,stat_closed=p->stat_queue==NULL,root_closed=p->root_queue==NULL,list_closed=p->list_queue==NULL,mkdir_closed=p->mkdir_queue==NULL,move_closed=p->move_queue==NULL;
    for (size_t i=0;i<CLEANUP_ATTEMPTS && (!tasks_closed || !queue_closed || !stat_closed || !root_closed || !list_closed || !mkdir_closed || !move_closed);++i) {
        if (!tasks_closed) {
            vireo_task_queue_close_report_t report;
            vireo_result_t rc=vireo_task_queue_close(p->tasks,VIREO_TASK_QUEUE_CANCEL_PENDING,&report);
            if (rc!=VIREO_OK && rc!=VIREO_RESULT_BUSY) fatal();
            tasks_closed=rc==VIREO_OK;
            if (tasks_closed) r->queues_closed|=1u;
        }
        if (!queue_closed) {
            vireo_completion_queue_close_report_t report;
            vireo_result_t rc=vireo_completion_queue_close(p->queue,&report);
            if (rc!=VIREO_OK && rc!=VIREO_RESULT_BUSY) fatal();
            queue_closed=rc==VIREO_OK;
            if (queue_closed) r->queues_closed|=2u;
        }
        if (!stat_closed) {
            vireo_completion_queue_close_report_t report;
            vireo_result_t rc=vireo_completion_queue_close(p->stat_queue,&report);
            if (rc!=VIREO_OK && rc!=VIREO_RESULT_BUSY) fatal();
            stat_closed=rc==VIREO_OK;
            if (stat_closed) r->queues_closed|=4u;
        }
        if (!root_closed) {
            vireo_completion_queue_close_report_t report;
            vireo_result_t rc=vireo_completion_queue_close(p->root_queue,&report);
            if (rc!=VIREO_OK && rc!=VIREO_RESULT_BUSY) fatal();
            root_closed=rc==VIREO_OK;
            if (root_closed) r->queues_closed|=8u;
        }
        if (!list_closed) {
            vireo_completion_queue_close_report_t report;
            vireo_result_t rc=vireo_completion_queue_close(p->list_queue,&report);
            if (rc!=VIREO_OK && rc!=VIREO_RESULT_BUSY) fatal();
            list_closed=rc==VIREO_OK;
            if (list_closed) r->queues_closed|=16u;
        }
        if (!mkdir_closed) {
            vireo_completion_queue_close_report_t report;
            vireo_result_t rc=vireo_completion_queue_close(p->mkdir_queue,&report);
            if (rc!=VIREO_OK && rc!=VIREO_RESULT_BUSY) fatal();
            mkdir_closed=rc==VIREO_OK;
            if (mkdir_closed) r->queues_closed|=32u;
        }
        if (!move_closed) {
            vireo_completion_queue_close_report_t report;
            vireo_result_t rc=vireo_completion_queue_close(p->move_queue,&report);
            if (rc!=VIREO_OK && rc!=VIREO_RESULT_BUSY) fatal();
            move_closed=rc==VIREO_OK;
            if (move_closed) r->queues_closed|=64u;
        }
        if (!tasks_closed || !queue_closed || !stat_closed || !root_closed || !list_closed || !mkdir_closed || !move_closed) cleanup_result(r,progress(p));
    }
    if (!tasks_closed || !queue_closed || !stat_closed || !root_closed || !list_closed || !mkdir_closed || !move_closed) fatal();
    if (p->workers) {
        vireo_thread_pool_info_t info;
        if (vireo_thread_pool_inspect(p->workers,&info)!=VIREO_OK) fatal();
        if (info.created_count!=info.joined_count) {
            vireo_thread_pool_report_t joined;
            vireo_result_t const rc=vireo_auth_process_join_with(p->workers,CLEANUP_ATTEMPTS,vireo_thread_pool_stop_and_join,&joined);
            if (joined.stage!=VIREO_THREAD_POOL_STAGE_NONE && joined.stage!=VIREO_THREAD_POOL_STAGE_EXECUTE_TASK)
                cleanup_result(r,rc);
            if (vireo_thread_pool_inspect(p->workers,&info)!=VIREO_OK) fatal();
        }
        r->created_count=info.created_count; r->joined_count=info.joined_count;
        if (info.joined_count!=info.created_count) fatal();
        for (size_t i=0;i<info.joined_count;++i) {
            vireo_thread_pool_worker_result_t worker;
            if (vireo_thread_pool_inspect_worker_result(p->workers,i,&worker)!=VIREO_OK) fatal();
            if (r->first_worker_result==VIREO_OK) r->first_worker_result=worker.result;
            if (worker.stage!=VIREO_THREAD_POOL_STAGE_NONE && worker.stage!=VIREO_THREAD_POOL_STAGE_EXECUTE_TASK)
                cleanup_result(r,worker.result==VIREO_OK?VIREO_RESULT_INTERNAL:worker.result);
        }
    }
    if (p->tasks) {
        for (size_t i=0;i<=64;++i) {
            vireo_task_t *task=NULL; vireo_task_queue_transfer_report_t moved;
            vireo_result_t rc=vireo_task_queue_try_take_cancelled(p->tasks,&task,&moved);
            if (task && vireo_task_destroy(&task)!=VIREO_OK) fatal();
            if (rc==VIREO_RESULT_NOT_FOUND) break;
            if (rc!=VIREO_OK || i==64) fatal();
        }
    }
    if (vireo_auth_failure_writer_join(&p->audit_writer)!=VIREO_OK) fatal();
    r->audit_writer=p->audit_writer.report;
    if (p->audit && vireo_auth_failure_audit_inspect(p->audit,&r->audit_queue)!=VIREO_OK) fatal();
    vireo_directory_move_worker_faults_t const final=faults(p);
    r->final_faults=final.auth; r->stat_final_faults=final.stat; r->root_final_faults=final.root; r->list_final_faults=final.list; r->mkdir_final_faults=final.mkdir; r->move_final_faults=final.move;
}
/**
 * @brief 全部producer退出后分别观察已启用完成队列，保存实际空事实
 * @param[in] p 必需主线程独占对象；已完成shutdown_workers，queue借用至返回。
 * @param[in,out] r 必需独占报告，空queue对应位只OR；未创建的queue不置位。
 * @retval true 所有已创建完成queue均为空；service内部owner/receipt仍须独立结束。
 * @retval false 至少一个queue非空，caller继续有限service轮，不销毁队列或服务。
 * @note 无producer后队列不再增长；不按提示计数，也不因一个非空或空项短路另一个。
 *     inspect意外失败沿应用fatal退出；正常路径保持errno，无新申请/等待/owner转移。
 */
static bool completions_empty(process_t const *p,vireo_auth_process_report_t *r)
{
    bool empty=true;
    vireo_completion_queue_t *const queues[]={p->queue,p->stat_queue,p->root_queue,p->list_queue,p->mkdir_queue,p->move_queue};
    for (size_t i=0;i<6;++i) {
        if (!queues[i]) continue;
        vireo_completion_queue_info_t info;
        vireo_result_t const rc=vireo_completion_queue_inspect(queues[i],&info);
        if (rc!=VIREO_OK) fatal();
        if (info.count) empty=false;
        else r->queues_drained|=2u<<(unsigned)i;
    }
    return empty;
}
/** 只能在依赖访问者已join后逆序释放；每个owner按实际NULL判断是否消耗。 */
static void cleanup(process_t *p,vireo_auth_process_report_t *r)
{
    shutdown_workers(p,r);
    for (size_t i=0;i<CLEANUP_ATTEMPTS && p->service;++i) {
        /* 即使service当前没有客户/pending，queue中仍可有迟到结果；destroy不代替drain。 */
        cleanup_result(r,progress(p)); ++r->final_drain_turns;
        if (!completions_empty(p,r)) continue;
        vireo_result_t rc=vireo_auth_service_destroy(&p->service);
        if (rc!=VIREO_OK && rc!=VIREO_RESULT_BUSY) cleanup_result(r,rc);
    }
    if (p->service) fatal();
    if (!completions_empty(p,r)) fatal();
#define RELEASE(field,expression) do { \
    for (size_t attempt=0;attempt<3 && p->field;++attempt) cleanup_result(r,(expression)); \
    if (p->field) fatal(); \
} while (0)
    RELEASE(deadline_wheel,vireo_timer_wheel_destroy(&p->deadline_wheel));
    RELEASE(workers,vireo_thread_pool_destroy(&p->workers));
    RELEASE(notifier,vireo_notifier_destroy(&p->notifier,NULL));
    RELEASE(move_queue,vireo_completion_queue_destroy(&p->move_queue));
    RELEASE(mkdir_queue,vireo_completion_queue_destroy(&p->mkdir_queue));
    RELEASE(list_queue,vireo_completion_queue_destroy(&p->list_queue));
    RELEASE(page_key,vireo_page_token_key_destroy(&p->page_key));
    RELEASE(root_queue,vireo_completion_queue_destroy(&p->root_queue));
    RELEASE(stat_queue,vireo_completion_queue_destroy(&p->stat_queue));
    RELEASE(queue,vireo_completion_queue_destroy(&p->queue));
    RELEASE(tasks,vireo_task_queue_destroy(&p->tasks));
    RELEASE(admission,vireo_auth_login_admission_destroy(&p->admission));
    RELEASE(sessions,vireo_auth_sessions_destroy(&p->sessions));
    RELEASE(store,vireo_inflight_store_destroy(&p->store));
    RELEASE(server,vireo_tcp_server_destroy(&p->server,NULL));
    RELEASE(listener,vireo_acceptor_destroy(&p->listener,NULL));
    RELEASE(tls,vireo_tls_context_destroy(&p->tls,NULL));
    RELEASE(verifier,vireo_auth_login_verifier_destroy(&p->verifier));
    if (p->gate) cleanup_result(r,vireo_auth_password_gate_close(p->gate));
    RELEASE(gate,vireo_auth_password_gate_destroy(&p->gate));
    if (p->database) {
        bool closed=false;
        for (size_t i=0;i<3 && !closed;++i) cleanup_result(r,vireo_mysql_pool_close(p->database,&closed,NULL));
        if (!closed) fatal();
    }
    RELEASE(database,vireo_mysql_pool_destroy(p->thread,&p->database,NULL));
    if (p->audit_database) {
        bool closed=false;
        for(size_t i=0;i<3 && !closed;++i) {
            vireo_result_t const ar=vireo_mysql_pool_close(p->audit_database,&closed,NULL);
            if(ar!=VIREO_OK && r->audit_writer.first_result==VIREO_OK) {
                r->audit_writer.first_result=ar; r->audit_writer.disabled=true;
            }
        }
        if(!closed) fatal();
        for(size_t i=0;i<3 && p->audit_database;++i) {
            vireo_result_t const ar=vireo_mysql_pool_destroy(p->thread,&p->audit_database,NULL);
            if(ar!=VIREO_OK) { r->audit_writer.disabled=true;
                if(r->audit_writer.first_result==VIREO_OK) r->audit_writer.first_result=ar; }
        }
        if(p->audit_database) fatal();
    }
    if(p->audit && vireo_auth_failure_audit_destroy(&p->audit)!=VIREO_OK) fatal();
    RELEASE(thread,vireo_mysql_thread_detach(&p->thread));
    RELEASE(mysql,vireo_mysql_runtime_destroy(&p->mysql));
#undef RELEASE
    if (p->listener_fd>=0 && close(p->listener_fd)!=0) cleanup_result(r,VIREO_RESULT_INTERNAL);
    if (p->signal_fd>=0 && close(p->signal_fd)!=0) cleanup_result(r,VIREO_RESULT_INTERNAL);
    wipe(&p->certificate); wipe(&p->key); wipe(&p->password);
    r->clean=r->cleanup_result==VIREO_OK;
}
/** 阶段失败统一回滚；TRY不包含任何业务执行重试。 */
static vireo_result_t run(process_t *p,vireo_auth_process_options_t const *o,vireo_auth_process_report_t *r)
{
    vireo_result_t rc=VIREO_OK;
#define TRY(expression) do { rc=(expression); if (rc!=VIREO_OK) goto done; } while (0)
    r->phase=VIREO_AUTH_PROCESS_SIGNALS; TRY(signals(p));
    r->phase=VIREO_AUTH_PROCESS_TLS;
    TRY(load(o->certificate_file,1048576,&p->certificate)); TRY(load(o->key_file,65536,&p->key));
    vireo_tls_context_options_t const tls={p->certificate.bytes,p->certificate.size,p->key.bytes,p->key.size,65536};
    TRY(vireo_tls_context_create_server(&tls,&p->tls,NULL)); wipe(&p->certificate); wipe(&p->key);
    r->phase=VIREO_AUTH_PROCESS_DATABASE;
    TRY(load(o->password_file,1026,&p->password));
    if (p->password.size && p->password.bytes[p->password.size-1]=='\n') {
        --p->password.size;
        if (p->password.size && p->password.bytes[p->password.size-1]=='\r') --p->password.size;
    }
    if (p->password.size>1024 || memchr(p->password.bytes,0,p->password.size) ||
        memchr(p->password.bytes,'\n',p->password.size) || memchr(p->password.bytes,'\r',p->password.size)) {
        rc=VIREO_RESULT_INVALID_ARGUMENT; goto done;
    }
    p->password.bytes[p->password.size]=0;
    TRY(vireo_mysql_runtime_create(&p->mysql,NULL)); TRY(vireo_mysql_thread_attach(p->mysql,&p->thread,NULL));
    vireo_mysql_connection_options_t const connection={o->mysql_socket,o->mysql_user,(char const *)p->password.bytes,o->database,3,3,3};
    vireo_mysql_migration_t const *catalog=NULL; size_t count=0;
    TRY(vireo_mysql_schema_catalog(&catalog,&count)); vireo_mysql_migration_report_t migrated;
    TRY(vireo_mysql_migration_apply(p->thread,&connection,catalog,count,&migrated,NULL));
    if (!migrated.ready) { rc=VIREO_RESULT_INTERNAL; goto done; }
    vireo_mysql_pool_options_t const db={connection,2,2,VIREO_MYSQL_POOL_MEMORY_MAX};
    rc=vireo_mysql_pool_create(p->thread,&db,&p->database,NULL);
    if(rc==VIREO_OK) {
        vireo_mysql_pool_options_t const audit_db={connection,1,1,VIREO_MYSQL_POOL_MEMORY_MAX};
        vireo_result_t ar=vireo_mysql_pool_create(p->thread,&audit_db,&p->audit_database,NULL);
        uint64_t audit_now=0;
        if(ar==VIREO_OK) ar=vireo_clock_monotonic_now(&audit_now,NULL);
        vireo_auth_failure_audit_options_t const audit_options={256,65536,8,UINT64_C(1000000000)};
        if(ar==VIREO_OK) ar=vireo_auth_failure_audit_create(&audit_options,audit_now,&p->audit);
        if(ar==VIREO_OK) ar=vireo_auth_failure_writer_start(&p->audit_writer,p->mysql,p->audit_database,p->audit);
        if(ar!=VIREO_OK) {
            p->audit_writer.report.disabled=true;
            if(p->audit_writer.report.first_result==VIREO_OK) p->audit_writer.report.first_result=ar;
        }
    }
    wipe(&p->password); if(rc!=VIREO_OK) goto done;
    r->phase=VIREO_AUTH_PROCESS_RESOURCES;
    vireo_auth_password_gate_options_t const gate=VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT;
    TRY(vireo_auth_password_gate_create(&gate,&p->gate)); TRY(vireo_auth_login_verifier_create(p->gate,&p->verifier));
    vireo_tcp_server_options_t const server={32,64,MEMORY,MEMORY};
    bool const list_enabled=o->list_completion_allocation_budget!=0;
    bool const mkdir_enabled=o->mkdir_completion_allocation_budget!=0;
    vireo_tcp_server_tls_options_t const network={{4096,list_enabled?32768:4096,list_enabled?69632:40960,mkdir_enabled?512:256,mkdir_enabled?511:255,4096,0,list_enabled?32768:4096},4096,UINT64_C(5000000000),MEMORY};
    TRY(vireo_tcp_server_create_tls_with_auxiliary_capacity(&server,&network,1,&p->tls,&p->server,NULL));
    vireo_inflight_store_options_t const inflight={256,MEMORY}; TRY(vireo_inflight_store_create(&inflight,&p->store));
    vireo_auth_sessions_options_t const sessions={MEMORY}; TRY(vireo_auth_sessions_create(p->server,&sessions,&p->sessions));
    vireo_task_queue_options_t const tasks={64,MEMORY}; TRY(vireo_task_queue_create(&tasks,&p->tasks)); TRY(vireo_task_queue_prepare_wait(p->tasks));
    vireo_completion_queue_options_t const queue={64,MEMORY}; TRY(vireo_completion_queue_create(&queue,&p->queue)); TRY(vireo_completion_queue_prepare_wait(p->queue));
    TRY(vireo_completion_queue_create(&queue,&p->stat_queue)); TRY(vireo_completion_queue_prepare_wait(p->stat_queue));
    if(o->root_completion_allocation_budget) {
        TRY(vireo_completion_queue_create(&queue,&p->root_queue)); TRY(vireo_completion_queue_prepare_wait(p->root_queue));
    }
    if(list_enabled) {
        TRY(vireo_completion_queue_create(&queue,&p->list_queue)); TRY(vireo_completion_queue_prepare_wait(p->list_queue));
        TRY(vireo_page_token_key_create(&p->page_key));
    }
    if(mkdir_enabled) {
        TRY(vireo_completion_queue_create(&queue,&p->mkdir_queue)); TRY(vireo_completion_queue_prepare_wait(p->mkdir_queue));
    }
    if(o->move_completion_allocation_budget) {
        TRY(vireo_completion_queue_create(&queue,&p->move_queue)); TRY(vireo_completion_queue_prepare_wait(p->move_queue));
    }
    vireo_notifier_options_t const notifier={4096}; TRY(vireo_notifier_create(&notifier,&p->notifier,NULL));
    uint64_t now=0; TRY(vireo_clock_monotonic_now(&now,NULL));
    vireo_auth_login_admission_options_t const admission=VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    TRY(vireo_auth_login_admission_create(&admission,now,&p->admission));
    vireo_auth_worker_resources_t const resources={p->mysql,p->database,p->gate,p->verifier,p->queue,p->notifier,p->audit};
    vireo_auth_worker_options_t const worker={.execution={100,101,5000,102,103},.password=VIREO_PASSWORD_POLICY_DEFAULT,
        .request_timeout_ns=REQUEST_TIMEOUT,.session_lifetime_ms=o->session_lifetime_ms,
        .completion_allocation_budget=o->completion_allocation_budget,.max_memory_bytes=65536};
    TRY(vireo_auth_worker_runtime_init(&p->runtime,&resources,&worker,3)); p->runtime_initialized=true;
    vireo_directory_stat_worker_resources_t const stat_resources={p->mysql,p->database,p->stat_queue,p->notifier};
    vireo_directory_stat_worker_options_t const stat_worker={
        .execution={STAT_OPERATION,5000},.completion_allocation_budget=o->stat_completion_allocation_budget,
        .max_memory_bytes=65536};
    TRY(vireo_directory_stat_worker_runtime_init(&p->mixed_runtime,&p->runtime,&stat_resources,&stat_worker,3));
    p->mixed_runtime_initialized=true;
    if(p->root_queue) {
        vireo_directory_root_worker_resources_t const rr={p->mysql,p->database,p->root_queue,p->notifier};
        vireo_directory_root_worker_options_t const ro={.execution={ROOT_OPERATION,5000},
            .completion_allocation_budget=o->root_completion_allocation_budget,.max_memory_bytes=65536};
        TRY(vireo_directory_root_worker_runtime_init(&p->root_runtime,&p->mixed_runtime,&rr,&ro,3));
        p->root_runtime_initialized=true;
    }
    if(p->list_queue) {
        vireo_directory_list_worker_resources_t const lr={p->mysql,p->page_key,p->database,p->list_queue,p->notifier};
        vireo_directory_list_worker_options_t const lo={.execution={LIST_OPERATION,5000},
            .completion_allocation_budget=o->list_completion_allocation_budget,.max_memory_bytes=65536};
        TRY(vireo_directory_list_worker_runtime_init(&p->list_runtime,&p->root_runtime,&lr,&lo,3));
        p->list_runtime_initialized=true;
    }
    if(p->mkdir_queue) {
        vireo_directory_mkdir_worker_resources_t const mr={p->mysql,p->database,p->mkdir_queue,p->notifier};
        vireo_directory_mkdir_worker_options_t const mo={.execution={MKDIR_OPERATION,5000},
            .completion_allocation_budget=o->mkdir_completion_allocation_budget,.max_memory_bytes=65536};
        TRY(vireo_directory_mkdir_worker_runtime_init(&p->mkdir_runtime,&p->list_runtime,&mr,&mo,3));
        p->mkdir_runtime_initialized=true;
    }
    if(p->move_queue) {
        vireo_directory_move_worker_resources_t const mr={p->mysql,p->database,p->move_queue,p->notifier};
        vireo_directory_move_worker_options_t const mo={.execution={MOVE_OPERATION,5000},
            .completion_allocation_budget=o->move_completion_allocation_budget,.max_memory_bytes=65536};
        TRY(vireo_directory_move_worker_runtime_init(&p->move_runtime,&p->mkdir_runtime,&mr,&mo,3));
        p->move_runtime_initialized=true;
    }
    r->phase=VIREO_AUTH_PROCESS_WORKERS;
    vireo_thread_pool_options_t const workers={2,MEMORY}; TRY(vireo_thread_pool_create(&workers,&p->workers));
    vireo_thread_pool_configuration_t const config={p->tasks,
        p->move_queue?vireo_directory_move_worker_runtime_execute:p->mkdir_queue?vireo_directory_mkdir_worker_runtime_execute:p->list_queue?vireo_directory_list_worker_runtime_execute:p->root_queue?vireo_directory_root_worker_runtime_execute:vireo_directory_stat_worker_runtime_execute,
        p->move_queue?(void *)&p->move_runtime:p->mkdir_queue?(void *)&p->mkdir_runtime:p->list_queue?(void *)&p->list_runtime:p->root_queue?(void *)&p->root_runtime:(void *)&p->mixed_runtime};
    TRY(vireo_thread_pool_configure(p->workers,&config,NULL)); vireo_thread_pool_report_t started;
    TRY(vireo_thread_pool_start(p->workers,&started)); TRY(vireo_thread_pool_enable_execution(p->workers,&started));
    r->phase=VIREO_AUTH_PROCESS_LISTENER;
    p->listener_fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if (p->listener_fd<0) { rc=VIREO_RESULT_INTERNAL; goto done; }
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(o->port)};
    if (inet_pton(AF_INET,o->address,&address.sin_addr)!=1 ||
        bind(p->listener_fd,(struct sockaddr *)&address,sizeof address)!=0 || listen(p->listener_fd,64)!=0) { rc=VIREO_RESULT_INTERNAL; goto done; }
    vireo_acceptor_options_t const listener={4096}; TRY(vireo_acceptor_create(&listener,&p->listener_fd,&p->listener,NULL));
    TRY(vireo_tcp_server_adopt_listener(p->server,&p->listener,NULL)); TRY(vireo_tcp_server_bind_listener(p->server,false,NULL));
    r->phase=VIREO_AUTH_PROCESS_SERVICE;
    uint64_t timer_origin=0; TRY(vireo_clock_monotonic_now(&timer_origin,NULL));
    vireo_timer_wheel_options_t const wheel={{timer_origin,UINT64_C(100000000),512},MEMORY};
    TRY(vireo_timer_wheel_create(&wheel,&p->deadline_wheel));
    vireo_timer_wheel_registry_options_t const registry={server.connection_capacity,MEMORY};
    TRY(vireo_timer_wheel_prepare(p->deadline_wheel,&registry));
    vireo_auth_service_resources_t const service={p->server,p->store,p->workers,p->admission,p->sessions,p->queue,p->notifier,p->audit};
    vireo_auth_service_options_t const options={.max_clients=8,.admit={8,16},.max_completions=16,.cleanup_slots=32,
        .receive={4096,8},.send={list_enabled?16384:4096,8},.task_allocation_budget=4096,.max_client_requests=8,
        .register_operation=100,.login_operation=101,.logout_operation=102,.resume_operation=103,.request_timeout_ns=REQUEST_TIMEOUT,.max_memory_bytes=MEMORY};
    if(p->move_queue) { TRY(vireo_directory_move_reactor_create(&service,&options,p->stat_queue,STAT_OPERATION,p->root_queue,ROOT_OPERATION,p->list_queue,LIST_OPERATION,65536,p->mkdir_queue,MKDIR_OPERATION,p->move_queue,MOVE_OPERATION,&p->service)); }
    else if(p->mkdir_queue) { TRY(vireo_directory_mkdir_reactor_create(&service,&options,p->stat_queue,STAT_OPERATION,p->root_queue,ROOT_OPERATION,p->list_queue,LIST_OPERATION,65536,p->mkdir_queue,MKDIR_OPERATION,&p->service)); }
    else if(p->list_queue) { TRY(vireo_directory_list_reactor_create(&service,&options,p->stat_queue,STAT_OPERATION,p->root_queue,ROOT_OPERATION,p->list_queue,LIST_OPERATION,65536,&p->service)); }
    else if(p->root_queue) { TRY(vireo_directory_root_reactor_create(&service,&options,p->stat_queue,STAT_OPERATION,p->root_queue,ROOT_OPERATION,&p->service)); }
    else { TRY(vireo_directory_stat_reactor_create(&service,&options,p->stat_queue,STAT_OPERATION,&p->service)); }
    vireo_auth_service_deadline_options_t const deadlines={
        .unauthenticated_timeout_ns=UINT64_C(30000000000),.frame_timeout_ns=UINT64_C(10000000000),
        .authenticated_idle_timeout_ns=UINT64_C(60000000000),.advance={64,64},.max_expired=32,.max_memory_bytes=MEMORY};
    TRY(vireo_auth_service_enable_deadlines(p->service,p->deadline_wheel,&deadlines));
    TRY(stop_signal(p,r));
    if (r->stop_signal) goto done;
    if (fputs("vireo-auth-server ready\n",stdout)==EOF || fflush(stdout)!=0) { rc=VIREO_RESULT_INTERNAL; goto done; }
    r->ready=true; r->phase=VIREO_AUTH_PROCESS_RUNNING;
    for (;;) {
        vireo_directory_move_worker_faults_t sampled=faults(p);
        if (sampled.auth || sampled.stat || sampled.root || sampled.list || sampled.mkdir || sampled.move) { rc=VIREO_RESULT_INTERNAL; break; }
        TRY(stop_signal(p,r)); if (r->stop_signal) break;
        vireo_auth_service_report_t turn; TRY(vireo_auth_service_once(p->service,100,&turn));
        sampled=faults(p);
        if (sampled.auth || sampled.stat || sampled.root || sampled.list || sampled.mkdir || sampled.move) { rc=VIREO_RESULT_INTERNAL; break; }
        if(o->audit_observer && p->audit) {
            vireo_auth_failure_audit_info_t info;
            if(vireo_auth_failure_audit_inspect(p->audit,&info)==VIREO_OK)
                o->audit_observer(o->audit_observer_context,&info);
        }
    }
done:
    ; /* C11标签必须跟语句；空语句之后才声明收尾快照。 */
    vireo_directory_move_worker_faults_t const stopped=faults(p);
    r->faults_at_stop=stopped.auth; r->stat_faults_at_stop=stopped.stat; r->root_faults_at_stop=stopped.root; r->list_faults_at_stop=stopped.list; r->mkdir_faults_at_stop=stopped.mkdir; r->move_faults_at_stop=stopped.move;
    cleanup(p,r);
    if (rc==VIREO_OK && (r->cleanup_result!=VIREO_OK || r->faults_at_stop ||
        r->stat_faults_at_stop || r->root_faults_at_stop || r->list_faults_at_stop || r->mkdir_faults_at_stop || r->move_faults_at_stop ||
        (r->final_faults & ~(unsigned)VIREO_AUTH_WORKER_FAULT_PUBLISH) ||
        (r->stat_final_faults & ~(unsigned)VIREO_DIRECTORY_STAT_WORKER_FAULT_PUBLISH) ||
        (r->root_final_faults & ~(unsigned)VIREO_DIRECTORY_ROOT_WORKER_FAULT_PUBLISH) ||
        (r->list_final_faults & ~(unsigned)VIREO_DIRECTORY_LIST_WORKER_FAULT_PUBLISH) ||
        (r->mkdir_final_faults & ~(unsigned)VIREO_DIRECTORY_MKDIR_WORKER_FAULT_PUBLISH) ||
        (r->move_final_faults & ~(unsigned)VIREO_DIRECTORY_MOVE_WORKER_FAULT_PUBLISH) ||
        (!r->stop_signal && (r->final_faults || r->stat_final_faults || r->root_final_faults || r->list_final_faults || r->mkdir_final_faults || r->move_final_faults)))) rc=VIREO_RESULT_INTERNAL;
#undef TRY
    return rc;
}
vireo_result_t vireo_auth_process_run(vireo_auth_process_options_t const *o,vireo_auth_process_report_t *r)
{
    int const saved=errno;
    if (!r) return VIREO_RESULT_INVALID_ARGUMENT;
    *r=(vireo_auth_process_report_t){0};
    struct in_addr address;
    if (!o || !o->address || !o->port || inet_pton(AF_INET,o->address,&address)!=1 ||
        !o->certificate_file || !o->key_file || !o->mysql_socket || !o->mysql_user || !o->password_file || !o->database ||
        !*o->certificate_file || !*o->key_file || !*o->mysql_socket || !*o->mysql_user || !*o->password_file || !*o->database ||
        !o->session_lifetime_ms || !o->completion_allocation_budget || o->completion_allocation_budget>MEMORY ||
        !o->stat_completion_allocation_budget || o->stat_completion_allocation_budget>MEMORY || o->root_completion_allocation_budget>MEMORY || o->list_completion_allocation_budget>MEMORY || o->mkdir_completion_allocation_budget>MEMORY || o->move_completion_allocation_budget>MEMORY ||
        (o->move_completion_allocation_budget && !o->mkdir_completion_allocation_budget) ||
        (o->mkdir_completion_allocation_budget && !o->list_completion_allocation_budget) ||
        (o->list_completion_allocation_budget && !o->root_completion_allocation_budget)) {
        errno=saved; return VIREO_RESULT_INVALID_ARGUMENT;
    }
    int previous=0;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&previous)!=0) { errno=saved; return VIREO_RESULT_INTERNAL; }
    process_t p={.signal_fd=-1,.listener_fd=-1};
    vireo_result_t rc=run(&p,o,r);
    if (pthread_setcancelstate(previous,NULL)!=0 && rc==VIREO_OK) rc=VIREO_RESULT_INTERNAL;
    errno=saved; return rc;
}
