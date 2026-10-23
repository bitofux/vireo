/* PROJECT: VIREO; FILE: auth_process.h; AUTHOR: bitofux; DATE: 2026-10-20.
 * 应用私有进程生命周期；只在全新进程的主OS线程调用一次。 */
#ifndef VIREO_APP_AUTH_PROCESS_H
#define VIREO_APP_AUTH_PROCESS_H
#include "auth_failure_writer.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>

/** 仅借至run返回；不含原始密码，固定资源profile见041-20。 */
typedef struct vireo_auth_process_options {
    char const *address; /**< 数字IPv4。 */
    uint16_t port; /**< 非零。 */
    char const *certificate_file, *key_file; /**< 有界普通PEM文件。 */
    char const *mysql_socket, *mysql_user, *password_file, *database; /**< 本地数据库身份及密码文件。 */
    uint64_t session_lifetime_ms; /**< 操作员显式正寿命。 */
    size_t completion_allocation_budget; /**< 私有装配预算；正常入口4096，不能自动重投。 */
    void (*audit_observer)(void *,vireo_auth_failure_audit_info_t const *); /**< own进程测试观察；生产NULL，不改变SQL或策略。 */
    void *audit_observer_context; /**< 仅Reactor回调，借至run返回。 */
    size_t stat_completion_allocation_budget; /**< STAT独立正申请预算；生产4096，测试可验证未回投收尾。 */
    size_t root_completion_allocation_budget; /**< 0保留五命令；正预算<=64MiB启用ROOT，生产4096。 */
} vireo_auth_process_options_t;
/** 首因阶段，无路径、秘密、原生错误文本。 */
typedef enum vireo_auth_process_phase {
    VIREO_AUTH_PROCESS_VALIDATE, VIREO_AUTH_PROCESS_SIGNALS, VIREO_AUTH_PROCESS_TLS,
    VIREO_AUTH_PROCESS_DATABASE, VIREO_AUTH_PROCESS_RESOURCES, VIREO_AUTH_PROCESS_WORKERS,
    VIREO_AUTH_PROCESS_LISTENER, VIREO_AUTH_PROCESS_SERVICE, VIREO_AUTH_PROCESS_RUNNING
} vireo_auth_process_phase_t;
/** 返回前全部owner消耗才clean；业务首错独立于进程退出结果。 */
typedef struct vireo_auth_process_report {
    vireo_auth_process_phase_t phase;
    bool ready, clean;
    int stop_signal;
    unsigned faults_at_stop, final_faults;
    size_t created_count, joined_count;
    vireo_result_t first_worker_result, cleanup_result;
    vireo_auth_failure_writer_report_t audit_writer;
    vireo_auth_failure_audit_info_t audit_queue;
    unsigned stat_faults_at_stop, stat_final_faults; /**< STAT独立故障域，不能与原认证位混为同一值。 */
    unsigned queues_closed, queues_drained; /**< 独立确认位：task=1、auth=2、STAT=4、ROOT=8；drained在join后观察。 */
    size_t final_drain_turns; /**< join后无条件推进的有界服务轮数，不按notifier提示决定。 */
    unsigned root_faults_at_stop, root_final_faults; /**< ROOT独立永久故障域。 */
} vireo_auth_process_report_t;
/**
 * @brief 主线程同步装配、运行及清退认证四命令与NODE_STAT进程。
 * @param options 必需独立只读借用，字符串须存活、不为空；文件读取有界。
 * @param report 必需独立输出，基本拒绝也覆盖；无秘密/借用地址。
 * @return 正常INT/TERM且清理成功为OK；其他失败保首因；全路径正常返回保持errno。
 * @note 调用期间禁POSIX取消，SIGPIPE忽略、INT/TERM阻塞并由signalfd读取；
 * 不恢复信号配置，不支持嵌入/重启/多次调用。依赖单次调用可能阻塞，无退出硬时限。
 * 发生基础设施故障全服务放弃；全部已启用task/auth/STAT/ROOT队列独立close成功后才join，业务不重放。
 * join后至少一轮服务，分别确认已启用完成队列排空才destroy服务；保留可信迟到LOGOUT效果。
 * 全部已启用永久故障每服务轮前后采样；正常信号放弃期间新增PUBLISH保留为证据，
 * 其他故障或停前故障仍失败。原认证公共factory与ABI保持四命令模式。
 * 残留owner/未join线程无法安全释放时，应用_Exit(EXIT_FAILURE)，不返回悬空借用。
 */
vireo_result_t vireo_auth_process_run(vireo_auth_process_options_t const *options,
    vireo_auth_process_report_t *report);
#endif
