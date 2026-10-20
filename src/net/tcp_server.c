/*
- PROJECT : VIREO
- FILE    : tcp_server.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 独占 loop/空 pool 与可选监听的公开资源装配、受检真实预算
- -- 最后发布、快照核对、逆序回滚和消费型销毁
- -- 严格监听绑定、通知观察及先结束登记借用的整体清理
- -- 逐客户接入/创建/收纳/登记、部分进度与显式注销归还
- -- 租约验证后仅经公开 connection 合同驱动字节与有界帧查看
- -- 复用有限服务的持续run、回调安全窗口与公开loop停止透传
- -- 停止后的固定槽有界清理、原注销归还路径与真实前缀
 */
#include "tcp_server_internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <vireo/base/checked.h>

/** 固定表的存储租约与观察；实际 connection owner 始终只在公开 pool。 */
typedef struct client_slot {
    vireo_connection_pool_lease_t lease;
    size_t buffer_bytes;
    uint32_t last_events;
    bool live;
    bool bound;
    vireo_tcp_server_t *parent; /**< 固定槽所属 server 的借用，不是 owner。 */
    bool queued; /**< current live 客户至多一个 FIFO 位置。 */
    size_t queue_prev; /**< 前一个待办槽，SIZE_MAX 表示无前项。 */
    size_t queue_next; /**< 后一个待办槽，SIZE_MAX 表示无后项。 */
    uint32_t pending_events; /**< 尚未出队的通知 OR，缓存/显式安排可为零。 */
} client_slot_t;

struct vireo_tcp_server {
    vireo_tcp_server_options_t options;
    vireo_event_loop_t *loop;
    vireo_connection_pool_t *pool;
    vireo_event_loop_info_t loop_origin;
    vireo_connection_pool_info_t pool_origin;
    vireo_tcp_server_ops_t ops;
    vireo_tcp_server_listener_ops_t listener_ops;
    vireo_acceptor_t *listener;
    vireo_acceptor_info_t listener_origin;
    bool listener_bound;
    bool listener_read_enabled;
    uint32_t listener_last_events;
    bool listener_poll_active; /**< 仅新poll实际wait窗口，非跨线程状态。 */
    uint32_t listener_poll_events; /**< 本窗口OR，wait结束即取值并清零。 */
    vireo_tcp_server_client_ops_t client_ops;
    size_t server_bytes;
    size_t client_slots_bytes;
    size_t client_count;
    size_t registered_clients;
    size_t buffer_bytes;
    bool processing_active; /**< 同 Reactor 同步处理阶段，非同步锁。 */
    bool driving_active; /**< 整次客户驱动重入保护，非跨线程许可。 */
    vireo_tcp_server_scheduler_ops_t scheduler_ops;
    size_t queue_head; /**< 首待办槽，空队列 SIZE_MAX。 */
    size_t queue_tail; /**< 尾待办槽，空队列 SIZE_MAX。 */
    size_t queue_count; /**< 去重客户数量，始终不超过 live 客户数。 */
    bool scheduling_active; /**< 整个单轮等待及客户服务，普通 Reactor 重入标记。 */
    bool running_active; /**< 整次run含观察回调，普通Reactor重入标记。 */
    bool shutdown_active; /**< 整批清理保护，不能由跨线程停止请求读取。 */
    bool auto_release_ready; /**< Reactor服务轮显式模式，每轮入口冻结。 */
    bool auto_close_policy; /**< 固定EOF/网络错误规则，Reactor普通bool，默认false。 */
    size_t shutdown_next_slot; /**< 下次检查起点，0..connection_capacity-1。 */
    bool closing_active; /**< 关闭意图批次的普通Reactor保护，非停止线程数据。 */
    size_t close_next_slot; /**< 独立关闭扫描起点，构造0、失败槽也推进。 */
    vireo_tcp_server_stop_ops_t stop_ops; /**< 不可变公开停止桥接，供并发请求者读取。 */
    bool serving_active; /**< 自动组合轮次，包括压力同步及准入。 */
    bool admission_enabled; /**< 启用时必有owned bound listener。 */
    vireo_tcp_server_admission_options_t admission_options; /**< 数值副本，无外部长期借用。 */
    size_t admission_pair_bytes; /**< 两固定容量checked和，启用时正。 */
    uint32_t serve_listener_events; /**< 仅本serve wait期间通知OR，非历史快照。 */
    bool queue_fault; /**< void 通知适配器的异常转交本轮，健康合同下恒 false。 */
    vireo_event_loop_handle_t auxiliary_handle; /**< 唯一辅助登记身份，未绑定全零。 */
    int auxiliary_fd; /**< 借用fd，未绑定−1；不由server关闭。 */
    uint32_t auxiliary_pending_events; /**< 内部回调OR，安全窗口取出或成功DEL清零。 */
    vireo_tls_context_t *owned_tls_context; /**< 非空即固定TLS模式；供以后SSL创建，空根destroy释放。 */
    vireo_tcp_server_tls_options_t tls_options; /**< 创建时数值副本，不保留caller地址。 */
    size_t context_wrapper_bytes; /**< TLS根总预算中的真实context包装，RAW为0。 */
    size_t tls_pair_bytes; /**< 固定两FIFO账，入池/释放复用原buffer_bytes。 */
    size_t tls_per_connection_bytes; /**< pair+两暂存，当前总额由client_count受检推导。 */
    vireo_tcp_server_tls_ops_t tls_ops; /**< 仅本核心依赖桥接；无第二客户状态或owner。 */
    client_slot_t clients[]; /**< 随 control 单次固定申请，槽地址至 destroy 保持。 */
};

/** 一次等待只经已封板公共 loop；通知不能偷偷运行业务。 */
static vireo_result_t system_run_once(void *ctx, vireo_event_loop_t *loop, int timeout,
    vireo_event_loop_run_info_t *info, vireo_event_loop_error_t *error)
{
    (void)ctx;
    return vireo_event_loop_run_once(loop, timeout, info, error);
}
static vireo_tcp_server_scheduler_ops_t const system_scheduler_ops = {NULL, system_run_once};

/** 只桥接已封板公共停止；不访问本层Reactor状态。 */
static vireo_result_t system_request_stop(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_request_stop(loop, error);
}
static vireo_tcp_server_stop_ops_t const system_stop_ops = {NULL, system_request_stop};

/** Reactor侧仅观察公开停止快照；不读取opaque依赖布局，不分配/修改资源。 */
static vireo_result_t stop_snapshot(vireo_tcp_server_t const *server, bool *stopped)
{
    vireo_event_loop_info_t info = {0};
    vireo_result_t const result = vireo_event_loop_inspect(server->loop, &info);
    if (result == VIREO_OK) *stopped = info.stop_requested;
    return result;
}


/**
 * @brief O(1)核对队列数量和首尾边界，避免少量待办仍扫描全容量
 *
 * @param[in] s
 *     存活本层资源，只读借用；槽索引验证后才访问。
 *
 * @return
 *     true 表示边界/count 一致；不提供损坏图的全表修复保证。
 *
 * @note 无分配/系统调用/状态变化，Reactor-only。
 */
static bool queue_valid(vireo_tcp_server_t const *s)
{
    if (s->queue_count > s->client_count || s->queue_count > s->options.connection_capacity)
        return false;
    if (s->queue_count == 0)
        return s->queue_head == SIZE_MAX && s->queue_tail == SIZE_MAX;
    if (s->queue_head >= s->options.connection_capacity || s->queue_tail >= s->options.connection_capacity)
        return false;
    if ((s->queue_count == 1) != (s->queue_head == s->queue_tail)) return false;
    client_slot_t const *head = &s->clients[s->queue_head];
    client_slot_t const *tail = &s->clients[s->queue_tail];
    return head->live && head->queued && head->queue_prev == SIZE_MAX &&
        tail->live && tail->queued && tail->queue_next == SIZE_MAX;
}

/**
 * @brief 当前槽的有效 FIFO 位置检查
 *
 * @param[in] s
 *     本层存活对象，仅借用。
 * @param[in] index
 *     待检查槽号，数值先验证再访问。
 *
 * @return
 *     true 表示当前位置与邻项双向关系一致；不证明损坏对象全图可恢复。
 *
 * @note 无资源取得、系统调用或状态修改，Reactor-only。
 */
static bool queue_position(vireo_tcp_server_t const *s, size_t index)
{
    if (!queue_valid(s) || index >= s->options.connection_capacity) return false;
    client_slot_t const *slot = &s->clients[index];
    if (!slot->live || !slot->queued || slot->parent != s) return false;
    bool const prev = slot->queue_prev == SIZE_MAX ? s->queue_head == index :
        slot->queue_prev < s->options.connection_capacity &&
        s->clients[slot->queue_prev].queued && s->clients[slot->queue_prev].queue_next == index;
    bool const next = slot->queue_next == SIZE_MAX ? s->queue_tail == index :
        slot->queue_next < s->options.connection_capacity &&
        s->clients[slot->queue_next].queued && s->clients[slot->queue_next].queue_prev == index;
    return prev && next;
}

/**
 * @brief 有界尾插 current 槽，重复排队不移位
 *
 * @param[in,out] s
 *     存活 server，拥有固定链元数据。
 * @param[in] index
 *     当前 live 槽号；不授予 connection owner。
 *
 * @retval VIREO_OK
 *     位置已存在或恰一次尾插。
 * @retval VIREO_RESULT_INTERNAL
 *     不变量拒绝，检查后才修改链接。
 *
 * @note queue_count<client_count 的先验界证明增量不回绕；无分配/系统调用。
 */
static vireo_result_t queue_append(vireo_tcp_server_t *s, size_t index)
{
    if (!queue_valid(s) || index >= s->options.connection_capacity) return VIREO_RESULT_INTERNAL;
    client_slot_t *slot = &s->clients[index];
    if (!slot->live || slot->parent != s) return VIREO_RESULT_INTERNAL;
    if (slot->queued) return queue_position(s, index) ? VIREO_OK : VIREO_RESULT_INTERNAL;
    if (s->queue_count >= s->client_count) return VIREO_RESULT_INTERNAL;
    slot->queue_prev = s->queue_tail;
    slot->queue_next = SIZE_MAX;
    if (s->queue_tail == SIZE_MAX) s->queue_head = index;
    else s->clients[s->queue_tail].queue_next = index;
    s->queue_tail = index;
    slot->queued = true;
    ++s->queue_count;
    return VIREO_OK;
}

/**
 * @brief O(1)撤销当前槽位置，用于出队或消费型归还
 *
 * @param[in,out] s
 *     存活 server，撤销仅调度记录，不关闭客户。
 * @param[in] index
 *     本层当前槽号，未 queued 为成功空操作。
 *
 * @retval VIREO_OK
 *     双向链接/count 与 pending 已清理。
 * @retval VIREO_RESULT_INTERNAL
 *     数值/链不变量拒绝，无通用损坏恢复。
 *
 * @note 归还前 slot 仍在 server 控制块内，不能读取已消费 connection 或旧 pool 槽。
 */
static vireo_result_t queue_remove(vireo_tcp_server_t *s, size_t index)
{
    if (!queue_valid(s) || index >= s->options.connection_capacity) return VIREO_RESULT_INTERNAL;
    client_slot_t *slot = &s->clients[index];
    if (!slot->queued) return VIREO_OK;
    if (!queue_position(s, index)) return VIREO_RESULT_INTERNAL;
    if (slot->queue_prev == SIZE_MAX) s->queue_head = slot->queue_next;
    else s->clients[slot->queue_prev].queue_next = slot->queue_next;
    if (slot->queue_next == SIZE_MAX) s->queue_tail = slot->queue_prev;
    else s->clients[slot->queue_next].queue_prev = slot->queue_prev;
    --s->queue_count;
    slot->queued = false;
    slot->queue_prev = SIZE_MAX;
    slot->queue_next = SIZE_MAX;
    slot->pending_events = 0;
    return VIREO_OK;
}

/** malloc/free 配对，只有公共边界负责恢复入口 errno。 */
static void *system_allocate(void *context, size_t bytes)
{
    (void)context;
    return malloc(bytes);
}

/** 仅释放本层 control，不拥有或访问借用 context。 */
static void system_deallocate(void *context, void *memory)
{
    (void)context;
    free(memory);
}

/** 只经公开 loop 构造取得完整唯一 owner，无私有布局依赖。 */
static vireo_result_t system_create_loop(void *context, vireo_event_loop_options_t const *options,
                                        vireo_event_loop_t **owner, vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_create(options, owner, error);
}

/** 公开数值快照不提供内部 fd 或数组借用。 */
static vireo_result_t system_inspect_loop(void *context, vireo_event_loop_t const *loop,
                                         vireo_event_loop_info_t *info)
{
    (void)context;
    return vireo_event_loop_inspect(loop, info);
}

/** 未运行 loop 的 OK/IO 均消费 owner，关闭不重试。 */
static vireo_result_t system_destroy_loop(void *context, vireo_event_loop_t **owner,
                                         vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_destroy(owner, error);
}

/** 公开连接池只构造空容器，不创建客户或预申请其 buffer。 */
static vireo_result_t system_create_pool(void *context,
                                        vireo_connection_pool_options_t const *options,
                                        vireo_connection_pool_t **owner,
                                        vireo_connection_pool_error_t *error)
{
    (void)context;
    return vireo_connection_pool_create(options, owner, error);
}

/** 从公开完整申请数计账，不再次累计基础 pool。 */
static vireo_result_t system_inspect_pool(void *context, vireo_connection_pool_t const *pool,
                                         vireo_connection_pool_info_t *info)
{
    (void)context;
    return vireo_connection_pool_inspect(pool, info);
}

/** 空 pool 成功消费，依赖拒绝保留 owner 和资源。 */
static vireo_result_t system_destroy_pool(void *context, vireo_connection_pool_t **owner,
                                         vireo_connection_pool_error_t *error)
{
    (void)context;
    return vireo_connection_pool_destroy(owner, error);
}

static vireo_tcp_server_ops_t const system_ops = {
    NULL, system_allocate, system_deallocate,
    system_create_loop, system_inspect_loop, system_destroy_loop,
    system_create_pool, system_inspect_pool, system_destroy_pool
};

/** 逐对象监听表只桥接 public 接口；最外层恢复 errno。 */
static vireo_result_t system_listener_inspect(void *ctx, vireo_acceptor_t const *a,
                                             vireo_acceptor_info_t *info)
{
    (void)ctx;
    return vireo_acceptor_inspect(a, info);
}

static vireo_result_t system_listener_attach(void *ctx, vireo_acceptor_t *a,
                                            vireo_event_loop_t *loop, bool enabled,
                                            vireo_acceptor_callback_t callback, void *context,
                                            vireo_acceptor_loop_error_t *error)
{
    (void)ctx;
    return vireo_acceptor_attach(a, loop, enabled, callback, context, error);
}

static vireo_result_t system_listener_set(void *ctx, vireo_acceptor_t *a, bool enabled,
                                         vireo_acceptor_loop_error_t *error)
{
    (void)ctx;
    return vireo_acceptor_set_read_enabled(a, enabled, error);
}

static vireo_result_t system_listener_detach(void *ctx, vireo_acceptor_t *a,
                                            vireo_acceptor_loop_error_t *error)
{
    (void)ctx;
    return vireo_acceptor_detach(a, error);
}

static vireo_result_t system_listener_forget(void *ctx, vireo_acceptor_t *a)
{
    (void)ctx;
    return vireo_acceptor_forget_destroyed_loop(a, NULL);
}

static vireo_result_t system_listener_destroy(void *ctx, vireo_acceptor_t **a,
                                             vireo_acceptor_error_t *error)
{
    (void)ctx;
    return vireo_acceptor_destroy(a, error);
}

static vireo_tcp_server_listener_ops_t const system_listener_ops = {
    NULL, system_listener_inspect, system_listener_attach, system_listener_set,
    system_listener_detach, system_listener_forget, system_listener_destroy
};

/** 缺项不发布，表和借用 context 的生命周期沿本核心测试合同。 */
static bool listener_ops_valid(vireo_tcp_server_listener_ops_t const *ops)
{
    return ops != NULL && ops->inspect != NULL && ops->attach != NULL &&
           ops->set_read != NULL && ops->detach != NULL && ops->forget != NULL &&
           ops->destroy != NULL;
}

/** 无回调或接入，只按值保存本次最后通知；context 在登记结束前必须存活。 */
static void listener_observed(vireo_acceptor_t *acceptor, uint32_t events, void *context)
{
    (void)acceptor;
    vireo_tcp_server_t *server = context;
    server->listener_last_events = events;
    if (server->serving_active) server->serve_listener_events |= events;
    if (server->listener_poll_active) server->listener_poll_events |= events;
}

/** public acceptor 的固定申请必须为正且在自身预算内。 */
static bool listener_valid(vireo_acceptor_info_t const *info)
{
    return info->allocation_bytes > 0 && info->allocation_bytes <= info->max_memory_bytes &&
           info->max_memory_bytes <= VIREO_ACCEPTOR_MAX_MEMORY &&
           (info->loop_attached || !info->read_enabled);
}

/** 客户依赖只桥接 public API，无旧 private seam 或全局可变 hooks。 */
static vireo_result_t system_client_accept(void *ctx, vireo_acceptor_t *a,
    vireo_acceptor_accept_budget_t const *b, int *fds, size_t n,
    vireo_acceptor_accept_info_t *i, vireo_acceptor_error_t *e)
{ (void)ctx; return vireo_acceptor_accept_batch(a, b, fds, n, i, e); }
static vireo_result_t system_client_create(void *ctx, vireo_connection_options_t const *o,
    int *fd, vireo_connection_t **p, vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_create(o, fd, p, e); }
static vireo_result_t system_client_inspect(void *ctx, vireo_connection_t const *p,
    vireo_connection_info_t *i)
{ (void)ctx; return vireo_connection_inspect(p, i); }
static vireo_result_t system_client_adopt(void *ctx, vireo_connection_pool_t *p,
    vireo_connection_t **c, vireo_connection_pool_lease_t *l, vireo_connection_pool_operation_error_t *e)
{ (void)ctx; return vireo_connection_pool_adopt(p, c, l, e); }
static vireo_result_t system_client_lookup(void *ctx, vireo_connection_pool_t const *p,
    vireo_connection_pool_lease_t l, vireo_connection_t **c)
{ (void)ctx; return vireo_connection_pool_lookup(p, l, c); }
static vireo_result_t system_client_attach(void *ctx, vireo_connection_t *c,
    vireo_event_loop_t *p, uint32_t mask, vireo_connection_callback_t cb, void *cbctx,
    vireo_connection_loop_error_t *e)
{ (void)ctx; return vireo_connection_attach(c, p, mask, cb, cbctx, e); }
static vireo_result_t system_client_detach(void *ctx, vireo_connection_t *c,
    vireo_connection_loop_error_t *e)
{ (void)ctx; return vireo_connection_detach(c, e); }
static vireo_result_t system_client_release(void *ctx, vireo_connection_pool_t *p,
    vireo_connection_pool_lease_t *l, vireo_connection_pool_operation_error_t *e)
{ (void)ctx; return vireo_connection_pool_release(p, l, e); }
static vireo_result_t system_client_destroy(void *ctx, vireo_connection_t **c,
    vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_destroy(c, e); }
static int system_client_close(void *ctx, int fd)
{ (void)ctx; return close(fd); }
/** 字节桥接不取得第二 owner，也不隐式执行其他网络或调度操作。 */
static vireo_result_t system_client_receive(void *ctx, vireo_connection_t *c,
    vireo_connection_receive_budget_t const *b, vireo_connection_receive_info_t *i,
    vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_receive(c, b, i, e); }
static vireo_result_t system_client_read_peek(void *ctx, vireo_connection_t const *c,
    uint8_t const **p, size_t *n)
{ (void)ctx; return vireo_connection_read_peek(c, p, n); }
static vireo_result_t system_client_read_consume(void *ctx, vireo_connection_t *c, size_t n)
{ (void)ctx; return vireo_connection_read_consume(c, n); }
static vireo_result_t system_client_write_enqueue(void *ctx, vireo_connection_t *c,
    uint8_t const *p, size_t n, vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_write_enqueue(c, p, n, e); }
static vireo_result_t system_client_send(void *ctx, vireo_connection_t *c,
    vireo_connection_send_budget_t const *b, vireo_connection_send_info_t *i,
    vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_send(c, b, i, e); }
static vireo_result_t system_client_frames_peek(void *ctx, vireo_connection_t const *c,
    vireo_connection_frame_options_t const *o, vireo_connection_frame_budget_t const *b,
    vireo_connection_frame_view_t *v, size_t n, vireo_connection_frame_info_t *i,
    vireo_connection_frame_error_t *e)
{ (void)ctx; return vireo_connection_frames_peek(c, o, b, v, n, i, e); }
/**
 * @brief 透传客户 set_interests 的公开策略
 *
 * @param[in] ctx
 *     系统桥接不使用的逐对象借用 context，可空。
 * @param[in,out] c
 *     非空存活客户，本调用短借用，不取得第二 owner。
 * @param[in] interests
 *     LT 三已知关注位组合，仅按值读取。
 * @param[out] error
 *     独立完整连接策略诊断，只借用至返回。
 *
 * @return
 *     公开依赖的原分类，不重试或转换错误。
 *
 * @note 不重复策略状态机；最外层 client_policy 恢复 caller 的入口 errno。
 */
static vireo_result_t policy_set_interests(void *ctx, vireo_connection_t *c,
    uint32_t interests, vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_set_interests(c, interests, error);
}
/**
 * @brief 透传客户 flow_configure 的公开策略
 *
 * @param[in] ctx
 *     系统桥接不使用的逐对象借用 context，可空。
 * @param[in,out] c
 *     非空存活客户，本调用短借用，不取得第二 owner。
 * @param[in] options
 *     独立非空配置，仅本次借用，依赖成功按值保存。
 * @param[out] error
 *     独立完整连接策略诊断，只借用至返回。
 *
 * @return
 *     公开依赖的原分类，不重试或转换错误。
 *
 * @note 不重复策略状态机；最外层 client_policy 恢复 caller 的入口 errno。
 */
static vireo_result_t policy_flow_configure(void *ctx, vireo_connection_t *c,
    vireo_connection_flow_options_t const *options, vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_flow_configure(c, options, error);
}
/**
 * @brief 透传客户 flow_refresh 的公开策略
 *
 * @param[in] ctx
 *     系统桥接不使用的逐对象借用 context，可空。
 * @param[in,out] c
 *     非空存活客户，本调用短借用，不取得第二 owner。
 * @param[out] error
 *     独立完整连接策略诊断，只借用至返回。
 *
 * @return
 *     公开依赖的原分类，不重试或转换错误。
 *
 * @note 不重复策略状态机；最外层 client_policy 恢复 caller 的入口 errno。
 */
static vireo_result_t policy_flow_refresh(void *ctx, vireo_connection_t *c,
    vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_flow_refresh(c, error);
}
/**
 * @brief 透传客户 flow_disable 的公开策略
 *
 * @param[in] ctx
 *     系统桥接不使用的逐对象借用 context，可空。
 * @param[in,out] c
 *     非空存活客户，本调用短借用，不取得第二 owner。
 * @param[out] error
 *     独立完整连接策略诊断，只借用至返回。
 *
 * @return
 *     公开依赖的原分类，不重试或转换错误。
 *
 * @note 不重复策略状态机；最外层 client_policy 恢复 caller 的入口 errno。
 */
static vireo_result_t policy_flow_disable(void *ctx, vireo_connection_t *c,
    vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_flow_disable(c, error);
}
/**
 * @brief 透传客户 request_close 的公开策略
 *
 * @param[in] ctx
 *     系统桥接不使用的逐对象借用 context，可空。
 * @param[in,out] c
 *     非空存活客户，本调用短借用，不取得第二 owner。
 * @param[in] mode
 *     永久关闭模式，按值传递。
 * @param[in] reason
 *     首次关闭原因，按值传递。
 * @param[out] error
 *     独立完整连接策略诊断，只借用至返回。
 *
 * @return
 *     公开依赖的原分类，不重试或转换错误。
 *
 * @note 不重复策略状态机；最外层 client_policy 恢复 caller 的入口 errno。
 */
static vireo_result_t policy_request_close(void *ctx, vireo_connection_t *c,
    vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_request_close(c, mode, reason, error);
}
/**
 * @brief 透传客户 close_refresh 的公开策略
 *
 * @param[in] ctx
 *     系统桥接不使用的逐对象借用 context，可空。
 * @param[in,out] c
 *     非空存活客户，本调用短借用，不取得第二 owner。
 * @param[out] error
 *     独立完整连接策略诊断，只借用至返回。
 *
 * @return
 *     公开依赖的原分类，不重试或转换错误。
 *
 * @note 不重复策略状态机；最外层 client_policy 恢复 caller 的入口 errno。
 */
static vireo_result_t policy_close_refresh(void *ctx, vireo_connection_t *c,
    vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_close_refresh(c, error);
}

static vireo_tcp_server_client_ops_t const system_client_ops = {
    NULL, system_client_accept, system_client_create, system_client_inspect, system_client_adopt,
    system_client_lookup, system_client_attach, system_client_detach, system_client_release,
    system_client_destroy, system_client_close, system_client_receive, system_client_read_peek,
    system_client_read_consume, system_client_write_enqueue, system_client_send, system_client_frames_peek,
    policy_set_interests, policy_flow_configure, policy_flow_refresh, policy_flow_disable,
    policy_request_close, policy_close_refresh
};
static bool client_ops_valid(vireo_tcp_server_client_ops_t const *o)
{
    return o != NULL && o->accept != NULL && o->create != NULL && o->inspect != NULL &&
        o->adopt != NULL && o->lookup != NULL && o->attach != NULL && o->detach != NULL &&
        o->release != NULL && o->destroy != NULL && o->close_fd != NULL && o->receive != NULL &&
        o->read_peek != NULL && o->read_consume != NULL && o->write_enqueue != NULL && o->send != NULL && o->frames_peek != NULL &&
        o->set_interests != NULL &&
        o->flow_configure != NULL &&
        o->flow_refresh != NULL &&
        o->flow_disable != NULL &&
        o->request_close != NULL &&
        o->close_refresh != NULL;
}

/**
 * @brief 完整提交独立诊断并恢复最外层 errno
 *
 * @param[in] result
 *     本次主要分类。
 * @param[in] detail
 *     全部已初始化语义成员，仅调用期借用。
 * @param[out] error
 *     可空独立输出。
 * @param[in] saved_errno
 *     最外层入口值。
 *
 * @return
 *     result 原值。
 *
 * @note 不执行清理，不用 errno 推断成功或失败。
 */
static vireo_result_t finish(vireo_result_t result, vireo_tcp_server_error_t const *detail,
                              vireo_tcp_server_error_t *error, int saved_errno)
{
    if (error != NULL) *error = *detail;
    errno = saved_errno;
    return result;
}

/** 完整按值表才可存入对象，不支持运行中替换。 */
static bool ops_valid(vireo_tcp_server_ops_t const *ops)
{
    return ops != NULL && ops->allocate != NULL && ops->deallocate != NULL &&
           ops->create_loop != NULL && ops->inspect_loop != NULL && ops->destroy_loop != NULL &&
           ops->create_pool != NULL && ops->inspect_pool != NULL && ops->destroy_pool != NULL;
}

/**
 * @brief 验证公开 loop 的固定申请与本项登记数量
 *
 * @param[in] info
 *     依赖公开快照，不读取私有布局。
 * @param[in] options
 *     本次实际交给 loop 的选项。
 * @param[in] registered
 *     本层预期登记数：已绑定客户数加上可选的监听登记。
 *
 * @retval true
 *     数值、受检合计和预期登记数符合公开合同。
 * @retval false
 *     至少一个不变量违反，包括公开字节合计溢出。
 *
 * @note 内部唤醒不计客户 registered_count，已含在 epoll 实际申请中；运行态允许永久停止，新建未停另验。
 */
static bool loop_valid(vireo_event_loop_info_t const *info,
                        vireo_event_loop_options_t const *options, size_t registered)
{
    size_t events = 0;
    size_t work = 0;
    size_t total = 0;
    return vireo_checked_size_mul(options->event_capacity, sizeof(vireo_epoll_event_t),
                                   &events) == VIREO_OK &&
           vireo_checked_size_add(info->events_bytes, info->registrations_bytes,
                                   &work) == VIREO_OK &&
           vireo_checked_size_add(info->loop_allocation_bytes, info->epoll_allocation_bytes,
                                   &total) == VIREO_OK &&
           info->event_capacity == options->event_capacity && info->events_bytes == events &&
           info->registration_capacity == options->registration_capacity &&
           registered <= options->registration_capacity && info->registered_count == registered &&
           info->available_count == options->registration_capacity - registered &&
           info->registrations_bytes > 0 && info->loop_allocation_bytes > work &&
           info->epoll_allocation_bytes > 0 && info->allocation_bytes == total &&
           total <= options->max_memory_bytes &&
           info->max_memory_bytes == options->max_memory_bytes &&
           info->loop_id != 0;
}

/**
 * @brief 验证公开 pool 的固定申请、在用槽和双 buffer 容量账
 *
 * @param[in] info
 *     独立公开快照。
 * @param[in] options
 *     本次实际交给 pool 的选项。
 * @param[in] leased
 *     本层预期拥有的客户数，构造阶段为零。
 * @param[in] buffer_bytes
 *     在用客户的固定双 buffer 容量合计，构造阶段为零。
 *
 * @retval true
 *     受检账、固定容量、在用数量和预算一致。
 * @retval false
 *     数值不符合公开依赖合同。
 *
 * @note 不估计 opaque pool 的 sizeof，基础申请已计在 total 中。
 */
static bool pool_valid(vireo_connection_pool_info_t const *info,
                        vireo_connection_pool_options_t const *options, size_t leased, size_t buffer_bytes)
{
    size_t total = 0;
    return vireo_checked_size_add(info->container_allocation_bytes, info->storage_allocation_bytes,
                                   &total) == VIREO_OK &&
           info->capacity == options->capacity && leased <= options->capacity &&
           info->leased_slots == leased && info->available_slots == options->capacity - leased &&
           info->buffer_capacity_bytes == buffer_bytes && buffer_bytes <= options->max_buffer_bytes &&
           info->index_bytes > 0 && info->container_allocation_bytes > info->index_bytes &&
           info->storage_allocation_bytes > 0 && info->allocation_bytes == total &&
           total <= options->max_memory_bytes && info->max_memory_bytes == options->max_memory_bytes &&
           info->max_buffer_bytes == options->max_buffer_bytes;
}

/**
 * @brief 撤回尚未发布的资源，保留主要错误与首个清理错误
 *
 * @param[in,out] server
 *     尚未发布的 control，调用后失效。
 * @param[in,out] error
 *     已有主因的独立诊断。
 *
 * @note 有效构造的 pool 始终为空，回滚释放成功；loop OK/IO 消费。
 *     违约 hooks/损坏对象不提供通用恢复，不重复销毁同一个资源。
 */
static void rollback(vireo_tcp_server_t *server, vireo_tcp_server_error_t *error)
{
    if (server->pool != NULL) {
        vireo_connection_pool_error_t cause = {0};
        vireo_result_t const result = server->ops.destroy_pool(server->ops.context,
                                                               &server->pool, &cause);
        if (result != VIREO_OK) {
            error->cleanup_result = result;
            error->cleanup_stage = VIREO_TCP_SERVER_STAGE_DESTROY_POOL;
            error->cleanup_pool_error = cause;
        }
    }
    if (server->loop != NULL) {
        vireo_event_loop_error_t cause = {0};
        vireo_result_t const result = server->ops.destroy_loop(server->ops.context,
                                                               &server->loop, &cause);
        if (result != VIREO_OK && error->cleanup_result == VIREO_OK) {
            error->cleanup_result = result;
            error->cleanup_stage = VIREO_TCP_SERVER_STAGE_DESTROY_LOOP;
            error->cleanup_loop_error = cause;
        }
    }
    server->ops.deallocate(server->ops.context, server);
}

static vireo_result_t create_with_dependencies(vireo_tcp_server_options_t const *options,
                                               size_t auxiliary_capacity,
                                               vireo_tcp_server_ops_t const *ops,
                                               vireo_tcp_server_listener_ops_t const *listener_ops,
                                               vireo_tcp_server_client_ops_t const *client_ops,
                                               vireo_tcp_server_scheduler_ops_t const *scheduler_ops,
                                               vireo_tcp_server_stop_ops_t const *stop_ops,
                                               vireo_tcp_server_t **out_server,
                                               vireo_tcp_server_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_error_t detail = {0};
    if (options == NULL || out_server == NULL || !ops_valid(ops) || !listener_ops_valid(listener_ops) || !client_ops_valid(client_ops) || scheduler_ops == NULL || scheduler_ops->run_once == NULL || stop_ops == NULL || stop_ops->request_stop == NULL || *out_server != NULL ||
        options->connection_capacity == 0 || options->event_capacity == 0 ||
        options->max_memory_bytes == 0 || options->max_buffer_bytes == 0) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    }
    if (options->connection_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        options->event_capacity > VIREO_EVENT_LOOP_MAX_EVENTS ||
        options->max_memory_bytes > VIREO_TCP_SERVER_MAX_MEMORY ||
        options->max_buffer_bytes > VIREO_CONNECTION_POOL_MAX_BUFFER_MEMORY ||
        options->max_memory_bytes <= sizeof(vireo_tcp_server_t)) {
        return finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    }
    size_t registrations = 0;
    vireo_result_t result = vireo_checked_size_add(options->connection_capacity, 1, &registrations);
    if (result == VIREO_OK)
        result = vireo_checked_size_add(registrations, auxiliary_capacity, &registrations);
    if (result != VIREO_OK) return finish(result, &detail, error, saved_errno);
    if (registrations > VIREO_EVENT_LOOP_MAX_REGISTRATIONS) {
        return finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    }
    size_t slots_bytes = 0;
    size_t server_bytes = 0;
    result = vireo_checked_size_mul(options->connection_capacity, sizeof(client_slot_t), &slots_bytes);
    if (result == VIREO_OK) result = vireo_checked_size_add(sizeof(vireo_tcp_server_t), slots_bytes, &server_bytes);
    if (result != VIREO_OK) return finish(result, &detail, error, saved_errno);
    if (server_bytes >= options->max_memory_bytes) return finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    vireo_tcp_server_t *server = ops->allocate(ops->context, server_bytes);
    if (server == NULL) {
        detail.stage = VIREO_TCP_SERVER_STAGE_ALLOCATE_CONTROL;
        return finish(VIREO_RESULT_NO_MEMORY, &detail, error, saved_errno);
    }
    *server = (vireo_tcp_server_t){.options = *options, .ops = *ops, .listener_ops = *listener_ops,
        .client_ops = *client_ops, .scheduler_ops = *scheduler_ops, .stop_ops = *stop_ops,
        .queue_head = SIZE_MAX, .queue_tail = SIZE_MAX, .auto_release_ready = false, .auto_close_policy = false,
        .auxiliary_fd = -1,
        .server_bytes = server_bytes, .client_slots_bytes = slots_bytes};
    for (size_t i = 0; i < options->connection_capacity; ++i) server->clients[i] = (client_slot_t){.parent = server, .queue_prev = SIZE_MAX, .queue_next = SIZE_MAX};
    vireo_event_loop_options_t const loop_options = {
        options->event_capacity, options->max_memory_bytes - server_bytes, registrations
    };
    detail.stage = VIREO_TCP_SERVER_STAGE_CREATE_LOOP;
    result = server->ops.create_loop(server->ops.context, &loop_options,
                                     &server->loop, &detail.loop_error);
    if (result != VIREO_OK) goto failed;
    detail.stage = VIREO_TCP_SERVER_STAGE_INSPECT_LOOP;
    result = server->ops.inspect_loop(server->ops.context, server->loop, &server->loop_origin);
    if (result != VIREO_OK) goto failed;
    if (server->loop_origin.stop_requested || !loop_valid(&server->loop_origin, &loop_options, 0)) {
        result = VIREO_RESULT_INTERNAL;
        goto failed;
    }
    size_t subtotal = 0;
    if (vireo_checked_size_add(server_bytes, server->loop_origin.allocation_bytes,
                               &subtotal) != VIREO_OK || subtotal >= options->max_memory_bytes) {
        result = VIREO_RESULT_RANGE;
        goto failed;
    }
    vireo_connection_pool_options_t const pool_options = {
        options->connection_capacity, options->max_memory_bytes - subtotal, options->max_buffer_bytes
    };
    detail.stage = VIREO_TCP_SERVER_STAGE_CREATE_POOL;
    result = server->ops.create_pool(server->ops.context, &pool_options,
                                     &server->pool, &detail.pool_error);
    if (result != VIREO_OK) goto failed;
    detail.stage = VIREO_TCP_SERVER_STAGE_INSPECT_POOL;
    result = server->ops.inspect_pool(server->ops.context, server->pool, &server->pool_origin);
    if (result != VIREO_OK) goto failed;
    size_t total = 0;
    if (!pool_valid(&server->pool_origin, &pool_options, 0, 0) ||
        vireo_checked_size_add(subtotal, server->pool_origin.allocation_bytes,
                               &total) != VIREO_OK || total > options->max_memory_bytes) {
        result = VIREO_RESULT_INTERNAL;
        goto failed;
    }
    *out_server = server;
    detail = (vireo_tcp_server_error_t){0};
    return finish(VIREO_OK, &detail, error, saved_errno);

failed:
    rollback(server, &detail);
    return finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_create_with_all_ops(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_ops_t const *ops, vireo_tcp_server_listener_ops_t const *listener_ops,
    vireo_tcp_server_t **out_server, vireo_tcp_server_error_t *error)
{
    return create_with_dependencies(options, 0, ops, listener_ops, &system_client_ops, &system_scheduler_ops, &system_stop_ops, out_server, error);
}

vireo_result_t vireo_tcp_server_create_with_client_ops(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_ops_t const *ops, vireo_tcp_server_listener_ops_t const *listener_ops,
    vireo_tcp_server_client_ops_t const *client_ops, vireo_tcp_server_t **out_server,
    vireo_tcp_server_error_t *error)
{
    return create_with_dependencies(options, 0, ops != NULL ? ops : &system_ops,
        listener_ops != NULL ? listener_ops : &system_listener_ops, client_ops, &system_scheduler_ops, &system_stop_ops, out_server, error);
}

vireo_result_t vireo_tcp_server_create_with_scheduler_ops(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_ops_t const *ops, vireo_tcp_server_listener_ops_t const *listener_ops,
    vireo_tcp_server_client_ops_t const *client_ops,
    vireo_tcp_server_scheduler_ops_t const *scheduler_ops, vireo_tcp_server_t **out_server,
    vireo_tcp_server_error_t *error)
{
    return create_with_dependencies(options, 0, ops != NULL ? ops : &system_ops,
        listener_ops != NULL ? listener_ops : &system_listener_ops,
        client_ops != NULL ? client_ops : &system_client_ops, scheduler_ops, &system_stop_ops, out_server, error);
}

vireo_result_t vireo_tcp_server_create_with_run_ops(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_ops_t const *ops, vireo_tcp_server_listener_ops_t const *listener_ops,
    vireo_tcp_server_client_ops_t const *client_ops,
    vireo_tcp_server_scheduler_ops_t const *scheduler_ops,
    vireo_tcp_server_stop_ops_t const *stop_ops, vireo_tcp_server_t **out_server,
    vireo_tcp_server_error_t *error)
{
    return create_with_dependencies(options, 0, ops != NULL ? ops : &system_ops,
        listener_ops != NULL ? listener_ops : &system_listener_ops,
        client_ops != NULL ? client_ops : &system_client_ops, scheduler_ops, stop_ops, out_server, error);
}

vireo_result_t vireo_tcp_server_create_with_ops(vireo_tcp_server_options_t const *options,
                                               vireo_tcp_server_ops_t const *ops,
                                               vireo_tcp_server_t **out_server,
                                               vireo_tcp_server_error_t *error)
{
    return vireo_tcp_server_create_with_all_ops(options, ops, &system_listener_ops,
                                                out_server, error);
}

vireo_result_t vireo_tcp_server_create(vireo_tcp_server_options_t const *options,
                                     vireo_tcp_server_t **out_server,
                                     vireo_tcp_server_error_t *error)
{
    return vireo_tcp_server_create_with_ops(options, &system_ops, out_server, error);
}

/** 仅本核心测试使用原公开依赖表；额外容量不授予依赖布局访问权。 */
vireo_result_t vireo_tcp_server_create_with_auxiliary_ops(
    vireo_tcp_server_options_t const *options, size_t auxiliary_capacity,
    vireo_tcp_server_ops_t const *ops, vireo_tcp_server_t **out_server,
    vireo_tcp_server_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_error_t const detail = {0};
    if (auxiliary_capacity == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    return create_with_dependencies(options, auxiliary_capacity, ops, &system_listener_ops,
        &system_client_ops, &system_scheduler_ops, &system_stop_ops, out_server, error);
}

/** 仅本核心组合seam，容量仍受检，完整scheduler/context沿原公开桥接寿命。 */
vireo_result_t vireo_tcp_server_create_with_auxiliary_scheduler_ops(
    vireo_tcp_server_options_t const *options, size_t auxiliary_capacity,
    vireo_tcp_server_scheduler_ops_t const *scheduler_ops, vireo_tcp_server_t **out_server,
    vireo_tcp_server_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_error_t const detail = {0};
    if (auxiliary_capacity == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    return create_with_dependencies(options, auxiliary_capacity, &system_ops, &system_listener_ops,
        &system_client_ops, scheduler_ops, &system_stop_ops, out_server, error);
}

vireo_result_t vireo_tcp_server_create_with_auxiliary_capacity(
    vireo_tcp_server_options_t const *options, size_t auxiliary_capacity,
    vireo_tcp_server_t **out_server, vireo_tcp_server_error_t *error)
{
    return vireo_tcp_server_create_with_auxiliary_ops(options, auxiliary_capacity,
        &system_ops, out_server, error);
}

vireo_result_t vireo_tcp_server_inspect(vireo_tcp_server_t const *server,
                                      vireo_tcp_server_info_t *out_info)
{
    int const saved_errno = errno;
    vireo_tcp_server_error_t const unused = {0};
    if (server == NULL || out_info == NULL) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, &unused, NULL, saved_errno);
    }
    vireo_event_loop_info_t loop_info = {0};
    vireo_connection_pool_info_t pool_info = {0};
    vireo_result_t result = server->ops.inspect_loop(server->ops.context, server->loop, &loop_info);
    if (result != VIREO_OK) return finish(result, &unused, NULL, saved_errno);
    vireo_event_loop_options_t const loop_options = {
        server->options.event_capacity, server->loop_origin.max_memory_bytes,
        server->loop_origin.registration_capacity
    };
    size_t base_registrations = 0;
    if (vireo_checked_size_add(server->options.connection_capacity, 1,
                               &base_registrations) != VIREO_OK ||
        server->loop_origin.registration_capacity < base_registrations)
        return finish(VIREO_RESULT_INTERNAL, &unused, NULL, saved_errno);
    size_t const auxiliary_capacity = server->loop_origin.registration_capacity - base_registrations;
    bool const auxiliary_bound = server->auxiliary_handle.token != 0;
    uint32_t const auxiliary_mask = VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP;
    if ((server->auxiliary_handle.loop_id != 0) != auxiliary_bound ||
        (server->auxiliary_pending_events & ~auxiliary_mask) != 0 ||
        (auxiliary_bound && (auxiliary_capacity == 0 || server->auxiliary_fd < 0 ||
            server->auxiliary_handle.loop_id != server->loop_origin.loop_id)) ||
        (!auxiliary_bound && (server->auxiliary_fd != -1 || server->auxiliary_pending_events != 0)))
        return finish(VIREO_RESULT_INTERNAL, &unused, NULL, saved_errno);
    size_t registered = 0;
    if (server->registered_clients > server->client_count ||
        vireo_checked_size_add(server->registered_clients, server->listener_bound ? 1 : 0,
                                &registered) != VIREO_OK ||
        vireo_checked_size_add(registered, auxiliary_bound ? 1 : 0, &registered) != VIREO_OK ||
        !loop_valid(&loop_info, &loop_options, registered) ||
        loop_info.loop_id != server->loop_origin.loop_id ||
        loop_info.loop_allocation_bytes != server->loop_origin.loop_allocation_bytes ||
        loop_info.epoll_allocation_bytes != server->loop_origin.epoll_allocation_bytes ||
        loop_info.registrations_bytes != server->loop_origin.registrations_bytes) {
        return finish(VIREO_RESULT_INTERNAL, &unused, NULL, saved_errno);
    }
    result = server->ops.inspect_pool(server->ops.context, server->pool, &pool_info);
    if (result != VIREO_OK) return finish(result, &unused, NULL, saved_errno);
    vireo_connection_pool_options_t const pool_options = {
        server->options.connection_capacity, server->pool_origin.max_memory_bytes,
        server->options.max_buffer_bytes
    };
    size_t subtotal = 0;
    size_t total = 0;
    if (!pool_valid(&pool_info, &pool_options, server->client_count, server->buffer_bytes) ||
        pool_info.container_allocation_bytes != server->pool_origin.container_allocation_bytes ||
        pool_info.storage_allocation_bytes != server->pool_origin.storage_allocation_bytes ||
        pool_info.index_bytes != server->pool_origin.index_bytes ||
        vireo_checked_size_add(server->server_bytes, loop_info.allocation_bytes, &subtotal) != VIREO_OK ||
        vireo_checked_size_add(subtotal, pool_info.allocation_bytes, &total) != VIREO_OK ||
        vireo_checked_size_add(total, server->context_wrapper_bytes, &total) != VIREO_OK ||
        total > server->options.max_memory_bytes) {
        return finish(VIREO_RESULT_INTERNAL, &unused, NULL, saved_errno);
    }
    vireo_acceptor_info_t listener_info = {0};
    if (server->listener != NULL) {
        result = server->listener_ops.inspect(server->listener_ops.context, server->listener,
                                              &listener_info);
        if (result != VIREO_OK) return finish(result, &unused, NULL, saved_errno);
        if (!listener_valid(&listener_info) ||
            listener_info.allocation_bytes != server->listener_origin.allocation_bytes ||
            listener_info.max_memory_bytes != server->listener_origin.max_memory_bytes ||
            listener_info.loop_attached != server->listener_bound ||
            listener_info.read_enabled != server->listener_read_enabled ||
            vireo_checked_size_add(total, listener_info.allocation_bytes, &total) != VIREO_OK ||
            total > server->options.max_memory_bytes) {
            return finish(VIREO_RESULT_INTERNAL, &unused, NULL, saved_errno);
        }
    }
    if (!queue_valid(server) || server->shutdown_next_slot >= server->options.connection_capacity ||
        server->close_next_slot >= server->options.connection_capacity)
        return finish(VIREO_RESULT_INTERNAL, &unused, NULL, saved_errno);
    *out_info = (vireo_tcp_server_info_t){
        .connection_capacity = server->options.connection_capacity,
        .event_capacity = server->options.event_capacity,
        .registration_capacity = loop_info.registration_capacity,
        .server_allocation_bytes = server->server_bytes,
        .client_slots_bytes = server->client_slots_bytes,
        .registered_connections = server->registered_clients,
        .loop_allocation_bytes = loop_info.allocation_bytes,
        .pool_allocation_bytes = pool_info.allocation_bytes,
        .listener_allocation_bytes = listener_info.allocation_bytes,
        .allocation_bytes = total,
        .listener_owned = server->listener != NULL,
        .listener_bound = server->listener_bound,
        .listener_read_enabled = server->listener_read_enabled,
        .listener_last_events = server->listener_last_events,
        .max_memory_bytes = server->options.max_memory_bytes,
        .max_buffer_bytes = server->options.max_buffer_bytes,
        .connection_count = pool_info.leased_slots,
        .available_connections = pool_info.available_slots,
        .buffer_capacity_bytes = pool_info.buffer_capacity_bytes,
        .processing_active = server->processing_active,
        .driving_active = server->driving_active,
        .scheduling_active = server->scheduling_active, .pending_clients = server->queue_count,
        .running_active = server->running_active, .stop_requested = loop_info.stop_requested,
        .shutdown_active = server->shutdown_active, .shutdown_next_slot = server->shutdown_next_slot,
        .closing_active = server->closing_active, .close_next_slot = server->close_next_slot,
        .auto_release_ready = server->auto_release_ready, .auto_close_policy = server->auto_close_policy,
        .serving_active = server->serving_active, .admission_enabled = server->admission_enabled,
        .admission_connection_options = server->admission_options.connection,
        .admission_flow_options = server->admission_options.flow,
        .admission_pair_bytes = server->admission_pair_bytes,
        .admission_connection_limited = server->admission_enabled && server->client_count == server->options.connection_capacity,
        .admission_buffer_limited = server->admission_enabled && server->admission_pair_bytes > server->options.max_buffer_bytes - server->buffer_bytes,
        .admission_read_desired = server->admission_enabled && server->client_count < server->options.connection_capacity &&
            server->admission_pair_bytes <= server->options.max_buffer_bytes - server->buffer_bytes,
        .auxiliary_registration_capacity = auxiliary_capacity,
        .auxiliary_read_bound = auxiliary_bound,
        .auxiliary_pending_events = server->auxiliary_pending_events
    };
    return finish(VIREO_OK, &unused, NULL, saved_errno);
}

vireo_result_t vireo_tcp_server_destroy(vireo_tcp_server_t **server,
                                      vireo_tcp_server_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_error_t detail = {0};
    if (server == NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (*server == NULL) return finish(VIREO_OK, &detail, error, saved_errno);
    vireo_tcp_server_t *owner = *server;
    if (owner->closing_active || owner->shutdown_active || owner->running_active || owner->processing_active || owner->driving_active || owner->scheduling_active || owner->serving_active) return finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    if (owner->listener != NULL) {
        vireo_acceptor_info_t info = {0};
        vireo_result_t const check = owner->listener_ops.inspect(owner->listener_ops.context,
                                                                 owner->listener, &info);
        if (check != VIREO_OK) {
            detail.stage = VIREO_TCP_SERVER_STAGE_INSPECT_LISTENER;
            return finish(check, &detail, error, saved_errno);
        }
        if (info.callback_active) return finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    }
    vireo_result_t result = owner->ops.destroy_pool(owner->ops.context, &owner->pool,
                                                    &detail.pool_error);
    if (result != VIREO_OK) {
        detail.stage = VIREO_TCP_SERVER_STAGE_DESTROY_POOL;
        return finish(result, &detail, error, saved_errno);
    }
    result = owner->ops.destroy_loop(owner->ops.context, &owner->loop, &detail.loop_error);
    if (result != VIREO_OK && result != VIREO_RESULT_IO) {
        /* 有效隐藏 loop 从未运行；其他拒绝意味着前置/依赖已损坏，不伪造消费。 */
        detail.stage = VIREO_TCP_SERVER_STAGE_DESTROY_LOOP;
        return finish(result, &detail, error, saved_errno);
    }
    if (result == VIREO_RESULT_IO) detail.stage = VIREO_TCP_SERVER_STAGE_DESTROY_LOOP;
    if (owner->listener != NULL) {
        /* loop OK/IO 已真实消费且全部使用者结束，才满足 public forget 的严格前置。 */
        vireo_result_t const forgotten = owner->listener_ops.forget(owner->listener_ops.context,
                                                                    owner->listener);
        if (forgotten != VIREO_OK) {
            /* 有效对象不会到此；违约 hooks 不伪造资源消费或通用恢复。 */
            return finish(forgotten, &detail, error, saved_errno);
        }
        vireo_acceptor_error_t cause = {0};
        vireo_result_t const closed = owner->listener_ops.destroy(owner->listener_ops.context,
                                                                 &owner->listener, &cause);
        if (closed != VIREO_OK && closed != VIREO_RESULT_IO) {
            return finish(closed, &detail, error, saved_errno);
        }
        if (closed != VIREO_OK) {
            if (result == VIREO_OK) {
                result = closed;
                detail.stage = VIREO_TCP_SERVER_STAGE_DESTROY_LISTENER;
                detail.acceptor_error = cause;
            } else {
                detail.cleanup_result = closed;
                detail.cleanup_stage = VIREO_TCP_SERVER_STAGE_DESTROY_LISTENER;
                detail.cleanup_acceptor_error = cause;
            }
        }
    }
    /* pool已空且loop消费后，不再有SSL创建或回调借用；context销毁不做网络。 */
    if (owner->owned_tls_context != NULL)
        (void)vireo_tls_context_destroy(&owner->owned_tls_context, NULL);
    owner->ops.deallocate(owner->ops.context, owner);
    *server = NULL;
    return finish(result, &detail, error, saved_errno);
}

/** 同Reactor六有限阶段保护；整run的observer安全窗口不在这些阶段中。 */
static bool auxiliary_active(vireo_tcp_server_t const *s)
{
    return s->closing_active || s->shutdown_active || s->processing_active || s->driving_active ||
        s->scheduling_active || s->serving_active;
}

/** 独立原因覆盖与errno保持；基本拒绝/成功为NONE，不处理fd或回滚登记。 */
static vireo_result_t auxiliary_finish(vireo_result_t result,
    vireo_tcp_server_auxiliary_stage_t stage, vireo_event_loop_error_t loop_error,
    vireo_tcp_server_auxiliary_error_t *error, int saved_errno)
{
    if (error != NULL) *error = (vireo_tcp_server_auxiliary_error_t){
        result == VIREO_OK ? VIREO_TCP_SERVER_AUXILIARY_NONE : stage, loop_error};
    errno = saved_errno;
    return result;
}

/**
 * @brief
 *     自有loop的固定内部辅助回调，O(1)合并当前身份的原就绪位。
 *
 * @param[in] loop
 *     借用自有loop，不保存或对外暴露。
 * @param[in] handle
 *     当前完整登记身份，仅字段相等核对，不解码token。
 * @param[in] fd
 *     原登记借用fd，0合法。
 * @param[in] events
 *     公开过滤后的READ/ERROR/HANGUP。
 * @param[in,out] context
 *     存活server，登记借用由自有loop/控制块寿命保证。
 *
 * @note
 *     只OR数值，不消费fd、调用用户函数、分配、阻塞或解除在途保护。
 */
static void auxiliary_ready(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
    int fd, uint32_t events, void *context)
{
    vireo_tcp_server_t *s = context;
    if (s->loop == loop && s->auxiliary_handle.loop_id == handle.loop_id &&
        s->auxiliary_handle.token == handle.token && s->auxiliary_fd == fd)
        s->auxiliary_pending_events |= events;
}

static vireo_result_t auxiliary_inspect_public(void *context, vireo_event_loop_t const *loop,
    vireo_event_loop_handle_t handle, vireo_event_loop_registration_t *registration)
{
    (void)context;
    return vireo_event_loop_registration_inspect(loop, handle, registration);
}
static vireo_result_t auxiliary_add_public(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_registration_t const *registration, vireo_event_loop_handle_t *handle,
    vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_add(loop, registration, handle, error);
}
static vireo_result_t auxiliary_del_public(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_handle_t *handle, vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_del(loop, handle, error);
}
static vireo_tcp_server_auxiliary_ops_t const auxiliary_system_ops = {
    NULL, auxiliary_inspect_public, auxiliary_add_public, auxiliary_del_public};

static bool auxiliary_ops_valid(vireo_tcp_server_auxiliary_ops_t const *ops)
{
    return ops != NULL && ops->inspect != NULL && ops->add != NULL && ops->del != NULL;
}

vireo_result_t vireo_tcp_server_auxiliary_read_register_with_ops(vireo_tcp_server_t *s, int fd,
    vireo_event_loop_handle_t *out, vireo_tcp_server_auxiliary_error_t *error,
    vireo_tcp_server_auxiliary_ops_t const *ops)
{
    int const saved_errno = errno;
    vireo_event_loop_error_t detail = {0};
    if (s == NULL || fd < 0 || out == NULL || !auxiliary_ops_valid(ops) ||
        out->loop_id != 0 || out->token != 0)
        return auxiliary_finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_TCP_SERVER_AUXILIARY_NONE,
            detail, error, saved_errno);
    if (auxiliary_active(s))
        return auxiliary_finish(VIREO_RESULT_BUSY, VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING,
            detail, error, saved_errno);
    size_t base = 0;
    if (vireo_checked_size_add(s->options.connection_capacity, 1, &base) != VIREO_OK ||
        s->loop_origin.registration_capacity < base)
        return auxiliary_finish(VIREO_RESULT_INTERNAL, VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING,
            detail, error, saved_errno);
    if (s->loop_origin.registration_capacity == base)
        return auxiliary_finish(VIREO_RESULT_NOT_FOUND, VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING,
            detail, error, saved_errno);
    if (s->auxiliary_handle.token != 0)
        return auxiliary_finish(VIREO_RESULT_BUSY, VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING,
            detail, error, saved_errno);
    vireo_event_loop_registration_t const registration = {
        fd, VIREO_EPOLL_INTEREST_READ, auxiliary_ready, s};
    vireo_event_loop_handle_t handle = {0};
    vireo_result_t const result = ops->add(ops->context, s->loop, &registration, &handle, &detail);
    if (result == VIREO_OK) {
        s->auxiliary_handle = handle;
        s->auxiliary_fd = fd;
        s->auxiliary_pending_events = 0;
        *out = handle;
    }
    return auxiliary_finish(result, VIREO_TCP_SERVER_AUXILIARY_REGISTER, detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_auxiliary_read_unregister_with_ops(vireo_tcp_server_t *s,
    vireo_event_loop_handle_t *handle, vireo_tcp_server_auxiliary_error_t *error,
    vireo_tcp_server_auxiliary_ops_t const *ops)
{
    int const saved_errno = errno;
    vireo_event_loop_error_t detail = {0};
    if (s == NULL || handle == NULL || !auxiliary_ops_valid(ops))
        return auxiliary_finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_TCP_SERVER_AUXILIARY_NONE,
            detail, error, saved_errno);
    vireo_event_loop_registration_t registration = {0};
    vireo_result_t result = ops->inspect(ops->context, s->loop, *handle, &registration);
    if (result != VIREO_OK)
        return auxiliary_finish(result, VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING, detail, error, saved_errno);
    if (handle->loop_id != s->auxiliary_handle.loop_id || handle->token != s->auxiliary_handle.token)
        return auxiliary_finish(VIREO_RESULT_NOT_FOUND, VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING,
            detail, error, saved_errno);
    if (auxiliary_active(s))
        return auxiliary_finish(VIREO_RESULT_BUSY, VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING,
            detail, error, saved_errno);
    vireo_event_loop_handle_t local = *handle;
    result = ops->del(ops->context, s->loop, &local, &detail);
    if (result == VIREO_OK) {
        s->auxiliary_handle = (vireo_event_loop_handle_t){0};
        s->auxiliary_fd = -1;
        s->auxiliary_pending_events = 0;
        *handle = (vireo_event_loop_handle_t){0};
    }
    return auxiliary_finish(result, VIREO_TCP_SERVER_AUXILIARY_UNREGISTER, detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_auxiliary_read_register(vireo_tcp_server_t *s, int fd,
    vireo_event_loop_handle_t *out, vireo_tcp_server_auxiliary_error_t *error)
{
    return vireo_tcp_server_auxiliary_read_register_with_ops(s, fd, out, error, &auxiliary_system_ops);
}

vireo_result_t vireo_tcp_server_auxiliary_read_unregister(vireo_tcp_server_t *s,
    vireo_event_loop_handle_t *handle, vireo_tcp_server_auxiliary_error_t *error)
{
    return vireo_tcp_server_auxiliary_read_unregister_with_ops(s, handle, error, &auxiliary_system_ops);
}

vireo_result_t vireo_tcp_server_auxiliary_read_take_ready(vireo_tcp_server_t *s,
    vireo_tcp_server_auxiliary_event_t *out, vireo_tcp_server_auxiliary_error_t *error)
{
    int const saved_errno = errno;
    vireo_event_loop_error_t const detail = {0};
    if (s == NULL || out == NULL)
        return auxiliary_finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_TCP_SERVER_AUXILIARY_NONE,
            detail, error, saved_errno);
    if (auxiliary_active(s))
        return auxiliary_finish(VIREO_RESULT_BUSY, VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING,
            detail, error, saved_errno);
    if (s->auxiliary_handle.token == 0 || s->auxiliary_pending_events == 0)
        return auxiliary_finish(VIREO_RESULT_NOT_FOUND, VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING,
            detail, error, saved_errno);
    *out = (vireo_tcp_server_auxiliary_event_t){s->auxiliary_handle, s->auxiliary_pending_events};
    s->auxiliary_pending_events = 0;
    return auxiliary_finish(VIREO_OK, VIREO_TCP_SERVER_AUXILIARY_NONE, detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_adopt_listener(vireo_tcp_server_t *server,
                                              vireo_acceptor_t **listener_owner,
                                              vireo_tcp_server_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_error_t detail = {0};
    if (server == NULL || listener_owner == NULL || *listener_owner == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active) return finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    if (server->listener != NULL) return finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_acceptor_info_t info = {0};
    vireo_result_t result = server->listener_ops.inspect(server->listener_ops.context,
                                                        *listener_owner, &info);
    if (result != VIREO_OK) {
        detail.stage = VIREO_TCP_SERVER_STAGE_INSPECT_LISTENER;
        return finish(result, &detail, error, saved_errno);
    }
    if (!listener_valid(&info)) {
        detail.stage = VIREO_TCP_SERVER_STAGE_INSPECT_LISTENER;
        return finish(VIREO_RESULT_INTERNAL, &detail, error, saved_errno);
    }
    if (info.loop_attached || info.callback_active)
        return finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_tcp_server_info_t current = {0};
    result = vireo_tcp_server_inspect(server, &current);
    if (result != VIREO_OK) {
        detail.stage = VIREO_TCP_SERVER_STAGE_INSPECT_RESOURCES;
        return finish(result, &detail, error, saved_errno);
    }
    size_t total = 0;
    result = vireo_checked_size_add(current.allocation_bytes, info.allocation_bytes, &total);
    if (result != VIREO_OK) return finish(result, &detail, error, saved_errno);
    if (total > server->options.max_memory_bytes)
        return finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    server->listener_origin = info;
    server->listener = *listener_owner;
    *listener_owner = NULL;
    return finish(VIREO_OK, &detail, error, saved_errno);
}

/** 独立绑定诊断完整提交，恢复入口 errno；主资源诊断不参与。 */
static vireo_result_t listener_finish(vireo_result_t result,
                                       vireo_tcp_server_listener_error_t const *detail,
                                       vireo_tcp_server_listener_error_t *error, int saved_errno)
{
    if (error != NULL) *error = *detail;
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_tcp_server_bind_listener(vireo_tcp_server_t *server, bool read_enabled,
                                             vireo_tcp_server_listener_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_listener_error_t detail = {0};
    if (server == NULL) return listener_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active) return listener_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    if (server->listener == NULL) return listener_finish(VIREO_RESULT_NOT_FOUND, &detail, error, saved_errno);
    if (server->listener_bound) return listener_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_result_t const result = server->listener_ops.attach(server->listener_ops.context,
        server->listener, server->loop, read_enabled, listener_observed, server, &detail.acceptor_error);
    if (result != VIREO_OK) detail.stage = VIREO_TCP_SERVER_LISTENER_BIND;
    else {
        server->listener_bound = true;
        server->listener_read_enabled = read_enabled;
        server->listener_last_events = 0;
    }
    return listener_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_set_listener_read_enabled(vireo_tcp_server_t *server,
                                                         bool read_enabled,
                                                         vireo_tcp_server_listener_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_listener_error_t detail = {0};
    if (server == NULL) return listener_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active) return listener_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    if (server->admission_enabled) return listener_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    if (server->listener == NULL || !server->listener_bound)
        return listener_finish(VIREO_RESULT_NOT_FOUND, &detail, error, saved_errno);
    vireo_result_t const result = server->listener_ops.set_read(server->listener_ops.context,
        server->listener, read_enabled, &detail.acceptor_error);
    if (result != VIREO_OK) detail.stage = VIREO_TCP_SERVER_LISTENER_UPDATE;
    else server->listener_read_enabled = read_enabled;
    return listener_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_unbind_listener(vireo_tcp_server_t *server,
                                               vireo_tcp_server_listener_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_listener_error_t detail = {0};
    if (server == NULL) return listener_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active) return listener_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    if (server->listener == NULL) return listener_finish(VIREO_RESULT_NOT_FOUND, &detail, error, saved_errno);
    if (!server->listener_bound) return listener_finish(VIREO_OK, &detail, error, saved_errno);
    vireo_result_t const result = server->listener_ops.detach(server->listener_ops.context,
        server->listener, &detail.acceptor_error);
    if (result != VIREO_OK) detail.stage = VIREO_TCP_SERVER_LISTENER_UNBIND;
    else {
        server->listener_bound = false;
        server->listener_read_enabled = false;
        server->listener_last_events = 0;
        server->admission_enabled = false;
        server->admission_options = (vireo_tcp_server_admission_options_t){0};
        server->admission_pair_bytes = 0;
    }
    return listener_finish(result, &detail, error, saved_errno);
}

/** 独立客户诊断完整提交；主要分类不受清理错误或入口 errno 影响。 */
static vireo_result_t client_finish(vireo_result_t result, vireo_tcp_server_client_error_t const *detail,
                                    vireo_tcp_server_client_error_t *error, int saved_errno)
{
    if (error != NULL) *error = *detail;
    errno = saved_errno;
    return result;
}
static bool lease_empty(vireo_connection_pool_lease_t l)
{ return l.pool_id == 0 && l.slot_index == 0 && l.generation == 0; }
static bool lease_equal(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b)
{ return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation; }

/** 所属 loop 先查当前 token；固定槽通知只观察/合并入队，业务在分发返回后执行。 */
static void client_observed(vireo_connection_t *connection, uint32_t events, void *context)
{
    (void)connection;
    client_slot_t *slot = context;
    slot->last_events = events;
    vireo_tcp_server_t *server = slot->parent;
    uint32_t const known = VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_WRITE |
        VIREO_EPOLL_EVENT_PEER_WRITE_CLOSED | VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP;
    if (server == NULL) return; /* 健康绑定必有 parent，损坏 context 不可用来恢复资源。 */
    if ((events & ~known) != 0 || queue_append(server, slot->lease.slot_index) != VIREO_OK)
        server->queue_fault = true;
    else slot->pending_events |= events;
}

/** 先经公开 pool 验证租约，再按当前槽核对本层身份，不接受过期/跨池权限。 */
static vireo_result_t find_client(vireo_tcp_server_t const *server, vireo_connection_pool_lease_t lease,
                                  vireo_connection_t **out_connection)
{
    vireo_result_t const result = server->client_ops.lookup(server->client_ops.context,
                                                           server->pool, lease, out_connection);
    if (result != VIREO_OK) return result;
    if (*out_connection == NULL || lease.slot_index >= server->options.connection_capacity)
        return VIREO_RESULT_INTERNAL;
    client_slot_t const *slot = &server->clients[lease.slot_index];
    return slot->live && lease_equal(slot->lease, lease) ? VIREO_OK : VIREO_RESULT_INTERNAL;
}

/** 按唯一当前 owner 清理一个未发布客户，单次消费；不触碰此前成功客户。 */
static void clean_pending(vireo_tcp_server_t *server, int *fd, vireo_connection_t **connection,
                           vireo_connection_pool_lease_t *lease, vireo_tcp_server_client_error_t *error)
{
    vireo_tcp_server_client_ops_t const *o = &server->client_ops;
    if (!lease_empty(*lease)) {
        error->cleanup_result = o->release(o->context, server->pool, lease, &error->cleanup.pool_error);
        if (error->cleanup_result != VIREO_OK) error->cleanup.stage = VIREO_TCP_SERVER_CLIENT_RELEASE;
    } else if (*connection != NULL) {
        error->cleanup_result = o->destroy(o->context, connection, &error->cleanup.connection_error);
        if (error->cleanup_result != VIREO_OK) error->cleanup.stage = VIREO_TCP_SERVER_CLIENT_DESTROY_PENDING;
    } else if (*fd >= 0) {
        int const result = o->close_fd(o->context, *fd);
        int const system_errno = errno;
        *fd = -1;
        if (result != 0) {
            error->cleanup_result = result == -1 ? VIREO_RESULT_IO : VIREO_RESULT_INTERNAL;
            error->cleanup.stage = VIREO_TCP_SERVER_CLIENT_CLOSE_PENDING_FD;
            error->cleanup.system_errno = result == -1 ? system_errno : 0;
        }
    }
}

/**
 * @brief 复用显式准入核心，逐个发布已接管并登记的客户
 *
 * @param[in,out] server
 *     存活资源根，仅 Reactor 使用。
 * @param[in] options
 *     公开 connection 数值选项，仅调用期借用。
 * @param[in] budget
 *     显式成功接入数与系统调用次数预算。
 * @param[out] out_clients
 *     有效前缀入口全零；仅成功登记后写入 owned 租约。
 * @param[in] capacity
 *     数组容量，1..65535，与预算取较小值。
 * @param[out] out_info
 *     必需统计，前置拒绝保持，执行后提交真实进度。
 * @param[out] error
 *     可空独立原主因及首清理错误。
 * @param[in] from_serve
 *     仅组合服务传 true，越过自身 serving 标记，仍拒绝其他在途。
 *
 * @return
 *     原显式准入分类；失败不回滚先前已发布客户。
 *
 * @note 公共 wrapper 固定 false；不初始化 flow、不刷新监听，恢复入口 errno。
 */
static vireo_result_t admit_clients(vireo_tcp_server_t *server,
    vireo_connection_options_t const *options, vireo_tcp_server_admit_budget_t const *budget,
    vireo_connection_pool_lease_t *out_clients, size_t capacity,
    vireo_tcp_server_admit_info_t *out_info, vireo_tcp_server_client_error_t *error, bool from_serve)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || options == NULL || budget == NULL || out_clients == NULL || out_info == NULL ||
        budget->max_accepts == 0 || budget->max_accept_syscalls == 0)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->owned_tls_context != NULL || server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || (server->serving_active && !from_serve)) return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    if (capacity == 0 || capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        budget->max_accepts > VIREO_TCP_SERVER_MAX_CONNECTIONS)
        return client_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    size_t pair_bytes = 0;
    vireo_result_t result = vireo_checked_size_add(options->read_capacity, options->write_capacity, &pair_bytes);
    if (result != VIREO_OK) return client_finish(result, &detail, error, saved_errno);
    if (options->read_capacity == 0 || options->write_capacity == 0 || options->max_buffer_bytes == 0 ||
        options->read_capacity > VIREO_BUFFER_MAX_CAPACITY || options->write_capacity > VIREO_BUFFER_MAX_CAPACITY ||
        options->max_buffer_bytes > VIREO_CONNECTION_MAX_BUFFER_BYTES || pair_bytes > options->max_buffer_bytes ||
        pair_bytes > server->options.max_buffer_bytes)
        return client_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    size_t const limit = budget->max_accepts < capacity ? budget->max_accepts : capacity;
    for (size_t i = 0; i < limit; ++i)
        if (!lease_empty(out_clients[i]))
            return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->listener == NULL) return client_finish(VIREO_RESULT_NOT_FOUND, &detail, error, saved_errno);
    vireo_tcp_server_info_t current = {0};
    result = vireo_tcp_server_inspect(server, &current);
    if (result != VIREO_OK) {
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT_SERVER;
        return client_finish(result, &detail, error, saved_errno);
    }
    vireo_tcp_server_admit_info_t progress = {0};
    vireo_tcp_server_client_ops_t const *o = &server->client_ops;
    for (;;) {
        if (progress.accepted_count == limit) { progress.stop_reason = VIREO_TCP_SERVER_ADMIT_BATCH_LIMIT; break; }
        if (server->client_count == server->options.connection_capacity) {
            progress.stop_reason = VIREO_TCP_SERVER_ADMIT_CONNECTION_LIMIT; break;
        }
        if (pair_bytes > server->options.max_buffer_bytes - server->buffer_bytes) {
            progress.stop_reason = VIREO_TCP_SERVER_ADMIT_BUFFER_LIMIT; break;
        }
        if (progress.accept_calls == budget->max_accept_syscalls) {
            progress.stop_reason = VIREO_TCP_SERVER_ADMIT_CALL_LIMIT; break;
        }
        vireo_acceptor_accept_budget_t const single = {1, budget->max_accept_syscalls - progress.accept_calls};
        vireo_acceptor_accept_info_t accepted = {0};
        int fd = -1;
        vireo_connection_t *connection = NULL;
        vireo_connection_pool_lease_t lease = {0};
        client_slot_t *slot = NULL;
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_ACCEPT;
        result = o->accept(o->context, server->listener, &single, &fd, 1, &accepted, &detail.primary.acceptor_error);
        if (accepted.accepted_count > 1 || accepted.accept_calls > single.max_syscalls ||
            accepted.transient_errors > accepted.accept_calls ||
            accepted.accepted_count > accepted.accept_calls ||
            (accepted.accepted_count == 1) != (fd >= 0) ||
            vireo_checked_size_add(progress.accept_calls, accepted.accept_calls, &progress.accept_calls) != VIREO_OK ||
            vireo_checked_size_add(progress.transient_errors, accepted.transient_errors,
                                    &progress.transient_errors) != VIREO_OK) {
            result = VIREO_RESULT_INTERNAL;
            goto rejected;
        }
        progress.accepted_count += accepted.accepted_count; /* <= 显式 limit，受检预算保证不回绕。 */
        if (result != VIREO_OK) goto rejected;
        if (fd < 0) {
            if (accepted.stop_reason == VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK)
                progress.stop_reason = VIREO_TCP_SERVER_ADMIT_WOULD_BLOCK;
            else if (accepted.stop_reason == VIREO_ACCEPTOR_ACCEPT_CALL_BUDGET &&
                     progress.accept_calls == budget->max_accept_syscalls)
                progress.stop_reason = VIREO_TCP_SERVER_ADMIT_CALL_LIMIT;
            else { result = VIREO_RESULT_INTERNAL; goto rejected; }
            detail = (vireo_tcp_server_client_error_t){0};
            break;
        }
        detail.primary = (vireo_tcp_server_client_cause_t){.stage = VIREO_TCP_SERVER_CLIENT_CREATE};
        result = o->create(o->context, options, &fd, &connection, &detail.primary.connection_error);
        if (result != VIREO_OK) goto rejected;
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_ADOPT;
        result = o->adopt(o->context, server->pool, &connection, &lease, &detail.primary.pool_error);
        if (result != VIREO_OK) goto rejected;
        if (lease.slot_index >= server->options.connection_capacity || lease_empty(lease)) {
            result = VIREO_RESULT_INTERNAL; goto rejected;
        }
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
        vireo_connection_t *borrowed = NULL;
        result = o->lookup(o->context, server->pool, lease, &borrowed);
        if (result != VIREO_OK) goto rejected;
        if (borrowed == NULL) { result = VIREO_RESULT_INTERNAL; goto rejected; }
        slot = &server->clients[lease.slot_index];
        if (slot->live) { result = VIREO_RESULT_INTERNAL; goto rejected; }
        *slot = (client_slot_t){.lease = lease, .buffer_bytes = pair_bytes, .parent = server,
            .queue_prev = SIZE_MAX, .queue_next = SIZE_MAX};
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_ATTACH;
        result = o->attach(o->context, borrowed, server->loop,
            VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED,
            client_observed, slot, &detail.primary.loop_error);
        if (result != VIREO_OK) goto rejected;
        slot->live = true;
        slot->bound = true;
        ++server->client_count;
        ++server->registered_clients;
        server->buffer_bytes += pair_bytes; /* 前置证明 <= pool max，且只有当前 Reactor 改写。 */
        out_clients[progress.admitted_count++] = lease;
        detail = (vireo_tcp_server_client_error_t){0};
        continue;

rejected:
        progress.rejected_count = progress.accepted_count - progress.admitted_count;
        clean_pending(server, &fd, &connection, &lease, &detail);
        if (slot != NULL && lease_empty(lease)) *slot = (client_slot_t){.parent = server, .queue_prev = SIZE_MAX, .queue_next = SIZE_MAX};
        progress.stop_reason = VIREO_TCP_SERVER_ADMIT_ERROR;
        break;
    }
    *out_info = progress;
    return client_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_admit_batch(vireo_tcp_server_t *server,
    vireo_connection_options_t const *options, vireo_tcp_server_admit_budget_t const *budget,
    vireo_connection_pool_lease_t *out_clients, size_t capacity,
    vireo_tcp_server_admit_info_t *out_info, vireo_tcp_server_client_error_t *error)
{
    return admit_clients(server, options, budget, out_clients, capacity, out_info, error, false);
}

vireo_result_t vireo_tcp_server_client_peer_query(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_connection_peer_t *peer,
    vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || peer == NULL)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = find_client(server, client, &connection);
    if (result != VIREO_OK) {
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
        return client_finish(result, &detail, error, saved_errno);
    }
    result = vireo_connection_peer_query(connection, peer, &detail.primary.connection_error);
    if (result != VIREO_OK) detail.primary.stage = VIREO_TCP_SERVER_CLIENT_QUERY_PEER;
    return client_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_client_inspect(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_info_t *out_info)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t const unused = {0};
    if (server == NULL || out_info == NULL)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &unused, NULL, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = find_client(server, client, &connection);
    if (result != VIREO_OK) return client_finish(result, &unused, NULL, saved_errno);
    vireo_tcp_server_client_info_t info = {0};
    result = server->client_ops.inspect(server->client_ops.context, connection, &info.connection_info);
    client_slot_t const *slot = &server->clients[client.slot_index];
    if (result == VIREO_OK && (info.connection_info.loop_attached != slot->bound ||
        info.connection_info.buffer_capacity_bytes != slot->buffer_bytes)) result = VIREO_RESULT_INTERNAL;
    if (result == VIREO_OK) { info.last_events = slot->last_events; info.queued = slot->queued;
        info.pending_events = slot->pending_events; *out_info = info; }
    return client_finish(result, &unused, NULL, saved_errno);
}

/** 私有调用权限，仅各入口验证及安全时点后使用；不改变公共在途保护。 */
typedef enum release_scope {
    RELEASE_EXPLICIT,
    RELEASE_SHUTDOWN,
    RELEASE_ROUND
} release_scope_t;

/**
 * @brief 复用客户释放路径，按调用来源授予有限内部清理权限
 *
 * @param[in,out] server
 *     存活资源根，独占原pool/loop；processing/driving在途始终拒绝。
 * @param[in,out] client
 *     独立当前 lease 副本，实际消费时类型化清零。
 * @param[out] error
 *     可空独立完整原诊断。
 * @param[in] scope
 *     EXPLICIT无在途权限；SHUTDOWN仅清理入口；ROUND仅drive/回调已返回的服务turn。
 *
 * @return
 *     沿原显式释放合同；OK/消费型 IO 均退款撤队，拒绝保持客户。
 *
 * @note 不复制释放实现，不重试 DEL/close；所有出口恢复入口 errno。
 */
static vireo_result_t release_client(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t *client, vireo_tcp_server_client_error_t *error, release_scope_t scope)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || client == NULL)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || (server->shutdown_active && scope != RELEASE_SHUTDOWN) ||
        server->processing_active || server->driving_active ||
        ((server->scheduling_active || server->serving_active) && scope != RELEASE_ROUND))
        return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = find_client(server, *client, &connection);
    if (result != VIREO_OK) {
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
        return client_finish(result, &detail, error, saved_errno);
    }
    vireo_connection_info_t info = {0};
    result = server->client_ops.inspect(server->client_ops.context, connection, &info);
    if (result != VIREO_OK) {
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT;
        return client_finish(result, &detail, error, saved_errno);
    }
    if (info.callback_active) return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    client_slot_t *slot = &server->clients[client->slot_index];
    if (slot->bound) {
        result = server->client_ops.detach(server->client_ops.context, connection, &detail.primary.loop_error);
        if (result != VIREO_OK) {
            detail.primary.stage = VIREO_TCP_SERVER_CLIENT_DETACH;
            return client_finish(result, &detail, error, saved_errno);
        }
        slot->bound = false;
        --server->registered_clients;
    }
    vireo_connection_pool_lease_t local = *client;
    result = server->client_ops.release(server->client_ops.context, server->pool, &local, &detail.primary.pool_error);
    if (result != VIREO_OK) detail.primary.stage = VIREO_TCP_SERVER_CLIENT_RELEASE;
    if (result == VIREO_OK || result == VIREO_RESULT_IO) {
        if (!lease_empty(local)) return client_finish(VIREO_RESULT_INTERNAL, &detail, error, saved_errno);
        vireo_result_t const removed = queue_remove(server, client->slot_index);
        if (removed != VIREO_OK) result = removed; /* 消费已发生，仍清 owner/账；坏链不承诺恢复。 */
        --server->client_count;
        server->buffer_bytes -= slot->buffer_bytes;
        *slot = (client_slot_t){.parent = server, .queue_prev = SIZE_MAX, .queue_next = SIZE_MAX};
        *client = (vireo_connection_pool_lease_t){0};
    }
    return client_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_release_client(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t *client, vireo_tcp_server_client_error_t *error)
{
    return release_client(server, client, error, RELEASE_EXPLICIT);
}

vireo_result_t vireo_tcp_server_shutdown_batch(vireo_tcp_server_t *server,
    vireo_tcp_server_shutdown_budget_t const *budget,
    vireo_tcp_server_shutdown_result_t *out_results, size_t result_capacity,
    vireo_tcp_server_shutdown_info_t *out_info, vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || budget == NULL || out_results == NULL || out_info == NULL ||
        budget->max_slots == 0 || result_capacity == 0)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    size_t const max_slots = budget->max_slots;
    if (max_slots > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        result_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS)
        return client_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->running_active || server->processing_active ||
        server->driving_active || server->scheduling_active || server->serving_active)
        return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    bool stopped = false;
    vireo_result_t result = stop_snapshot(server, &stopped);
    if (result != VIREO_OK) {
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT_SERVER;
        return client_finish(result, &detail, error, saved_errno);
    }
    if (!stopped) return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    size_t const capacity = server->options.connection_capacity;
    if (server->shutdown_next_slot >= capacity || !queue_valid(server)) {
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT_SERVER;
        return client_finish(VIREO_RESULT_INTERNAL, &detail, error, saved_errno);
    }
    size_t const slot_limit = max_slots < capacity ? max_slots : capacity;
    vireo_tcp_server_shutdown_info_t progress = {0};
    server->shutdown_active = true;
    while (server->client_count != 0 && progress.scanned_slots < slot_limit &&
        progress.attempted_clients < result_capacity) {
        size_t const index = server->shutdown_next_slot;
        /* capacity <= 65535，推进和本批计数均有先验界，不依赖整数回绕。 */
        server->shutdown_next_slot = index + 1 == capacity ? 0 : index + 1;
        ++progress.scanned_slots;
        if (!server->clients[index].live) continue;
        vireo_tcp_server_shutdown_result_t row = {.lease = server->clients[index].lease};
        vireo_connection_pool_lease_t local = row.lease;
        row.result = release_client(server, &local, &row.error, RELEASE_SHUTDOWN);
        row.released = lease_empty(local);
        out_results[progress.attempted_clients++] = row;
        if (row.released) ++progress.released_clients;
        if (row.result != VIREO_OK) {
            result = row.result;
            detail = row.error;
            progress.stop_reason = VIREO_TCP_SERVER_SHUTDOWN_ERROR;
            break;
        }
    }
    progress.remaining_clients = server->client_count;
    progress.next_slot = server->shutdown_next_slot;
    if (result == VIREO_OK) {
        progress.stop_reason = server->client_count == 0 ? VIREO_TCP_SERVER_SHUTDOWN_COMPLETE :
            progress.scanned_slots == slot_limit ? VIREO_TCP_SERVER_SHUTDOWN_SLOT_BUDGET :
            VIREO_TCP_SERVER_SHUTDOWN_RESULT_CAPACITY;
    }
    server->shutdown_active = false;
    *out_info = progress;
    return client_finish(result, &detail, error, saved_errno);
}

/**
 * @brief 为一个字节操作验证当前存储权限
 *
 * @param[in] server
 *     已校验非空的存活资源根，只调用期借用。
 * @param[in] client
 *     调用者传入的数值租约，不凭槽号或 fd 猜身份。
 * @param[out] connection
 *     独立内部短借用输出，仅本次操作使用，不成为第二 owner。
 * @param[in,out] detail
 *     已类型初始化的独立操作诊断，失败标记 LOOKUP。
 *
 * @retval VIREO_OK
 *     public pool 验证及本层当前 slot 核对成功，借用存活客户。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空槽/旧代际；其他 public lookup 或本层不变量分类原样返回。
 *
 * @note 本辅助函数不做 I/O/清理，caller 恢复入口 errno；借用不能跨越归还。
 */
static vireo_result_t lookup_for_io(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_connection_t **connection,
    vireo_tcp_server_client_error_t *detail)
{
    vireo_result_t const result = find_client(server, client, connection);
    if (result != VIREO_OK) detail->primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
    return result;
}

vireo_result_t vireo_tcp_server_client_receive(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_receive_budget_t const *budget,
    vireo_connection_receive_info_t *out_info, vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || budget == NULL || out_info == NULL)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active) return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    if (budget->max_bytes == 0 || budget->max_syscalls == 0)
        return client_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = lookup_for_io(server, client, &connection, &detail);
    if (result != VIREO_OK) return client_finish(result, &detail, error, saved_errno);
    result = server->client_ops.receive(server->client_ops.context, connection, budget,
                                       out_info, &detail.primary.connection_error);
    if (result != VIREO_OK) detail.primary.stage = VIREO_TCP_SERVER_CLIENT_RECEIVE;
    return client_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_client_read_peek(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint8_t const **out_data, size_t *out_size,
    vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || out_data == NULL || out_size == NULL)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = lookup_for_io(server, client, &connection, &detail);
    if (result != VIREO_OK) return client_finish(result, &detail, error, saved_errno);
    uint8_t const *data = NULL;
    size_t size = 0;
    result = server->client_ops.read_peek(server->client_ops.context, connection, &data, &size);
    if (result == VIREO_OK) { *out_data = data; *out_size = size; }
    else detail.primary.stage = VIREO_TCP_SERVER_CLIENT_READ_PEEK;
    return client_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_client_read_consume(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, size_t size, vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL) return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active) return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = lookup_for_io(server, client, &connection, &detail);
    if (result != VIREO_OK) return client_finish(result, &detail, error, saved_errno);
    result = server->client_ops.read_consume(server->client_ops.context, connection, size);
    if (result != VIREO_OK) detail.primary.stage = VIREO_TCP_SERVER_CLIENT_READ_CONSUME;
    return client_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_client_write_enqueue(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint8_t const *bytes, size_t size,
    vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || (size != 0 && bytes == NULL))
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active) return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = lookup_for_io(server, client, &connection, &detail);
    if (result != VIREO_OK) return client_finish(result, &detail, error, saved_errno);
    result = server->client_ops.write_enqueue(server->client_ops.context, connection, bytes,
                                              size, &detail.primary.connection_error);
    if (result != VIREO_OK) detail.primary.stage = VIREO_TCP_SERVER_CLIENT_WRITE_ENQUEUE;
    return client_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_client_send(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_send_budget_t const *budget,
    vireo_connection_send_info_t *out_info, vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || budget == NULL || out_info == NULL)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active) return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    if (budget->max_bytes == 0 || budget->max_syscalls == 0)
        return client_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = lookup_for_io(server, client, &connection, &detail);
    if (result != VIREO_OK) return client_finish(result, &detail, error, saved_errno);
    result = server->client_ops.send(server->client_ops.context, connection, budget,
                                    out_info, &detail.primary.connection_error);
    if (result != VIREO_OK) detail.primary.stage = VIREO_TCP_SERVER_CLIENT_SEND;
    return client_finish(result, &detail, error, saved_errno);
}

/* 与读容量无关的参数先拒绝；容量/flow 上限仍由公开 framing 核对。
 * views/info 直接交依赖，才能保留解析错误前已验证的批次；不把失败等同零输出。 */
vireo_result_t vireo_tcp_server_client_frames_peek(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_connection_frame_options_t const *options,
    vireo_connection_frame_budget_t const *budget, vireo_connection_frame_view_t *views,
    size_t view_capacity, vireo_connection_frame_info_t *out_info,
    vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || options == NULL || budget == NULL || views == NULL || out_info == NULL ||
        (options->direction != VIREO_CONNECTION_FRAME_REQUEST &&
         options->direction != VIREO_CONNECTION_FRAME_RESPONSE))
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    size_t const header_size = (size_t)VIREO_PROTOCOL_HEADER_SIZE;
    if (view_capacity == 0 || budget->max_messages == 0 || budget->max_bytes == 0 ||
        options->max_frame_bytes < header_size || budget->max_bytes < options->max_frame_bytes ||
        options->max_frame_bytes - header_size > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE)
        return client_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = lookup_for_io(server, client, &connection, &detail);
    if (result != VIREO_OK) return client_finish(result, &detail, error, saved_errno);
    result = server->client_ops.frames_peek(server->client_ops.context, connection,
        options, budget, views, view_capacity, out_info, &detail.primary.frame_error);
    if (result != VIREO_OK) detail.primary.stage = VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK;
    return client_finish(result, &detail, error, saved_errno);
}

/**
 * @brief 将 handler 描述和已写 body 编码到 caller 工作区，输出完整 wire 长度
 *
 * @param[in] request
 *     已验证请求，只取按值 header 的关联字段。
 * @param[in] reply
 *     回调按值描述；body_size 须在给定上限内。
 * @param[in,out] wire
 *     独立 caller 区，body 已写在偏移 32，头允许被覆盖。
 * @param[in] limit
 *     已验证的最大响应 wire 字节数，至少 32。
 * @param[out] out_size
 *     独立局部输出，只在全部编码成功后提交。
 * @param[in,out] detail
 *     独立类型初始化诊断，失败保存 RESPONSE 及 codec 原因。
 *
 * @return
 *     公共 codec/checked 原分类，描述超界 RANGE。
 *
 * @note 无分配/系统调用，不保存借用；caller 恢复 errno。编码两次是为了先计算 CRC。
 */
static vireo_result_t encode_reply(vireo_connection_frame_view_t const *request,
    vireo_tcp_server_reply_t const *reply, uint8_t *wire, size_t limit, size_t *out_size,
    vireo_tcp_server_client_error_t *detail)
{
    detail->primary.stage = VIREO_TCP_SERVER_CLIENT_RESPONSE;
    size_t const head = (size_t)VIREO_PROTOCOL_HEADER_SIZE;
    if (reply->body_size > limit - head) return VIREO_RESULT_RANGE;
    size_t size = 0;
    vireo_result_t result = vireo_checked_size_add(head, reply->body_size, &size);
    if (result != VIREO_OK) return result;
    /* limit 的协议上限已证明，窄化 body_size 到 wire u32 可表示。 */
    vireo_protocol_header_t header = {
        .command = request->header.command, .flags = VIREO_PROTOCOL_FLAG_RESPONSE,
        .status = reply->status, .body_len = (uint32_t)reply->body_size,
        .sequence = request->header.sequence, .session_handle = reply->session_handle,
        .task_handle = reply->task_handle, .crc32c = 0
    };
    result = vireo_protocol_response_header_validate(&header, &detail->primary.response_codec_issue);
    if (result == VIREO_OK) result = vireo_protocol_header_encode(&header, wire, head);
    if (result == VIREO_OK)
        result = vireo_protocol_frame_crc32c_calculate(wire, head,
            reply->body_size == 0 ? NULL : wire + head, reply->body_size, &header.crc32c);
    if (result == VIREO_OK) result = vireo_protocol_header_encode(&header, wire, head);
    if (result == VIREO_OK) {
        *out_size = size;
        detail->primary.stage = VIREO_TCP_SERVER_CLIENT_NONE;
    }
    return result;
}

/**
 * @brief 共用原 REQUEST/SINGLE 处理核心，保持排队后消费与真实进度
 *
 * @param[in,out] server
 *     独立处理或本文件 driver 使用的存活资源根。
 * @param[in] client
 *     当前存储租约，公开 lookup 验证后才短借连接。
 * @param[in] options
 *     两整帧上限，入口复制，不改变固定容量。
 * @param[in] budget
 *     原三项显式处理预算，入口复制。
 * @param[in,out] wire_workspace
 *     独立固定响应工作区，仅借用至返回。
 * @param[in] workspace_capacity
 *     至少配置最大响应，不新增申请。
 * @param[in] handler
 *     有界正常返回的同步回调，不保留请求借用。
 * @param[in,out] context
 *     可空短期 caller context，不存入 server。
 * @param[out] out_info
 *     前置拒绝保持，执行后报告真实进度。
 * @param[out] error
 *     可空完整原 client 诊断。
 * @param[in] from_drive
 *     仅本文件 driver 传 true，越过自身 driving 标记，仍拒绝处理递归。
 *
 * @return
 *     原处理分类与失败合同，不隐式同步关注或清理资源。
 *
 * @note 恢复入口 errno；公共 wrapper 固定 false，不开放绕过在途保护的能力。
 *     不能先消费再排响应，也不能把两步伪装成可回滚事务。
 */
static vireo_result_t process_client(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_process_budget_t const *budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_process_info_t *out_info, vireo_tcp_server_client_error_t *error,
    bool from_drive)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || options == NULL || budget == NULL || wire_workspace == NULL ||
        handler == NULL || out_info == NULL)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || (server->driving_active && !from_drive) ||
        (server->scheduling_active && !from_drive) || (server->serving_active && !from_drive))
        return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_tcp_server_process_options_t const limits = *options;
    vireo_tcp_server_process_budget_t const allowance = *budget;
    size_t const head = (size_t)VIREO_PROTOCOL_HEADER_SIZE;
    if (limits.max_request_frame_bytes < head || limits.max_response_frame_bytes < head ||
        limits.max_request_frame_bytes - head > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE ||
        limits.max_response_frame_bytes - head > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE ||
        workspace_capacity < limits.max_response_frame_bytes || allowance.max_messages == 0 ||
        allowance.max_request_bytes < limits.max_request_frame_bytes ||
        allowance.max_response_bytes < limits.max_response_frame_bytes)
        return client_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = lookup_for_io(server, client, &connection, &detail);
    if (result != VIREO_OK) return client_finish(result, &detail, error, saved_errno);
    vireo_connection_info_t current = {0};
    result = server->client_ops.inspect(server->client_ops.context, connection, &current);
    if (result != VIREO_OK) {
        detail.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT;
        return client_finish(result, &detail, error, saved_errno);
    }
    if (limits.max_request_frame_bytes > current.read_buffer.capacity ||
        limits.max_response_frame_bytes > current.write_buffer.capacity)
        return client_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    if (current.close_state != VIREO_CONNECTION_CLOSE_OPEN)
        return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    if (current.flow_enabled && limits.max_request_frame_bytes > current.flow_options.max_frame_bytes)
        return client_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    vireo_connection_frame_options_t const framing = {
        VIREO_CONNECTION_FRAME_REQUEST, limits.max_request_frame_bytes
    };
    vireo_connection_frame_budget_t const one = {1, limits.max_request_frame_bytes};
    vireo_tcp_server_process_info_t progress = {0};
    server->processing_active = true;
    for (;;) {
        if (progress.handler_calls == allowance.max_messages) {
            progress.stop_reason = VIREO_TCP_SERVER_PROCESS_MESSAGE_BUDGET; break;
        }
        if (allowance.max_request_bytes - progress.consumed_request_bytes < limits.max_request_frame_bytes) {
            progress.stop_reason = VIREO_TCP_SERVER_PROCESS_REQUEST_BUDGET; break;
        }
        if (allowance.max_response_bytes - progress.enqueued_response_bytes < limits.max_response_frame_bytes) {
            progress.stop_reason = VIREO_TCP_SERVER_PROCESS_RESPONSE_BUDGET; break;
        }
        vireo_connection_frame_view_t request = {0};
        vireo_connection_frame_info_t parsed = {0};
        result = server->client_ops.frames_peek(server->client_ops.context, connection,
            &framing, &one, &request, 1, &parsed, &detail.primary.frame_error);
        if (result != VIREO_OK) { detail.primary.stage = VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK; break; }
        if (parsed.frame_count == 0) {
            if (parsed.stop_reason == VIREO_CONNECTION_FRAME_STOP_NEED_MORE)
                progress.stop_reason = VIREO_TCP_SERVER_PROCESS_NEED_MORE;
            else if (parsed.stop_reason == VIREO_CONNECTION_FRAME_STOP_EOF)
                progress.stop_reason = VIREO_TCP_SERVER_PROCESS_EOF;
            else { result = VIREO_RESULT_INTERNAL; detail.primary.stage = VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK; }
            break;
        }
        if (parsed.frame_count != 1 || request.wire_size < head ||
            request.wire_size > limits.max_request_frame_bytes ||
            request.body_size != request.wire_size - head ||
            request.header.body_len != request.body_size || parsed.frame_bytes != request.wire_size ||
            (request.body_size != 0 && request.body == NULL)) {
            result = VIREO_RESULT_INTERNAL; detail.primary.stage = VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK; break;
        }
        result = server->client_ops.inspect(server->client_ops.context, connection, &current);
        if (result != VIREO_OK) { detail.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT; break; }
        if (current.write_buffer.readable_size > current.write_buffer.capacity ||
            current.write_buffer.capacity < limits.max_response_frame_bytes) {
            result = VIREO_RESULT_INTERNAL; detail.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT; break;
        }
        if (current.write_buffer.capacity - current.write_buffer.readable_size < limits.max_response_frame_bytes) {
            progress.stop_reason = VIREO_TCP_SERVER_PROCESS_WRITE_FULL; break;
        }
        vireo_tcp_server_reply_t reply = {
            .status = VIREO_STATUS_OK, .body_size = 0,
            .session_handle = request.header.session_handle, .task_handle = request.header.task_handle
        };
        ++progress.handler_calls; /* 每次进入前证明 < max_messages，失败也计数。 */
        result = handler(&request, wire_workspace + head, limits.max_response_frame_bytes - head,
                         &reply, context);
        if (result != VIREO_OK) {
            detail.primary.stage = VIREO_TCP_SERVER_CLIENT_HANDLER;
            detail.primary.handler_result = result;
            if ((unsigned)result > (unsigned)VIREO_RESULT_INTERNAL) result = VIREO_RESULT_INTERNAL;
            break;
        }
        size_t response_size = 0;
        result = encode_reply(&request, &reply, wire_workspace, limits.max_response_frame_bytes,
                              &response_size, &detail);
        if (result != VIREO_OK) break;
        result = server->client_ops.write_enqueue(server->client_ops.context, connection,
            wire_workspace, response_size, &detail.primary.connection_error);
        if (result != VIREO_OK) { detail.primary.stage = VIREO_TCP_SERVER_CLIENT_WRITE_ENQUEUE; break; }
        ++progress.enqueued_responses;
        progress.enqueued_response_bytes += response_size; /* 最大帧预留证明不超过剩额。 */
        result = server->client_ops.read_consume(server->client_ops.context, connection, request.wire_size);
        if (result != VIREO_OK) { detail.primary.stage = VIREO_TCP_SERVER_CLIENT_READ_CONSUME; break; }
        ++progress.consumed_requests;
        progress.consumed_request_bytes += request.wire_size;
        /* consume 后旧 body 借用结束，下一轮必须重新公开 peek。 */
    }
    if (result != VIREO_OK) progress.stop_reason = VIREO_TCP_SERVER_PROCESS_ERROR;
    server->processing_active = false;
    *out_info = progress;
    return client_finish(result, &detail, error, saved_errno);
}


/* 公共独立处理保留原无隐式 MOD 合同；共用核心只给本文件有限 driver 使用。 */
vireo_result_t vireo_tcp_server_client_process(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_process_budget_t const *budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_process_info_t *out_info, vireo_tcp_server_client_error_t *error)
{
    return process_client(server, client, options, budget, wire_workspace, workspace_capacity,
                          handler, context, out_info, error, false);
}

/**
 * @brief 为六个公开策略入口执行共同身份与在途保护
 *
 * @param[in,out] server
 *     非空存活资源根，仅本调用借用。
 * @param[in] client
 *     当前数值租约，不凭 fd 或槽地址猜身份。
 * @param[in] stage
 *     六个本层策略阶段之一，决定单次公开依赖调用。
 * @param[in] interests
 *     仅手动关注阶段读取。
 * @param[in] options
 *     仅配置阶段读取的短期独立借用，必需非空。
 * @param[in] mode
 *     仅关闭请求阶段读取。
 * @param[in] reason
 *     仅关闭请求阶段读取，首次理由由依赖保存。
 * @param[out] error
 *     可空独立诊断，完整提交并恢复入口 errno。
 *
 * @return
 *     公开依赖原分类；本层前置拒绝不触及客户策略。
 *
 * @note 不做第二份状态机/资源清理；关闭依赖失败仍可能提交永久意图。
 */
static vireo_result_t client_policy(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_stage_t stage,
    uint32_t interests, vireo_connection_flow_options_t const *options,
    vireo_connection_close_mode_t mode, vireo_connection_close_reason_t reason,
    vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL || (stage == VIREO_TCP_SERVER_CLIENT_FLOW_CONFIGURE && options == NULL))
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active)
        return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = lookup_for_io(server, client, &connection, &detail);
    if (result != VIREO_OK) return client_finish(result, &detail, error, saved_errno);
    vireo_tcp_server_client_ops_t const *o = &server->client_ops;
    switch (stage) {
    case VIREO_TCP_SERVER_CLIENT_SET_INTERESTS:
        result = o->set_interests(o->context, connection, interests, &detail.primary.loop_error);
        break;
    case VIREO_TCP_SERVER_CLIENT_FLOW_CONFIGURE:
        result = o->flow_configure(o->context, connection, options, &detail.primary.loop_error);
        break;
    case VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH:
        result = o->flow_refresh(o->context, connection, &detail.primary.loop_error);
        break;
    case VIREO_TCP_SERVER_CLIENT_FLOW_DISABLE:
        result = o->flow_disable(o->context, connection, &detail.primary.loop_error);
        break;
    case VIREO_TCP_SERVER_CLIENT_REQUEST_CLOSE:
        result = o->request_close(o->context, connection, mode, reason, &detail.primary.loop_error);
        break;
    case VIREO_TCP_SERVER_CLIENT_CLOSE_REFRESH:
        result = o->close_refresh(o->context, connection, &detail.primary.loop_error);
        break;
    default:
        result = VIREO_RESULT_INTERNAL;
        break;
    }
    if (result != VIREO_OK) detail.primary.stage = stage;
    return client_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_client_set_interests(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint32_t interests, vireo_tcp_server_client_error_t *error)
{
    return client_policy(server, client, VIREO_TCP_SERVER_CLIENT_SET_INTERESTS,
        interests, NULL, VIREO_CONNECTION_CLOSE_MODE_DRAIN, VIREO_CONNECTION_CLOSE_REASON_NONE, error);
}

vireo_result_t vireo_tcp_server_client_flow_configure(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_flow_options_t const *options,
    vireo_tcp_server_client_error_t *error)
{
    return client_policy(server, client, VIREO_TCP_SERVER_CLIENT_FLOW_CONFIGURE,
        0, options, VIREO_CONNECTION_CLOSE_MODE_DRAIN, VIREO_CONNECTION_CLOSE_REASON_NONE, error);
}

vireo_result_t vireo_tcp_server_client_flow_refresh(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error)
{
    return client_policy(server, client, VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH,
        0, NULL, VIREO_CONNECTION_CLOSE_MODE_DRAIN, VIREO_CONNECTION_CLOSE_REASON_NONE, error);
}

vireo_result_t vireo_tcp_server_client_flow_disable(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error)
{
    return client_policy(server, client, VIREO_TCP_SERVER_CLIENT_FLOW_DISABLE,
        0, NULL, VIREO_CONNECTION_CLOSE_MODE_DRAIN, VIREO_CONNECTION_CLOSE_REASON_NONE, error);
}

vireo_result_t vireo_tcp_server_client_request_close(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_tcp_server_client_error_t *error)
{
    return client_policy(server, client, VIREO_TCP_SERVER_CLIENT_REQUEST_CLOSE,
        0, NULL, mode, reason, error);
}

vireo_result_t vireo_tcp_server_client_close_refresh(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error)
{
    return client_policy(server, client, VIREO_TCP_SERVER_CLIENT_CLOSE_REFRESH,
        0, NULL, VIREO_CONNECTION_CLOSE_MODE_DRAIN, VIREO_CONNECTION_CLOSE_REASON_NONE, error);
}


/**
 * @brief 提交组合诊断并恢复入口 errno
 *
 * @param[in] result
 *     首分类，不被独立补同步次错覆盖。
 * @param[in] detail
 *     完整独立诊断，仅借用到返回。
 * @param[out] error
 *     可空 caller 输出，非空时按值完整复制。
 * @param[in] saved_errno
 *     最外层入口值，不代表底层系统原原因。
 *
 * @return
 *     result 原值，不处理资源 owner。
 *
 * @note 不申请资源，不自动重试。
 */
static vireo_result_t drive_finish(vireo_result_t result,
    vireo_tcp_server_drive_error_t const *detail, vireo_tcp_server_drive_error_t *error,
    int saved_errno)
{
    if (error != NULL) *error = *detail;
    errno = saved_errno;
    return result;
}

/**
 * @brief 按已确认模式同步一次关注
 *
 * @param[in,out] server
 *     driver 已建立在途保护的存活资源根。
 * @param[in,out] connection
 *     经公开 lookup 取得的当前短借用，只调用公开策略。
 * @param[in] closing
 *     true 选择 close_refresh，否则 flow_refresh，不自行转换意图。
 * @param[out] detail
 *     独立原 client 诊断，本次覆盖全部语义成员。
 *
 * @return
 *     依赖原分类与完整原因，不重试、不发送字节。
 *
 * @note 同步不是资源清理；最外层统一恢复 errno。
 */
static vireo_result_t drive_sync(vireo_tcp_server_t *server, vireo_connection_t *connection,
    bool closing, vireo_tcp_server_client_error_t *detail)
{
    *detail = (vireo_tcp_server_client_error_t){0};
    vireo_result_t const result = closing
        ? server->client_ops.close_refresh(server->client_ops.context, connection,
                                           &detail->primary.loop_error)
        : server->client_ops.flow_refresh(server->client_ops.context, connection,
                                          &detail->primary.loop_error);
    if (result != VIREO_OK)
        detail->primary.stage = closing ? VIREO_TCP_SERVER_CLIENT_CLOSE_REFRESH
                                        : VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH;
    return result;
}

/* 公共前置与执行分开：只有全部配置/身份/容量通过后才发布执行统计。
 * final sync 是反映实际部分进度的一次操作，不能覆写主因或自动重放业务。 */
/** 已复制的共同数值与工作区校验；真实客户容量仍只在其 turn 检查。 */
static bool drive_arguments_valid(vireo_tcp_server_process_options_t limits,
    vireo_tcp_server_drive_budget_t allowance, size_t workspace_capacity)
{
    size_t const head = (size_t)VIREO_PROTOCOL_HEADER_SIZE;
    return !(limits.max_request_frame_bytes < head || limits.max_response_frame_bytes < head ||
        limits.max_request_frame_bytes - head > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE ||
        limits.max_response_frame_bytes - head > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE ||
        workspace_capacity < limits.max_response_frame_bytes ||
        allowance.receive.max_bytes == 0 || allowance.receive.max_syscalls == 0 ||
        allowance.send.max_bytes == 0 || allowance.send.max_syscalls == 0 ||
        allowance.process.max_messages == 0 ||
        allowance.process.max_request_bytes < limits.max_request_frame_bytes ||
        allowance.process.max_response_bytes < limits.max_response_frame_bytes);
}

/**
 * @brief 共用单客户驱动，只允许本层调度器在自身在途范围内调用
 *
 * @param[in,out] server
 *     存活 server，驱动和处理标记沿原公开范围。
 * @param[in] client
 *     当前租约。
 * @param[in] options
 *     原帧配置。
 * @param[in] budget
 *     原三阶段预算。
 * @param[in,out] wire_workspace
 *     本次独立响应工作区。
 * @param[in] workspace_capacity
 *     工作区字节数。
 * @param[in] handler
 *     原同步有界回调。
 * @param[in,out] context
 *     回调借用 context。
 * @param[out] out_info
 *     原真实进度。
 * @param[out] error
 *     原主/补同步诊断。
 * @param[in] from_scheduler
 *     仅内部调度为 true，公开单客户入口固定 false。
 *
 * @return
 *     原公开 drive 分类、进度与失败后置。
 *
 * @note 本辅助不新增队列副作用；保护不能被公开调用者绕过，保持 errno。
 */
static vireo_result_t drive_client(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_drive_budget_t const *budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_drive_info_t *out_info, vireo_tcp_server_drive_error_t *error,
    bool from_scheduler)
{
    int const saved_errno = errno;
    vireo_tcp_server_drive_error_t detail = {0};
    if (server == NULL || options == NULL || budget == NULL || wire_workspace == NULL ||
        handler == NULL || out_info == NULL)
        return drive_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->owned_tls_context != NULL || server->closing_active || server->shutdown_active || server->processing_active || server->driving_active ||
        (server->scheduling_active && !from_scheduler) || (server->serving_active && !from_scheduler))
        return drive_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_tcp_server_process_options_t const limits = *options;
    vireo_tcp_server_drive_budget_t const allowance = *budget;
    if (!drive_arguments_valid(limits, allowance, workspace_capacity))
        return drive_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = lookup_for_io(server, client, &connection, &detail.primary_error);
    if (result != VIREO_OK) {
        detail.primary_stage = VIREO_TCP_SERVER_DRIVE_LOOKUP;
        return drive_finish(result, &detail, error, saved_errno);
    }
    vireo_connection_info_t current = {0};
    result = server->client_ops.inspect(server->client_ops.context, connection, &current);
    if (result != VIREO_OK) {
        detail.primary_stage = VIREO_TCP_SERVER_DRIVE_INSPECT;
        detail.primary_error.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT;
        return drive_finish(result, &detail, error, saved_errno);
    }
    if (limits.max_request_frame_bytes > current.read_buffer.capacity ||
        limits.max_response_frame_bytes > current.write_buffer.capacity)
        return drive_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    if (current.close_state != VIREO_CONNECTION_CLOSE_OPEN &&
        current.close_state != VIREO_CONNECTION_CLOSE_DRAINING &&
        current.close_state != VIREO_CONNECTION_CLOSE_READY)
        return drive_finish(VIREO_RESULT_INTERNAL, &detail, error, saved_errno);
    bool const closing = current.close_state != VIREO_CONNECTION_CLOSE_OPEN;
    if (!closing && (!current.loop_attached || !current.flow_enabled))
        return drive_finish(VIREO_RESULT_NOT_FOUND, &detail, error, saved_errno);
    if (!closing && limits.max_request_frame_bytes > current.flow_options.max_frame_bytes)
        return drive_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);

    vireo_tcp_server_drive_info_t progress = {0};
    vireo_tcp_server_client_error_t cause = {0};
    server->driving_active = true;
    if (!closing) {
        result = drive_sync(server, connection, false, &cause);
        if (result != VIREO_OK) {
            detail.primary_stage = VIREO_TCP_SERVER_DRIVE_PRE_SYNC;
            detail.primary_error = cause;
            goto done; /* 不因初次 MOD 失败而在出口偷偷重试。 */
        }
        result = server->client_ops.inspect(server->client_ops.context, connection, &current);
        if (result != VIREO_OK) {
            detail.primary_stage = VIREO_TCP_SERVER_DRIVE_INSPECT;
            detail.primary_error.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT;
            goto done;
        }
        if (!current.read_eof && !current.read_pressure && !current.write_pressure) {
            progress.receive_called = true;
            result = server->client_ops.receive(server->client_ops.context, connection,
                &allowance.receive, &progress.receive, &cause.primary.connection_error);
            if (result != VIREO_OK) {
                cause.primary.stage = VIREO_TCP_SERVER_CLIENT_RECEIVE;
                detail.primary_stage = VIREO_TCP_SERVER_DRIVE_RECEIVE;
                detail.primary_error = cause;
            }
        }
        if (result == VIREO_OK) {
            progress.process_called = true;
            result = process_client(server, client, &limits, &allowance.process, wire_workspace,
                workspace_capacity, handler, context, &progress.process, &cause, true);
            if (result != VIREO_OK) {
                detail.primary_stage = VIREO_TCP_SERVER_DRIVE_PROCESS;
                detail.primary_error = cause;
            }
        }
    }
    if (result == VIREO_OK && current.close_state != VIREO_CONNECTION_CLOSE_READY) {
        cause = (vireo_tcp_server_client_error_t){0};
        progress.send_called = true;
        result = server->client_ops.send(server->client_ops.context, connection, &allowance.send,
                                         &progress.send, &cause.primary.connection_error);
        if (result != VIREO_OK) {
            cause.primary.stage = VIREO_TCP_SERVER_CLIENT_SEND;
            detail.primary_stage = VIREO_TCP_SERVER_DRIVE_SEND;
            detail.primary_error = cause;
        }
    }
    {
        vireo_result_t const synced = drive_sync(server, connection, closing, &cause);
        if (synced != VIREO_OK) {
            if (result == VIREO_OK) {
                result = synced;
                detail.primary_stage = VIREO_TCP_SERVER_DRIVE_FINAL_SYNC;
                detail.primary_error = cause;
            } else {
                detail.sync_result = synced;
                detail.sync_error = cause;
            }
        }
    }
    if (result == VIREO_OK) {
        result = server->client_ops.inspect(server->client_ops.context, connection, &current);
        if (result != VIREO_OK || current.write_buffer.readable_size > current.write_buffer.capacity ||
            current.read_buffer.readable_size > current.read_buffer.capacity) {
            if (result == VIREO_OK) result = VIREO_RESULT_INTERNAL;
            detail.primary_stage = VIREO_TCP_SERVER_DRIVE_INSPECT;
            detail.primary_error.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT;
        } else {
            progress.ready_to_release = current.close_state == VIREO_CONNECTION_CLOSE_READY;
            vireo_tcp_server_process_stop_t const stop = progress.process.stop_reason;
            bool const limited = stop == VIREO_TCP_SERVER_PROCESS_MESSAGE_BUDGET ||
                stop == VIREO_TCP_SERVER_PROCESS_REQUEST_BUDGET ||
                stop == VIREO_TCP_SERVER_PROCESS_RESPONSE_BUDGET ||
                stop == VIREO_TCP_SERVER_PROCESS_WRITE_FULL;
            progress.needs_processing = !closing && progress.process_called && limited &&
                current.read_buffer.readable_size != 0 &&
                current.write_buffer.capacity - current.write_buffer.readable_size >=
                    limits.max_response_frame_bytes;
        }
    }
done:
    server->driving_active = false;
    *out_info = progress;
    return drive_finish(result, &detail, error, saved_errno);
}


vireo_result_t vireo_tcp_server_client_drive(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_drive_budget_t const *budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_drive_info_t *out_info, vireo_tcp_server_drive_error_t *error)
{
    return drive_client(server, client, options, budget, wire_workspace, workspace_capacity,
        handler, context, out_info, error, false);
}

vireo_result_t vireo_tcp_server_schedule_client(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL) return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active)
        return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_connection_t *connection = NULL;
    vireo_result_t result = find_client(server, client, &connection);
    if (result != VIREO_OK) detail.primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
    else result = queue_append(server, client.slot_index);
    return client_finish(result, &detail, error, saved_errno);
}

/**
 * @brief 提交独立调度诊断并恢复入口 errno
 *
 * @param[in] result
 *     返回分类，不按诊断改写。
 * @param[in] detail
 *     非空局部按值诊断，调用期借用。
 * @param[out] error
 *     可空独立调用者输出，仅复制语义成员。
 * @param[in] saved_errno
 *     最外层入口保存值。
 *
 * @return
 *     result 原值；不提交主要统计或取得资源。
 *
 * @note 输出保持责任在调用点，所有出口统一 errno。
 */
static vireo_result_t round_finish(vireo_result_t result,
    vireo_tcp_server_round_error_t const *detail, vireo_tcp_server_round_error_t *error,
    int saved_errno)
{
    if (error != NULL) *error = *detail;
    errno = saved_errno;
    return result;
}

/**
 * @brief 服务turn安全点按真实错误来源或EOF空缓存选择一次关闭
 *
 * @param[in,out] server
 *     scheduling_active已发布，loop/driver/handler均已返回；不撤外部在途保护。
 * @param[in,out] turn
 *     当前owned客户原drive按值结果，仅写独立close字段。
 * @param[out] ready_next
 *     局部false初值；成功EOF新READY时true，由round安排一次下轮。
 *
 * @note 只依赖公开lookup/inspect/request_close，既有关闭原因由connection永久保持。
 *     不修改drive hint，不DEL/释放/重试，最外层恢复入口errno。
 */
static void apply_close_policy(vireo_tcp_server_t *server,
    vireo_tcp_server_turn_result_t *turn, bool *ready_next)
{
    turn->close_checked = true;
    vireo_tcp_server_client_cause_t const *origin = &turn->error.primary_error.primary;
    bool const protocol = turn->result == VIREO_RESULT_PROTOCOL &&
        turn->error.primary_stage == VIREO_TCP_SERVER_DRIVE_PROCESS &&
        origin->stage == VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK;
    bool const receive = turn->error.primary_stage == VIREO_TCP_SERVER_DRIVE_RECEIVE &&
        origin->stage == VIREO_TCP_SERVER_CLIENT_RECEIVE &&
        origin->connection_error.stage == VIREO_CONNECTION_STAGE_RECEIVE;
    bool const send = turn->error.primary_stage == VIREO_TCP_SERVER_DRIVE_SEND &&
        origin->stage == VIREO_TCP_SERVER_CLIENT_SEND &&
        origin->connection_error.stage == VIREO_CONNECTION_STAGE_SEND;
    bool const socket_io = turn->result == VIREO_RESULT_IO && (receive || send) &&
        origin->connection_error.system_errno > 0 && origin->connection_error.system_errno != EINTR;
    if (turn->result != VIREO_OK && !protocol && !socket_io) return;
    if (turn->result == VIREO_OK && turn->info.ready_to_release) return;

    vireo_connection_t *connection = NULL;
    turn->close_result = find_client(server, turn->client, &connection);
    if (turn->close_result != VIREO_OK) {
        turn->close_error.primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
        return;
    }
    vireo_connection_info_t current = {0};
    turn->close_result = server->client_ops.inspect(server->client_ops.context, connection, &current);
    if (turn->close_result != VIREO_OK) {
        turn->close_error.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT;
        return;
    }
    if (current.read_buffer.readable_size > current.read_buffer.capacity ||
        current.write_buffer.readable_size > current.write_buffer.capacity ||
        (current.close_state != VIREO_CONNECTION_CLOSE_OPEN &&
         current.close_state != VIREO_CONNECTION_CLOSE_DRAINING &&
         current.close_state != VIREO_CONNECTION_CLOSE_READY)) {
        turn->close_result = VIREO_RESULT_INTERNAL;
        turn->close_error.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT;
        return;
    }
    if (current.close_state == VIREO_CONNECTION_CLOSE_READY ||
        (current.close_state != VIREO_CONNECTION_CLOSE_OPEN && !socket_io)) return;
    vireo_connection_close_mode_t mode = VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE;
    vireo_connection_close_reason_t reason = protocol ? VIREO_CONNECTION_CLOSE_REASON_PROTOCOL :
        VIREO_CONNECTION_CLOSE_REASON_IO;
    if (turn->result == VIREO_OK) {
        if (current.close_state != VIREO_CONNECTION_CLOSE_OPEN || !current.read_eof ||
            current.read_buffer.readable_size != 0) return;
        mode = VIREO_CONNECTION_CLOSE_MODE_DRAIN;
        reason = VIREO_CONNECTION_CLOSE_REASON_PEER_EOF;
    }
    turn->close_attempted = true;
    turn->close_result = server->client_ops.request_close(server->client_ops.context, connection,
        mode, reason, &turn->close_error.primary.loop_error);
    if (turn->close_result != VIREO_OK) {
        turn->close_error.primary.stage = VIREO_TCP_SERVER_CLIENT_REQUEST_CLOSE;
        return;
    }
    /* 公开DRAIN合同：request_close不改字节，入口待发为空时成功必为READY。 */
    *ready_next = turn->result == VIREO_OK && current.write_buffer.readable_size == 0;
}

/**
 * @brief 复用一次等待与 FIFO 客户轮次，不执行自动准入
 *
 * @param[in,out] server
 *     存活资源根，整轮保持 scheduling_active。
 * @param[in] timeout_ms
 *     -1/0/正毫秒；已有待办时实际使用 0。
 * @param[in] options
 *     调用期借用的原共同帧上限。
 * @param[in] drive_budget
 *     每个客户各自使用的三阶段预算。
 * @param[in] round_budget
 *     本轮客户数量上限，1..65535。
 * @param[in,out] wire_workspace
 *     独立固定响应工作区，不保存地址。
 * @param[in] workspace_capacity
 *     工作区字节容量，至少容纳最大响应整帧。
 * @param[in] handler
 *     原有界同步 handler，须正常返回。
 * @param[in,out] context
 *     可空 caller context，仅本轮借用。
 * @param[out] out_turns
 *     仅写真实客户 turn 前缀，含首个失败客户。
 * @param[in] turn_capacity
 *     结果容量，1..65535。
 * @param[out] out_info
 *     前置/等待拒绝保持；等待成功后提交真实进度。
 * @param[out] error
 *     可空独立原 round/wait/drive 诊断。
 * @param[in] from_serve
 *     仅组合服务传 true，越过自身 serving 标记。
 *
 * @return
 *     原 FIFO 单轮分类；首客户错误停止，其余待办保留。
 *
 * @note 公共 wrapper 固定 false；每客户本轮至多一次，不分配、不重试，恢复入口 errno。
 */
static vireo_result_t run_round(vireo_tcp_server_t *server, int timeout_ms,
    vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_drive_budget_t const *drive_budget,
    vireo_tcp_server_round_budget_t const *round_budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_tcp_server_round_info_t *out_info, vireo_tcp_server_round_error_t *error, bool from_serve)
{
    int const saved_errno = errno;
    vireo_tcp_server_round_error_t detail = {0};
    if (server == NULL || options == NULL || drive_budget == NULL || round_budget == NULL ||
        wire_workspace == NULL || handler == NULL || out_turns == NULL || out_info == NULL || timeout_ms < -1)
        return round_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->owned_tls_context != NULL || server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || ((server->serving_active || server->running_active) && !from_serve))
        return round_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    vireo_tcp_server_process_options_t const limits = *options;
    vireo_tcp_server_drive_budget_t const per_client = *drive_budget;
    size_t const client_limit = round_budget->max_clients;
    if (client_limit == 0 || client_limit > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        turn_capacity == 0 || turn_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        !drive_arguments_valid(limits, per_client, workspace_capacity))
        return round_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    if (!queue_valid(server)) {
        detail.stage = VIREO_TCP_SERVER_ROUND_QUEUE;
        return round_finish(VIREO_RESULT_INTERNAL, &detail, error, saved_errno);
    }
    if (!from_serve) {
        bool stopped = false;
        vireo_result_t const observed = stop_snapshot(server, &stopped);
        if (observed != VIREO_OK) return round_finish(observed, &detail, error, saved_errno);
        if (stopped) {
            *out_info = (vireo_tcp_server_round_info_t){0};
            return round_finish(VIREO_OK, &detail, error, saved_errno);
        }
    }
    bool const auto_release_ready = server->auto_release_ready;
    bool const auto_close_policy = server->auto_close_policy;
    vireo_tcp_server_round_info_t progress = {.queued_before_wait = server->queue_count,
        .effective_timeout_ms = server->queue_count != 0 ? 0 : timeout_ms};
    server->scheduling_active = true;
    server->queue_fault = false;
    vireo_result_t result = server->scheduler_ops.run_once(server->scheduler_ops.context, server->loop,
        progress.effective_timeout_ms, &progress.wait, &detail.loop_error);
    if (result != VIREO_OK) {
        detail.stage = VIREO_TCP_SERVER_ROUND_WAIT;
        server->scheduling_active = false;
        return round_finish(result, &detail, error, saved_errno);
    }
    detail = (vireo_tcp_server_round_error_t){0};
    progress.queued_after_wait = server->queue_count;
    if (server->queue_fault || !queue_valid(server)) {
        result = VIREO_RESULT_INTERNAL;
        detail.stage = VIREO_TCP_SERVER_ROUND_QUEUE;
        goto done;
    }
    size_t count = progress.queued_after_wait;
    if (count > client_limit) count = client_limit;
    if (count > turn_capacity) count = turn_capacity;
    /* 快照 Q 次中，每次仅移走首项并把它回到尾部，不可能本轮重访一个客户。 */
    for (size_t k = 0; k < count; ++k) {
        size_t const index = server->queue_head;
        if (index >= server->options.connection_capacity) {
            result = VIREO_RESULT_INTERNAL; detail.stage = VIREO_TCP_SERVER_ROUND_QUEUE; break;
        }
        client_slot_t const *slot = &server->clients[index];
        vireo_tcp_server_turn_result_t turn = {.client = slot->lease, .events = slot->pending_events};
        result = queue_remove(server, index);
        if (result != VIREO_OK) { detail.stage = VIREO_TCP_SERVER_ROUND_QUEUE; break; }
        turn.result = drive_client(server, turn.client, &limits, &per_client, wire_workspace,
            workspace_capacity, handler, context, &turn.info, &turn.error, true);
        bool ready_next = false;
        if (auto_close_policy) apply_close_policy(server, &turn, &ready_next);
        if (turn.close_attempted) ++progress.close_attempted_count;
        if (turn.close_result != VIREO_OK) {
            detail.close_result = turn.close_result;
            detail.close_error = turn.close_error;
        }
        result = turn.result;
        if (result != VIREO_OK) {
            out_turns[progress.turn_count++] = turn;
            ++progress.failed_count;
            detail.stage = VIREO_TCP_SERVER_ROUND_DRIVE;
            detail.client = turn.client;
            detail.drive_error = turn.error;
            break;
        }
        ++progress.succeeded_count;
        if (turn.close_result != VIREO_OK) {
            detail.stage = VIREO_TCP_SERVER_ROUND_CLOSE;
            detail.client = turn.client;
            result = turn.close_result;
            out_turns[progress.turn_count++] = turn;
            break;
        }
        if (auto_release_ready && turn.info.ready_to_release) {
            vireo_connection_pool_lease_t owner_lease = turn.client;
            turn.release_attempted = true;
            ++progress.release_attempted_count;
            turn.release_result = release_client(server, &owner_lease, &turn.release_error,
                RELEASE_ROUND);
            turn.released = lease_empty(owner_lease);
            if (turn.released) ++progress.released_count;
            result = turn.release_result;
            if (result != VIREO_OK) {
                detail.stage = VIREO_TCP_SERVER_ROUND_RELEASE;
                detail.client = turn.client;
                detail.client_error = turn.release_error;
            }
        }
        if (result == VIREO_OK && !turn.released && (turn.info.needs_processing || ready_next)) {
            result = queue_append(server, index);
            if (result != VIREO_OK) detail.stage = VIREO_TCP_SERVER_ROUND_QUEUE;
            else if (ready_next) {
                turn.close_requeued = true;
                ++progress.close_requeued_count;
            } else ++progress.requeued_count;
        }
        out_turns[progress.turn_count++] = turn; /* 原固定上限约束关闭/归还与完整结果前缀。 */
        if (result != VIREO_OK) break;
    }
done:
    progress.remaining_count = server->queue_count;
    server->scheduling_active = false;
    *out_info = progress;
    return round_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_run_once(vireo_tcp_server_t *server, int timeout_ms,
    vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_drive_budget_t const *drive_budget,
    vireo_tcp_server_round_budget_t const *round_budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_tcp_server_round_info_t *out_info, vireo_tcp_server_round_error_t *error)
{
    return run_round(server, timeout_ms, options, drive_budget, round_budget, wire_workspace,
        workspace_capacity, handler, context, out_turns, turn_capacity, out_info, error, false);
}

/**
 * @brief 校验自动新客户的公开容量和 flow 数值
 *
 * @param[in] s
 *     非空存活 server，提供全池固定 buffer 容量限额。
 * @param[in] o
 *     非空局部按值配置，不保留 caller 地址。
 * @param[out] pair
 *     非空局部双容量和，不直接发布到公共输出。
 *
 * @retval VIREO_OK
 *     双容量、原公开硬限、预算及帧流阈值均合法。
 * @retval VIREO_RESULT_OVERFLOW
 *     读写容量受检合计无法表示。
 * @retval VIREO_RESULT_RANGE
 *     数值范围或单客户/全池预算不满足。
 *
 * @note 先做受检加法，无资源申请；最外层入口恢复 errno，失败不发布配置。
 */
static vireo_result_t admission_values(vireo_tcp_server_t const *s,
    vireo_tcp_server_admission_options_t const *o, size_t *pair)
{
    vireo_result_t const r = vireo_checked_size_add(o->connection.read_capacity,
        o->connection.write_capacity, pair);
    if (r != VIREO_OK) return r;
    vireo_connection_options_t const c = o->connection;
    vireo_connection_flow_options_t const f = o->flow;
    size_t const head = (size_t)VIREO_PROTOCOL_HEADER_SIZE;
    if (c.read_capacity < head || c.write_capacity < head ||
        c.read_capacity > VIREO_BUFFER_MAX_CAPACITY || c.write_capacity > VIREO_BUFFER_MAX_CAPACITY ||
        c.max_buffer_bytes == 0 || c.max_buffer_bytes > VIREO_CONNECTION_MAX_BUFFER_BYTES ||
        *pair > c.max_buffer_bytes || *pair > s->options.max_buffer_bytes ||
        f.max_frame_bytes < head || f.max_frame_bytes > c.read_capacity ||
        f.max_frame_bytes - head > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE ||
        f.read_low < f.max_frame_bytes - 1 || f.read_low >= f.read_high ||
        f.read_high > c.read_capacity || f.write_low >= f.write_high || f.write_high > c.write_capacity)
        return VIREO_RESULT_RANGE;
    return VIREO_OK;
}

/**
 * @brief 从真实容量账同步监听；不发布配置，不回滚已有资源进度
 *
 * @param[in,out] s
 *     存活server，仅内部Reactor使用。
 * @param[in] pair
 *     已校验新客户正双容量和。
 * @param[out] detail
 *     非空局部独立原监听诊断。
 *
 * @return
 *     单次公开MOD原分类；无绑定NOT_FOUND，损坏容量账INTERNAL。
 *
 * @note 同值省MOD；失败保持实际开关，caller统一恢复errno。
 */
static vireo_result_t admission_sync(vireo_tcp_server_t *s, size_t pair,
    vireo_tcp_server_listener_error_t *detail)
{
    *detail = (vireo_tcp_server_listener_error_t){0};
    if (s->listener == NULL || !s->listener_bound) return VIREO_RESULT_NOT_FOUND;
    if (s->client_count > s->options.connection_capacity || s->buffer_bytes > s->options.max_buffer_bytes)
        return VIREO_RESULT_INTERNAL;
    bool const desired = s->client_count < s->options.connection_capacity &&
        pair <= s->options.max_buffer_bytes - s->buffer_bytes;
    if (desired == s->listener_read_enabled) return VIREO_OK;
    vireo_result_t const result = s->listener_ops.set_read(s->listener_ops.context,
        s->listener, desired, &detail->acceptor_error);
    if (result == VIREO_OK) s->listener_read_enabled = desired;
    else detail->stage = VIREO_TCP_SERVER_LISTENER_UPDATE;
    return result;
}

vireo_result_t vireo_tcp_server_admission_configure(vireo_tcp_server_t *server,
    vireo_tcp_server_admission_options_t const *options, vireo_tcp_server_listener_error_t *error)
{
    int const saved = errno;
    vireo_tcp_server_listener_error_t detail = {0};
    if (server == NULL || options == NULL) return listener_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    if (server->owned_tls_context != NULL || server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active)
        return listener_finish(VIREO_RESULT_BUSY, &detail, error, saved);
    vireo_tcp_server_admission_options_t const copy = *options;
    size_t pair = 0;
    vireo_result_t result = admission_values(server, &copy, &pair);
    if (result == VIREO_OK) result = admission_sync(server, pair, &detail);
    if (result == VIREO_OK) {
        server->admission_options = copy;
        server->admission_pair_bytes = pair;
        server->admission_enabled = true;
    }
    return listener_finish(result, &detail, error, saved);
}

vireo_result_t vireo_tcp_server_admission_refresh(vireo_tcp_server_t *server,
    vireo_tcp_server_listener_error_t *error)
{
    int const saved = errno;
    vireo_tcp_server_listener_error_t detail = {0};
    if (server == NULL) return listener_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    if (server->owned_tls_context != NULL || server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active)
        return listener_finish(VIREO_RESULT_BUSY, &detail, error, saved);
    vireo_result_t const result = server->admission_enabled
        ? admission_sync(server, server->admission_pair_bytes, &detail) : VIREO_RESULT_NOT_FOUND;
    return listener_finish(result, &detail, error, saved);
}

vireo_result_t vireo_tcp_server_admission_disable(vireo_tcp_server_t *server,
    vireo_tcp_server_listener_error_t *error)
{
    int const saved = errno;
    vireo_tcp_server_listener_error_t detail = {0};
    if (server == NULL) return listener_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    if (server->owned_tls_context != NULL || server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active)
        return listener_finish(VIREO_RESULT_BUSY, &detail, error, saved);
    server->admission_enabled = false;
    server->admission_options = (vireo_tcp_server_admission_options_t){0};
    server->admission_pair_bytes = 0;
    return listener_finish(VIREO_OK, &detail, error, saved);
}

/**
 * @brief 按值提交组合服务诊断并恢复最外层 errno
 *
 * @param[in] r
 *     本次主要返回分类，不依据诊断改写。
 * @param[in] d
 *     非空、完全初始化的局部主因及补同步错误。
 * @param[out] error
 *     可空独立 caller 输出，仅复制语义成员。
 * @param[in] saved
 *     最外层入口保存的 errno。
 *
 * @return
 *     r 原值，不提交主要统计或取得资源。
 *
 * @note 主要输出保持和 serving 清理由调用点负责，此函数不重试、不清资源。
 */
static vireo_result_t serve_finish(vireo_result_t r, vireo_tcp_server_serve_error_t const *d,
    vireo_tcp_server_serve_error_t *error, int saved)
{
    if (error != NULL) *error = *d;
    errno = saved;
    return r;
}

/**
 * @brief 复用完整有限serve，连续run只绕过外层running重入和单轮入口停止判断
 *
 * @param[in,out] server
 *     自有资源根，有限整轮保持serving_active。
 * @param[in] options
 *     原timeout及四组配置，入口复制，严格前置校验。
 * @param[in,out] wire_workspace
 *     独立响应工作区，只调用原drive/process。
 * @param[in] workspace_capacity
 *     字节数，须足够最大响应整帧。
 * @param[in] handler
 *     原有界同步业务handler，借到调用返回。
 * @param[in,out] context
 *     原handler context，可空，不拥有。
 * @param[out] out_turns
 *     只写成功等待后真实客户前缀。
 * @param[in] turn_capacity
 *     原客户结果容量，1..65535。
 * @param[in,out] out_clients
 *     原新lease数组，有效前缀须全零。
 * @param[in] client_capacity
 *     原新客户结果容量，1..65535。
 * @param[out] out_info
 *     前置/wait拒绝保持，成功wait提交真实统计。
 * @param[out] error
 *     可空独立完整主因/补同步诊断。
 * @param[in] from_run
 *     仅内部run为true，已进入的整轮不再中途停止。
 *
 * @return
 *     原有限serve分类，不自动重试/回滚/关闭客户。
 *
 * @note 原四active含义不变；sync_called仅在成功wait轮发布，供run识别回调时点。
 */
static vireo_result_t serve_round(vireo_tcp_server_t *server,
    vireo_tcp_server_serve_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_tcp_server_serve_info_t *out_info, vireo_tcp_server_serve_error_t *error, bool from_run)
{
    int const saved = errno;
    vireo_tcp_server_serve_error_t detail = {0};
    if (server == NULL || options == NULL || wire_workspace == NULL || handler == NULL ||
        out_turns == NULL || out_clients == NULL || out_info == NULL)
        return serve_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    if (server->owned_tls_context != NULL || server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active || (server->running_active && !from_run))
        return serve_finish(VIREO_RESULT_BUSY, &detail, error, saved);
    vireo_tcp_server_serve_options_t const o = *options;
    if (o.timeout_ms < -1 || o.admit.max_accepts == 0 || o.admit.max_accept_syscalls == 0)
        return serve_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    if (turn_capacity == 0 || turn_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        client_capacity == 0 || client_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        o.round.max_clients == 0 || o.round.max_clients > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        o.admit.max_accepts > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        !drive_arguments_valid(o.process, o.drive, workspace_capacity))
        return serve_finish(VIREO_RESULT_RANGE, &detail, error, saved);
    size_t const limit = o.admit.max_accepts < client_capacity ? o.admit.max_accepts : client_capacity;
    for (size_t k = 0; k < limit; ++k)
        if (!lease_empty(out_clients[k])) return serve_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    if (!server->admission_enabled || server->listener == NULL || !server->listener_bound)
        return serve_finish(VIREO_RESULT_NOT_FOUND, &detail, error, saved);
    if (o.process.max_request_frame_bytes > server->admission_options.flow.max_frame_bytes ||
        o.process.max_response_frame_bytes > server->admission_options.connection.write_capacity)
        return serve_finish(VIREO_RESULT_RANGE, &detail, error, saved);
    if (!queue_valid(server)) return serve_finish(VIREO_RESULT_INTERNAL, &detail, error, saved);
    if (!from_run) {
        bool stopped = false;
        vireo_result_t const observed = stop_snapshot(server, &stopped);
        if (observed != VIREO_OK) return serve_finish(observed, &detail, error, saved);
        if (stopped) {
            *out_info = (vireo_tcp_server_serve_info_t){0};
            return serve_finish(VIREO_OK, &detail, error, saved);
        }
    }
    server->serving_active = true;
    vireo_result_t result = admission_sync(server, server->admission_pair_bytes, &detail.listener_error);
    if (result != VIREO_OK) {
        detail.stage = VIREO_TCP_SERVER_SERVE_PRE_SYNC;
        goto unchanged;
    }
    server->serve_listener_events = 0;
    vireo_tcp_server_serve_info_t progress = {0};
    result = run_round(server, o.timeout_ms, &o.process, &o.drive, &o.round, wire_workspace,
        workspace_capacity, handler, context, out_turns, turn_capacity, &progress.round,
        &detail.round_error, true);
    if (result != VIREO_OK) {
        detail.stage = VIREO_TCP_SERVER_SERVE_ROUND;
        if (detail.round_error.stage == VIREO_TCP_SERVER_ROUND_WAIT) goto unchanged;
        goto sync;
    }
    progress.listener_events = server->serve_listener_events;
    if ((progress.listener_events & (VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP)) != 0) {
        result = VIREO_RESULT_IO;
        detail.stage = VIREO_TCP_SERVER_SERVE_LISTENER_EVENT;
        detail.listener_events = progress.listener_events;
        goto sync;
    }
    if ((progress.listener_events & VIREO_EPOLL_EVENT_READ) != 0) {
        progress.admission_called = true;
        for (;;) {
            if (progress.admission.accepted_count == limit) {
                progress.admission.stop_reason = VIREO_TCP_SERVER_ADMIT_BATCH_LIMIT; break;
            }
            if (server->client_count == server->options.connection_capacity) {
                progress.admission.stop_reason = VIREO_TCP_SERVER_ADMIT_CONNECTION_LIMIT; break;
            }
            if (server->admission_pair_bytes > server->options.max_buffer_bytes - server->buffer_bytes) {
                progress.admission.stop_reason = VIREO_TCP_SERVER_ADMIT_BUFFER_LIMIT; break;
            }
            if (progress.admission.accept_calls == o.admit.max_accept_syscalls) {
                progress.admission.stop_reason = VIREO_TCP_SERVER_ADMIT_CALL_LIMIT; break;
            }
            size_t const index = progress.admission.admitted_count;
            vireo_tcp_server_admit_budget_t const b = {1, o.admit.max_accept_syscalls - progress.admission.accept_calls};
            vireo_tcp_server_admit_info_t part = {0};
            result = admit_clients(server, &server->admission_options.connection, &b,
                &out_clients[index], 1, &part, &detail.client_error, true);
            /* 原core证明每次最多1成功fd/calls<=剩额；总计均有明确上界。 */
            progress.admission.accepted_count += part.accepted_count;
            progress.admission.admitted_count += part.admitted_count;
            progress.admission.rejected_count += part.rejected_count;
            progress.admission.accept_calls += part.accept_calls;
            progress.admission.transient_errors += part.transient_errors;
            progress.admission.stop_reason = part.stop_reason;
            if (result != VIREO_OK) { detail.stage = VIREO_TCP_SERVER_SERVE_ADMIT; break; }
            if (part.admitted_count == 0) break;
            /* 已登记且owned的lease必须保留；后置flow失败不能伪装未发布后直接close。 */
            vireo_connection_t *connection = NULL;
            result = lookup_for_io(server, out_clients[index], &connection, &detail.client_error);
            if (result == VIREO_OK) {
                result = server->client_ops.flow_configure(server->client_ops.context, connection,
                    &server->admission_options.flow, &detail.client_error.primary.loop_error);
                if (result != VIREO_OK) detail.client_error.primary.stage = VIREO_TCP_SERVER_CLIENT_FLOW_CONFIGURE;
            }
            if (result != VIREO_OK) {
                detail.stage = VIREO_TCP_SERVER_SERVE_INITIALIZE;
                detail.client = out_clients[index];
                progress.admission.stop_reason = VIREO_TCP_SERVER_ADMIT_ERROR;
                break;
            }
            ++progress.initialized_count;
        }
    }
sync:
    progress.listener_events = server->serve_listener_events;
    progress.sync_called = true;
    vireo_tcp_server_listener_error_t sync_error = {0};
    vireo_result_t const synced = admission_sync(server, server->admission_pair_bytes, &sync_error);
    if (synced != VIREO_OK) {
        if (result == VIREO_OK) {
            result = synced; detail.stage = VIREO_TCP_SERVER_SERVE_POST_SYNC;
            detail.listener_error = sync_error;
        } else { detail.sync_result = synced; detail.sync_error = sync_error; }
    }
    progress.listener_read_enabled = server->listener_read_enabled;
    *out_info = progress;
unchanged:
    server->serving_active = false;
    return serve_finish(result, &detail, error, saved);
}


vireo_result_t vireo_tcp_server_serve_once(vireo_tcp_server_t *server,
    vireo_tcp_server_serve_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_tcp_server_serve_info_t *out_info, vireo_tcp_server_serve_error_t *error)
{
    return serve_round(server, options, wire_workspace, workspace_capacity, handler, context,
        out_turns, turn_capacity, out_clients, client_capacity, out_info, error, false);
}

vireo_result_t vireo_tcp_server_request_stop(vireo_tcp_server_t *server,
    vireo_event_loop_error_t *error)
{
    int const saved = errno;
    vireo_event_loop_error_t detail = {0};
    vireo_result_t const result = server == NULL ? VIREO_RESULT_INVALID_ARGUMENT :
        server->stop_ops.request_stop(server->stop_ops.context, server->loop, &detail);
    if (error != NULL) *error = detail;
    errno = saved;
    return result;
}

vireo_result_t vireo_tcp_server_run(vireo_tcp_server_t *server,
    vireo_tcp_server_run_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_tcp_server_round_callback_t callback, void *callback_context,
    vireo_tcp_server_run_error_t *error)
{
    int const saved = errno;
    vireo_tcp_server_run_error_t detail = {0};
    vireo_result_t result = VIREO_OK;
    if (server == NULL || options == NULL || wire_workspace == NULL || handler == NULL ||
        out_turns == NULL || out_clients == NULL || callback == NULL) {
        result = VIREO_RESULT_INVALID_ARGUMENT; goto finished;
    }
    if (server->owned_tls_context != NULL || server->closing_active || server->shutdown_active || server->running_active || server->processing_active || server->driving_active ||
        server->scheduling_active || server->serving_active) {
        result = VIREO_RESULT_BUSY; goto finished;
    }
    vireo_tcp_server_run_options_t const copy = *options;
    if (copy.admit.max_accepts == 0 || copy.admit.max_accept_syscalls == 0) {
        result = VIREO_RESULT_INVALID_ARGUMENT; goto finished;
    }
    if (turn_capacity == 0 || turn_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        client_capacity == 0 || client_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        copy.round.max_clients == 0 || copy.round.max_clients > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        copy.admit.max_accepts > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        !drive_arguments_valid(copy.process, copy.drive, workspace_capacity)) {
        result = VIREO_RESULT_RANGE; goto finished;
    }
    size_t const limit = copy.admit.max_accepts < client_capacity ? copy.admit.max_accepts : client_capacity;
    for (size_t k = 0; k < limit; ++k) {
        if (!lease_empty(out_clients[k])) { result = VIREO_RESULT_INVALID_ARGUMENT; goto finished; }
    }
    vireo_tcp_server_serve_options_t const finite = {-1, copy.process, copy.drive, copy.round, copy.admit};
    size_t previous_clients = 0;
    server->running_active = true;
    for (;;) {
        bool stopped = false;
        result = stop_snapshot(server, &stopped);
        if (result != VIREO_OK) { detail.stage = VIREO_TCP_SERVER_RUN_STOP_SNAPSHOT; break; }
        if (stopped) break;
        /* 只撤回上轮数值输出，不消费pool内owner；回调已结束其view借用。 */
        for (size_t k = 0; k < previous_clients; ++k)
            out_clients[k] = (vireo_connection_pool_lease_t){0};
        vireo_tcp_server_serve_info_t progress = {0};
        vireo_tcp_server_serve_error_t cause = {0};
        result = serve_round(server, &finite, wire_workspace, workspace_capacity, handler, context,
            out_turns, turn_capacity, out_clients, client_capacity, &progress, &cause, true);
        /* sync_called只有成功wait的真实轮才发布；全部四旧active已清除。 */
        if (progress.sync_called) callback(server, result, &progress, out_turns, out_clients,
            &cause, callback_context);
        if (result != VIREO_OK) {
            detail.stage = VIREO_TCP_SERVER_RUN_SERVE;
            detail.round_available = progress.sync_called;
            detail.round_info = progress;
            detail.serve_error = cause;
            break; /* 错误优先于回调中或并发提交的stop。 */
        }
        previous_clients = progress.admission.admitted_count;
    }
    server->running_active = false;
finished:
    if (error != NULL) *error = detail;
    errno = saved;
    return result;
}

vireo_result_t vireo_tcp_server_set_auto_release_ready(vireo_tcp_server_t *server,
    bool enabled, vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->processing_active || server->driving_active || server->scheduling_active ||
        server->serving_active || server->closing_active || server->shutdown_active)
        return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    server->auto_release_ready = enabled;
    return client_finish(VIREO_OK, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_set_auto_close_policy(vireo_tcp_server_t *server,
    bool enabled, vireo_tcp_server_client_error_t *error)
{
    int const saved_errno = errno;
    vireo_tcp_server_client_error_t detail = {0};
    if (server == NULL)
        return client_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    if (server->owned_tls_context != NULL || server->processing_active || server->driving_active || server->scheduling_active ||
        server->serving_active || server->closing_active || server->shutdown_active)
        return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    server->auto_close_policy = enabled;
    return client_finish(VIREO_OK, &detail, error, saved_errno);
}

/** 提交独立关闭批次诊断并恢复入口errno，主要输出由执行分支决定。 */
static vireo_result_t close_batch_finish(vireo_result_t result,
    vireo_tcp_server_close_batch_error_t const *detail,
    vireo_tcp_server_close_batch_error_t *error, int saved_errno)
{
    if (error != NULL) *error = *detail;
    errno = saved_errno;
    return result;
}

/**
 * @brief 实际有限扫描实现，自有可空测试门不代替真实FIFO操作
 *
 * @param[in,out] server
 *     同public合同，closing_active保持到完整统计提交前。
 * @param[in] mode
 *     仅DRAIN/IMMEDIATE，首次理由由公开connection保持。
 * @param[in] budget
 *     正槽预算，每槽含空与失败仅本批一次。
 * @param[out] out_results
 *     caller固定数组，未写尾部保持。
 * @param[in] result_capacity
 *     正live结果上限。
 * @param[out] out_info
 *     前置拒绝保持，执行后提交真实部分进度。
 * @param[out] error
 *     可空独立首阶段与原关闭诊断。
 * @param[in] gate
 *     自有测试故障门；生产NULL，OK后执行原queue_append。
 * @param[in,out] gate_context
 *     仅本调用借用，不存入对象。
 *
 * @return
 *     public合同的首分类；请求后排队失败不能回滚永久意图。
 *
 * @note 原stop线程不访问本实现的普通状态；无分配、收发、资源消费或重试。
 */
vireo_result_t vireo_tcp_server_close_batch_with_gate(vireo_tcp_server_t *server,
    vireo_connection_close_mode_t mode, vireo_tcp_server_close_batch_budget_t const *budget,
    vireo_tcp_server_close_batch_result_t *out_results, size_t result_capacity,
    vireo_tcp_server_close_batch_info_t *out_info, vireo_tcp_server_close_batch_error_t *error,
    vireo_tcp_server_close_queue_gate_t gate, void *gate_context)
{
    int const saved_errno = errno;
    vireo_tcp_server_close_batch_error_t detail = {0};
    if (server == NULL || budget == NULL || out_results == NULL || out_info == NULL ||
        budget->max_slots == 0 || result_capacity == 0 ||
        (mode != VIREO_CONNECTION_CLOSE_MODE_DRAIN && mode != VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE))
        return close_batch_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved_errno);
    size_t const max_slots = budget->max_slots;
    if (max_slots > VIREO_TCP_SERVER_MAX_CONNECTIONS || result_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS)
        return close_batch_finish(VIREO_RESULT_RANGE, &detail, error, saved_errno);
    if (server->owned_tls_context != NULL || server->closing_active || server->shutdown_active || server->processing_active ||
        server->driving_active || server->scheduling_active || server->serving_active)
        return close_batch_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    bool stopped = false;
    vireo_result_t result = stop_snapshot(server, &stopped);
    if (result != VIREO_OK) {
        detail.stage = VIREO_TCP_SERVER_CLOSE_BATCH_SNAPSHOT;
        return close_batch_finish(result, &detail, error, saved_errno);
    }
    if (stopped) return close_batch_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
    size_t const capacity = server->options.connection_capacity;
    if (server->close_next_slot >= capacity || !queue_valid(server)) {
        detail.stage = VIREO_TCP_SERVER_CLOSE_BATCH_SNAPSHOT;
        return close_batch_finish(VIREO_RESULT_INTERNAL, &detail, error, saved_errno);
    }
    size_t const slot_limit = max_slots < capacity ? max_slots : capacity;
    vireo_tcp_server_close_batch_info_t progress = {0};
    server->closing_active = true;
    while (server->client_count != 0 && progress.scanned_slots < slot_limit &&
        progress.processed_clients < result_capacity) {
        size_t const index = server->close_next_slot;
        /* index<capacity<=65535，推进及本批计数不依赖回绕，不扫描输出上限后的空槽。 */
        server->close_next_slot = index + 1 == capacity ? 0 : index + 1;
        ++progress.scanned_slots;
        if (!server->clients[index].live) continue;
        vireo_tcp_server_close_batch_result_t row = {.lease = server->clients[index].lease};
        vireo_connection_t *connection = NULL;
        row.close_result = find_client(server, row.lease, &connection);
        if (row.close_result != VIREO_OK) {
            detail.stage = VIREO_TCP_SERVER_CLOSE_BATCH_LOOKUP;
            row.close_error.primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
        } else {
            row.close_attempted = true;
            ++progress.close_attempted_clients;
            row.close_result = server->client_ops.request_close(server->client_ops.context,
                connection, mode, VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP,
                &row.close_error.primary.loop_error);
            if (row.close_result != VIREO_OK) {
                detail.stage = VIREO_TCP_SERVER_CLOSE_BATCH_REQUEST;
                row.close_error.primary.stage = VIREO_TCP_SERVER_CLIENT_REQUEST_CLOSE;
            }
        }
        row.result = row.close_result;
        if (row.close_result == VIREO_OK) {
            row.schedule_attempted = true;
            row.schedule_result = gate == NULL ? VIREO_OK : gate(gate_context, server, row.lease);
            if (row.schedule_result == VIREO_OK) row.schedule_result = queue_append(server, index);
            row.scheduled = row.schedule_result == VIREO_OK;
            if (row.scheduled) ++progress.scheduled_clients;
            else detail.stage = VIREO_TCP_SERVER_CLOSE_BATCH_QUEUE;
            row.result = row.schedule_result;
        }
        out_results[progress.processed_clients++] = row;
        if (row.result != VIREO_OK) {
            result = row.result;
            detail.client = row.lease;
            detail.client_error = row.close_error;
            progress.stop_reason = VIREO_TCP_SERVER_CLOSE_BATCH_ERROR;
            break;
        }
    }
    progress.owned_clients = server->client_count;
    progress.next_slot = server->close_next_slot;
    if (result == VIREO_OK)
        progress.stop_reason = server->client_count == 0 ? VIREO_TCP_SERVER_CLOSE_BATCH_EMPTY :
            progress.scanned_slots == slot_limit ? VIREO_TCP_SERVER_CLOSE_BATCH_SCAN_LIMIT :
            VIREO_TCP_SERVER_CLOSE_BATCH_RESULT_CAPACITY;
    server->closing_active = false;
    *out_info = progress;
    return close_batch_finish(result, &detail, error, saved_errno);
}

vireo_result_t vireo_tcp_server_close_batch(vireo_tcp_server_t *server,
    vireo_connection_close_mode_t mode, vireo_tcp_server_close_batch_budget_t const *budget,
    vireo_tcp_server_close_batch_result_t *out_results, size_t result_capacity,
    vireo_tcp_server_close_batch_info_t *out_info, vireo_tcp_server_close_batch_error_t *error)
{
    return vireo_tcp_server_close_batch_with_gate(server, mode, budget, out_results,
        result_capacity, out_info, error, NULL, NULL);
}

/**
 * @brief 单次扫描固定槽，公开读取state/due并可安排到期机会
 *
 * @param[in,out] server
 *     非空TLS根，已持scheduling_active，客户/队列只在此Reactor变化。
 * @param[in] enqueue
 *     false为等待前最近due扫描，true为等待后到期排队。
 * @param[in] now
 *     后扫描的新同域采样；前扫描忽略此值。
 * @param[in,out] report
 *     非空本次局部报告，累计槽检查/期限/到期计数。
 * @param[in,out] detail
 *     非空本次诊断，失败保持实际扫描阶段与原TLS原因。
 *
 * @return
 *     OK完成N槽；原观察失败或INTERNAL停止，不回滚已经排入的到期项。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_scan(vireo_tcp_server_t *, bool, vireo_monotonic_ns_t,
    vireo_tcp_server_tls_poll_report_t *, vireo_tcp_server_tls_error_t *);

/**
 * @brief 在整轮保护下共享一次等待及TLS期限扫描，保持原FIFO不撤取
 * @param[in,out] server 非空根，调用者已核队列并设置scheduling_active。
 * @param[in,out] progress 非空已初始化原poll事实，effective_timeout已计划。
 * @param[out] listener_events 可空窗口输出，沿原poll规则。
 * @param[in,out] tls_report TLS模式非空局部时间报告，RAW为NULL。
 * @param[out] tls_error TLS模式非空原因，RAW为NULL。
 * @return 原扫描/采时/wait/停止/队列分类，不执行客户阶段。
 * @note 不取得owner或撤取待办，不撤销外层保护；部分到期入队保持，外层恢复errno。
 */
static vireo_result_t ready_wait(vireo_tcp_server_t *server,
    vireo_tcp_server_poll_report_t *progress, uint32_t *listener_events,
    vireo_tcp_server_tls_poll_report_t *tls_report, vireo_tcp_server_tls_error_t *tls_error)
{
    bool wait_succeeded = false;
    vireo_result_t result = VIREO_OK;
    server->queue_fault = false;
    if (tls_report != NULL) {
        result = tls_scan(server, false, 0, tls_report, tls_error);
        if (result != VIREO_OK) goto waited;
        tls_error->stage = VIREO_TCP_SERVER_TLS_CLOCK;
        result = server->tls_ops.now(server->tls_ops.context, &tls_report->before_wait_ns,
            &tls_error->clock_error);
        if (result != VIREO_OK) goto waited;
        if (tls_report->has_deadline) {
            tls_error->stage = VIREO_TCP_SERVER_TLS_DEADLINE;
            result = vireo_clock_deadline_wait_ms(tls_report->before_wait_ns,
                tls_report->nearest_deadline_ns, progress->effective_timeout_ms,
                &progress->effective_timeout_ms);
            if (result != VIREO_OK) goto waited;
        }
        tls_error->stage = VIREO_TCP_SERVER_TLS_WAIT;
    }
    progress->stage = VIREO_TCP_SERVER_POLL_WAIT;
    progress->wait_called = true;
    if (listener_events != NULL) {
        server->listener_poll_events = 0;
        server->listener_poll_active = true;
    }
    result = server->scheduler_ops.run_once(server->scheduler_ops.context, server->loop,
        progress->effective_timeout_ms, &progress->wait, &progress->loop_error);
    if (listener_events != NULL) {
        server->listener_poll_active = false;
        if (result == VIREO_OK) *listener_events = server->listener_poll_events;
        server->listener_poll_events = 0;
    }
    if (result != VIREO_OK) {
        if (tls_error != NULL) tls_error->loop_error = progress->loop_error;
        goto waited;
    }
    wait_succeeded = true;
    progress->queued_after_wait = server->queue_count;
    if (tls_report != NULL) {
        tls_error->stage = VIREO_TCP_SERVER_TLS_CLOCK;
        result = server->tls_ops.now(server->tls_ops.context, &tls_report->after_wait_ns,
            &tls_error->clock_error);
        if (result != VIREO_OK) goto waited;
        result = tls_scan(server, true, tls_report->after_wait_ns, tls_report, tls_error);
        if (result != VIREO_OK) goto waited;
        result = stop_snapshot(server, &progress->stopped);
        if (result != VIREO_OK || progress->stopped) goto waited;
        tls_error->stage = VIREO_TCP_SERVER_TLS_QUEUE;
    }
    progress->queued_after_wait = server->queue_count;
    progress->stage = VIREO_TCP_SERVER_POLL_QUEUE;
    if (server->queue_fault || !queue_valid(server)) {
        result = VIREO_RESULT_INTERNAL;
        goto waited;
    }
waited:
    if (wait_succeeded) progress->queued_after_wait = server->queue_count;
    progress->remaining_count = server->queue_count;
    return result;
}

/**
 * @brief
 *     公共机械等待及本核心取出前故障门的共同实现。
 *
 * @param[in,out] server
 *     沿公开 poll 合同，持有原固定队列及 scheduling_active。
 * @param[in] timeout_ms
 *     非负毫秒上限；已排队使用 0。
 * @param[in] max_clients
 *     本次正取出上限。
 * @param[out] out_clients
 *     仅写真实已移走前缀。
 * @param[in] client_capacity
 *     独立数组的正容量。
 * @param[out] report
 *     必需独立报告，每可写路径发布。
 * @param[in] gate
 *     可空本核心测试门，只读观察，不改变队列/资源。
 * @param[in,out] context
 *     gate 的可空短借用 context，不保存。
 * @param[out] listener_events
 *     可空独立局部事件值；NULL关闭新采集，非空仅成功wait后发布本次OR。
 * @param[in,out] tls_report
 *     NULL为旧RAW机械等待，非空为TLS同FIFO前后扫描及时间报告；与模式必须相符。
 * @param[in,out] tls_error
 *     TLS路径非空独立局部原因，保存扫描/采时/等待失败；RAW路径为NULL。
 *
 * @return
 *     原 poll 分类；失败保留真实取出前缀和未取队列。
 *
 * @note
 *     无申请或用户业务回调；全部受控出口恢复 errno，等待阶段统一清在途标记。
 */
static vireo_result_t poll_ready(vireo_tcp_server_t *server, int timeout_ms,
    size_t max_clients, vireo_tcp_server_ready_client_t *out_clients, size_t client_capacity,
    vireo_tcp_server_poll_report_t *report, vireo_tcp_server_poll_queue_gate_t gate, void *context,
    uint32_t *listener_events, vireo_tcp_server_tls_poll_report_t *tls_report,
    vireo_tcp_server_tls_error_t *tls_error)
{
    int const saved = errno;
    vireo_tcp_server_poll_report_t progress = {0};
    if (listener_events != NULL) *listener_events = 0;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || out_clients == NULL || report == NULL || timeout_ms < 0 ||
        max_clients == 0 || client_capacity == 0) goto finish;
    if (max_clients > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        client_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS) {
        result = VIREO_RESULT_RANGE;
        goto finish;
    }
    progress.stage = VIREO_TCP_SERVER_POLL_CHECK_SERVER;
    if ((server->owned_tls_context != NULL) != (tls_report != NULL)) {
        result = VIREO_RESULT_BUSY; goto finish;
    }
    if (tls_report != NULL && (!server->listener_bound || server->listener == NULL)) {
        result = VIREO_RESULT_NOT_FOUND; goto finish;
    }
    if (server->closing_active || server->shutdown_active || server->processing_active ||
        server->driving_active || server->scheduling_active || server->serving_active ||
        server->running_active) {
        result = VIREO_RESULT_BUSY;
        goto finish;
    }
    progress.stage = VIREO_TCP_SERVER_POLL_QUEUE;
    if (!queue_valid(server)) {
        result = VIREO_RESULT_INTERNAL;
        goto finish;
    }
    progress.queued_before_wait = server->queue_count;
    progress.remaining_count = server->queue_count;
    progress.stage = VIREO_TCP_SERVER_POLL_CHECK_SERVER;
    result = stop_snapshot(server, &progress.stopped);
    if (result != VIREO_OK || progress.stopped) goto finish;
    progress.effective_timeout_ms = server->queue_count != 0 ? 0 : timeout_ms;
    server->scheduling_active = true;
    result = ready_wait(server, &progress, listener_events, tls_report, tls_error);
    if (result != VIREO_OK || progress.stopped) goto waited;
    size_t count = progress.queued_after_wait;
    if (count > max_clients) count = max_clients;
    if (count > client_capacity) count = client_capacity;
    for (size_t k = 0; k < count; ++k) {
        size_t const index = server->queue_head;
        if (index >= server->options.connection_capacity) {
            result = VIREO_RESULT_INTERNAL;
            break;
        }
        client_slot_t const *slot = &server->clients[index];
        vireo_tcp_server_ready_client_t const item = {slot->lease, slot->pending_events};
        if (gate != NULL) {
            result = gate(context, server, item.client, progress.selected_count);
            if (result != VIREO_OK) break;
        }
        result = queue_remove(server, index);
        if (result != VIREO_OK) break;
        out_clients[progress.selected_count++] = item;
    }
waited:
    progress.remaining_count = server->queue_count;
    server->scheduling_active = false;
finish:
    if (result == VIREO_OK) progress.stage = VIREO_TCP_SERVER_POLL_NONE;
    if (report != NULL) *report = progress;
    errno = saved;
    return result;
}

vireo_result_t vireo_tcp_server_poll_ready_once(vireo_tcp_server_t *server, int timeout_ms,
    size_t max_clients, vireo_tcp_server_ready_client_t *out_clients, size_t client_capacity,
    vireo_tcp_server_poll_report_t *report)
{
    return poll_ready(server, timeout_ms, max_clients, out_clients, client_capacity, report, NULL, NULL, NULL, NULL, NULL);
}

vireo_result_t vireo_tcp_server_poll_ready_once_with_gate(vireo_tcp_server_t *server,
    int timeout_ms, size_t max_clients, vireo_tcp_server_ready_client_t *out_clients,
    size_t client_capacity, vireo_tcp_server_poll_report_t *report,
    vireo_tcp_server_poll_queue_gate_t gate, void *context)
{
    return poll_ready(server, timeout_ms, max_clients, out_clients, client_capacity, report, gate, context, NULL, NULL, NULL);
}

/** 两字段局部报告独立于资源，NULL report仍走原基本拒绝，无窗口变更。 */
vireo_result_t vireo_tcp_server_poll_with_listener_once_with_gate(vireo_tcp_server_t *server,
    int timeout_ms, size_t max_clients, vireo_tcp_server_ready_client_t *out_clients,
    size_t client_capacity, vireo_tcp_server_listener_poll_report_t *report,
    vireo_tcp_server_poll_queue_gate_t gate, void *context)
{
    vireo_tcp_server_listener_poll_report_t value = {0};
    vireo_result_t const result = poll_ready(server, timeout_ms, max_clients, out_clients,
        client_capacity, report != NULL ? &value.poll : NULL, gate, context, &value.listener_events, NULL, NULL);
    if (report != NULL) *report = value;
    return result;
}

vireo_result_t vireo_tcp_server_poll_with_listener_once(vireo_tcp_server_t *server,
    int timeout_ms, size_t max_clients, vireo_tcp_server_ready_client_t *out_clients,
    size_t client_capacity, vireo_tcp_server_listener_poll_report_t *report)
{
    return vireo_tcp_server_poll_with_listener_once_with_gate(server, timeout_ms,
        max_clients, out_clients, client_capacity, report, NULL, NULL);
}

/* TLS扩展只组合公开依赖；状态/期限权威仍在同一个TLS对象。 */
/**
 * @brief 桥接公开单调采集，不在server保存第二时钟
 *
 * @param[in] ctx
 *     系统桥接不用的上下文，可空。
 * @param[out] now
 *     非空独立纳秒输出，仅成功提交。
 * @param[out] error
 *     可空独立clock原因。
 *
 * @return
 *     公开采集OK/IO/OVERFLOW/INTERNAL原样返回。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_system_now(void *ctx, vireo_monotonic_ns_t *now, vireo_clock_error_t *error)
{ (void)ctx; return vireo_clock_monotonic_now(now, error); }
/**
 * @brief 桥接公开TLS connection创建，失败不转移fd
 *
 * @param[in] ctx
 *     系统桥接不用的上下文，可空。
 * @param[in] context
 *     server拥有的context，仅短借。
 * @param[in] options
 *     固定单SSL包装预算，短借。
 * @param[in,out] fd
 *     非空唯一accepted fd owner，成功清为-1。
 * @param[in,out] owner
 *     非空独立NULL connection owner，成功接管。
 * @param[out] error
 *     可空独立connection原因。
 *
 * @return
 *     公开创建分类原样返回；不执行握手或业务。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_system_create(void *ctx, vireo_tls_context_t const *context,
    vireo_tls_connection_options_t const *options, int *fd, vireo_connection_t **owner,
    vireo_connection_error_t *error)
{ (void)ctx; return vireo_connection_create_tls_server(context, options, fd, owner, error); }
/**
 * @brief 桥接固定应用资源准备，不改TLS业务许可
 *
 * @param[in] ctx
 *     不用的上下文，可空。
 * @param[in,out] tls
 *     当前未握手对象的串行短借，不转移owner。
 * @param[in] options
 *     固定八配置，短借至返回。
 * @param[out] error
 *     可空独立TLS原因。
 *
 * @return
 *     公开prepare成功/失败分类，失败仍由connection清理。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_system_prepare(void *ctx, vireo_tls_connection_t *tls,
    vireo_tls_io_options_t const *options, vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_io_prepare(tls, options, error); }
/**
 * @brief 桥接一次期限装载，不额外采时或续期
 *
 * @param[in] ctx
 *     不用的上下文，可空。
 * @param[in,out] tls
 *     当前INITIAL对象短借。
 * @param[in] now
 *     成功accept后采得的同域纳秒值。
 * @param[in] due
 *     受检求得的同域绝对期限。
 * @param[out] error
 *     可空独立TLS原因。
 *
 * @return
 *     公开arm原分类，失败不转移owner。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_system_arm(void *ctx, vireo_tls_connection_t *tls,
    vireo_monotonic_ns_t now, vireo_monotonic_ns_t due, vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_handshake_deadline_arm(tls, now, due, error); }
/**
 * @brief 桥接真实TLS握手快照，避免server复制状态
 *
 * @param[in] ctx
 *     不用的上下文，可空。
 * @param[in] tls
 *     同Reactor短借，不得跨release使用。
 * @param[out] info
 *     非空独立快照，失败保持。
 * @param[out] error
 *     可空独立TLS原因。
 *
 * @return
 *     公开inspect原分类，无网络或状态推进。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_system_inspect(void *ctx, vireo_tls_connection_t const *tls,
    vireo_tls_connection_info_t *info, vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_inspect(tls, info, error); }
/**
 * @brief 桥接原TLS期限观察，不保存第二份due
 *
 * @param[in] ctx
 *     不用的上下文，可空。
 * @param[in] tls
 *     当前客户TLS短借。
 * @param[out] info
 *     非空独立期限快照，失败保持。
 * @param[out] error
 *     可空独立TLS原因。
 *
 * @return
 *     公开deadline inspect原分类，不采时或修改期限。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_system_deadline(void *ctx, vireo_tls_connection_t const *tls,
    vireo_tls_handshake_deadline_info_t *info, vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_handshake_deadline_inspect(tls, info, error); }
/**
 * @brief 桥接原TLS带时间单步，真实原生次数仍由TLS限制
 *
 * @param[in] ctx
 *     不用的上下文，可空。
 * @param[in,out] tls
 *     同Reactor当前客户TLS短借。
 * @param[in] now
 *     当前入口新采得的同域纳秒值。
 * @param[out] info
 *     非空独立握手报告，原生前拒绝保持。
 * @param[out] error
 *     可空独立TLS首因。
 *
 * @return
 *     公开step_at原分类，WANT或终态事实由info决定。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_system_step(void *ctx, vireo_tls_connection_t *tls,
    vireo_monotonic_ns_t now, vireo_tls_handshake_info_t *info, vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_handshake_step_at(tls, now, info, error); }

/**
 * @brief 桥接真实应用快照，不复制长期TLS状态
 *
 * @param[in] ctx
 *     不用的上下文，可空。
 * @param[in] tls
 *     当前短借对象，存活至返回。
 * @param[out] info
 *     必需独立快照，成功提交。
 * @param[out] error
 *     可空独立TLS诊断。
 *
 * @return
 *     原公开分类。
 *
 * @note 无网络或owner交接，errno沿原依赖，最外层统一恢复。
 */
static vireo_result_t tls_system_io_inspect(void *ctx, vireo_tls_connection_t const *tls,
    vireo_tls_io_info_t *info, vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_io_inspect(tls, info, error); }

/**
 * @brief 桥接纯TLS迟滞/关注建议，不自动MOD
 *
 * @param[in] ctx
 *     不用的上下文，可空。
 * @param[in,out] tls
 *     当前短借对象，同Reactor串行。
 * @param[out] info
 *     必需独立flow，成功提交。
 * @param[out] error
 *     可空独立诊断。
 *
 * @return
 *     原公开分类。
 *
 * @note 无owner交接/网络/等待，errno由最外层恢复。
 */
static vireo_result_t tls_system_flow(void *ctx, vireo_tls_connection_t *tls,
    vireo_tls_io_flow_t *info, vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_flow_refresh(tls, info, error); }

/**
 * @brief 桥接单次有界TLS接收，保留原生前输出保持
 *
 * @param[in] ctx
 *     不用的上下文，可空。
 * @param[in,out] tls
 *     当前短借对象，同Reactor串行。
 * @param[in] budget
 *     原明文字节/SSL次数预算，只借至返回。
 * @param[out] info
 *     必需独立进度，按原发布规则。
 * @param[out] error
 *     可空独立TLS诊断。
 *
 * @return
 *     原公开分类，不替调用者重试。
 *
 * @note 沿原稳定请求/SIGPIPE/库队列规则，errno由最外层恢复，无owner交接。
 */
static vireo_result_t tls_system_receive(void *ctx, vireo_tls_connection_t *tls,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *info,
    vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_receive(tls, budget, info, error); }

/**
 * @brief 桥接单次有界TLS发送，不重领预算或改变locked请求
 *
 * @param[in] ctx
 *     不用的上下文，可空。
 * @param[in,out] tls
 *     当前短借对象，同Reactor串行。
 * @param[in] budget
 *     原明文字节/SSL次数预算，只借至返回。
 * @param[out] info
 *     必需独立进度，按原发布规则。
 * @param[out] error
 *     可空独立TLS诊断。
 *
 * @return
 *     原公开分类，不替调用者重试。
 *
 * @note 沿原稳定请求/SIGPIPE/库队列规则，errno由最外层恢复，无owner交接。
 */
static vireo_result_t tls_system_send(void *ctx, vireo_tls_connection_t *tls,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *info,
    vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_send(tls, budget, info, error); }

/**
 * @brief 桥接关闭快照，阻止应用driver绕过已请求关闭的门禁
 *
 * @param[in] ctx
 *     不用的上下文，可空。
 * @param[in] tls
 *     当前短借对象，存活至返回。
 * @param[out] info
 *     必需独立关闭快照，成功提交。
 * @param[out] error
 *     可空独立TLS诊断。
 *
 * @return
 *     原公开分类。
 *
 * @note 无网络/采时/owner交接，errno由最外层恢复。
 */
static vireo_result_t tls_system_close_inspect(void *ctx, vireo_tls_connection_t const *tls,
    vireo_tls_close_info_t *info, vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_close_inspect(tls, info, error); }

/**
 * @brief 桥接原关闭请求，仅成功时封口。
 * @param[in] ctx 不用的短借上下文。
 * @param[in,out] tls 同Reactor存活对象短借。
 * @param[in] now 同域本次采时。
 * @param[in] due checked后的固定期限。
 * @param[out] error 可空独立TLS原因。
 * @return 原公开分类，无网络/owner交接，外层恢复errno。
 */
static vireo_result_t tls_system_close_request(void *ctx, vireo_tls_connection_t *tls,
    vireo_monotonic_ns_t now, vireo_monotonic_ns_t due, vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_close_request(tls, now, due, error); }
/**
 * @brief 桥接原关闭单步，不额外重试。
 * @param[in] ctx 不用的短借上下文。
 * @param[in,out] tls 同Reactor存活对象短借。
 * @param[in] now 同域新采时，终态忽略。
 * @param[in] bytes 已核正字节预算。
 * @param[out] info 必需独立报告，原生前拒绝保持。
 * @param[out] error 可空独立TLS原因。
 * @return 原公开分类，至多一次native，无owner交接，外层恢复errno。
 */
static vireo_result_t tls_system_close_step_at(void *ctx, vireo_tls_connection_t *tls,
    vireo_monotonic_ns_t now, size_t bytes, vireo_tls_close_progress_t *info,
    vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_close_step_at(tls, now, bytes, info, error); }

static vireo_tcp_server_tls_ops_t const system_tls_ops = {
    NULL, tls_system_now, tls_system_create, tls_system_prepare, tls_system_arm,
    tls_system_inspect, tls_system_deadline, tls_system_step, tls_system_io_inspect,
    tls_system_flow, tls_system_receive, tls_system_send, tls_system_close_inspect,
    tls_system_close_request, tls_system_close_step_at
};

/** 完整表验证不执行依赖；无全局可变hooks或外模块private访问。 */
static bool tls_ops_valid(vireo_tcp_server_tls_ops_t const *o)
{
    return o != NULL && o->now != NULL && o->create != NULL && o->prepare != NULL &&
        o->arm != NULL && o->inspect != NULL && o->deadline != NULL && o->step != NULL &&
        o->io_inspect != NULL && o->flow_refresh != NULL && o->receive != NULL &&
        o->send != NULL && o->close_inspect != NULL &&
        o->close_request != NULL && o->close_step_at != NULL;
}

/**
 * @brief 覆盖独立诊断并恢复最外层errno
 *
 * @param[in] result
 *     已有主要分类，不由次因改写。
 * @param[in] detail
 *     非空完整初始化的局部主因及次因。
 * @param[out] error
 *     可空独立诊断，非空时覆盖。
 * @param[in] saved_errno
 *     公共入口保存的原errno。
 *
 * @return
 *     原result不变。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_finish(vireo_result_t result, vireo_tcp_server_tls_error_t const *detail,
    vireo_tcp_server_tls_error_t *error, int saved_errno)
{
    if (error != NULL) *error = *detail;
    errno = saved_errno;
    return result;
}

/**
 * @brief 在accept前固定八配置及两份容量口径
 *
 * @param[in] base
 *     非空原server配置，仅借用。
 * @param[in] o
 *     非空TLS固定选项，仅借用。
 * @param[out] pair
 *     非空局部受检两FIFO和，失败值不发布给caller。
 * @param[out] total
 *     非空局部四固定区和，失败值不发布给caller。
 *
 * @return
 *     OK表示数值合法；INVALID_ARGUMENT/RANGE/OVERFLOW区分正值、原prepare范围和算术拒绝。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_options_validate(vireo_tcp_server_options_t const *base,
    vireo_tcp_server_tls_options_t const *o, size_t *pair, size_t *total)
{
    vireo_tls_io_options_t const *i = &o->io;
    vireo_result_t result = vireo_checked_size_add(i->read_capacity, i->write_capacity, pair);
    if (result == VIREO_OK)
        result = vireo_checked_size_add(*pair, 2 * VIREO_TLS_IO_SCRATCH_BYTES, total);
    if (result != VIREO_OK) return result;
    if (o->max_wrapper_bytes == 0 || o->handshake_timeout_ns == 0 || o->max_tls_resource_bytes == 0)
        return VIREO_RESULT_INVALID_ARGUMENT;
    if (i->max_buffer_bytes == 0 || i->read_capacity == 0 || i->write_capacity == 0 ||
        i->max_read_unit_bytes == 0 || i->read_low >= i->read_high || i->write_low >= i->write_high)
        return VIREO_RESULT_RANGE;
    if (o->max_wrapper_bytes > VIREO_TLS_CONNECTION_MAX_WRAPPER_BYTES ||
        o->max_tls_resource_bytes > VIREO_TLS_IO_MAX_BUFFER_BYTES ||
        i->read_capacity < VIREO_PROTOCOL_HEADER_SIZE || i->write_capacity < VIREO_PROTOCOL_HEADER_SIZE ||
        i->max_read_unit_bytes < VIREO_PROTOCOL_HEADER_SIZE ||
        i->max_read_unit_bytes > i->read_capacity || i->read_low < i->max_read_unit_bytes - 1 ||
        i->read_high > i->read_capacity || i->write_high > i->write_capacity ||
        i->max_buffer_bytes > VIREO_TLS_IO_MAX_BUFFER_BYTES || *total > i->max_buffer_bytes ||
        *total > o->max_tls_resource_bytes || *pair > base->max_buffer_bytes)
        return VIREO_RESULT_RANGE;
    return VIREO_OK;
}

/** 旧零容量与新正容量共享同一根构造，context只在最后成功点move。 */
static vireo_result_t create_tls_with_dependencies(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_tls_options_t const *tls_options, size_t auxiliary_capacity,
    vireo_tls_context_t **context_owner,
    vireo_tcp_server_ops_t const *base_ops, vireo_tcp_server_listener_ops_t const *listener_ops,
    vireo_tcp_server_client_ops_t const *client_ops,
    vireo_tcp_server_scheduler_ops_t const *scheduler_ops, vireo_tcp_server_tls_ops_t const *tls_ops,
    vireo_tcp_server_t **out_server, vireo_tcp_server_tls_error_t *error)
{
    int const saved = errno;
    vireo_tcp_server_tls_error_t detail = {0};
    vireo_tcp_server_tls_ops_t const *o = tls_ops != NULL ? tls_ops : &system_tls_ops;
    if (options == NULL || tls_options == NULL || context_owner == NULL || *context_owner == NULL ||
        out_server == NULL || *out_server != NULL || !tls_ops_valid(o))
        return tls_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    size_t pair = 0, total = 0;
    vireo_result_t result = tls_options_validate(options, tls_options, &pair, &total);
    if (result != VIREO_OK) return tls_finish(result, &detail, error, saved);
    vireo_tls_context_info_t context_info = {0};
    detail.stage = VIREO_TCP_SERVER_TLS_CONTEXT;
    result = vireo_tls_context_inspect(*context_owner, &context_info, &detail.context_error);
    if (result != VIREO_OK) return tls_finish(result, &detail, error, saved);
    if (options->max_memory_bytes > VIREO_TCP_SERVER_MAX_MEMORY ||
        options->max_memory_bytes <= context_info.wrapper_bytes)
        return tls_finish(VIREO_RESULT_RANGE, &detail, error, saved);
    /* 原构造只看到扣除context预留后的预算；其真实loop/pool上限保持该值。 */
    vireo_tcp_server_options_t adjusted = *options;
    adjusted.max_memory_bytes -= context_info.wrapper_bytes;
    vireo_tcp_server_t *candidate = NULL;
    detail.stage = VIREO_TCP_SERVER_TLS_CREATE_SERVER;
    result = create_with_dependencies(&adjusted, auxiliary_capacity, base_ops != NULL ? base_ops : &system_ops,
        listener_ops != NULL ? listener_ops : &system_listener_ops, client_ops != NULL ? client_ops : &system_client_ops,
        scheduler_ops != NULL ? scheduler_ops : &system_scheduler_ops, &system_stop_ops,
        &candidate, &detail.server_error);
    if (result != VIREO_OK) return tls_finish(result, &detail, error, saved);
    candidate->options = *options;
    candidate->tls_options = *tls_options;
    candidate->context_wrapper_bytes = context_info.wrapper_bytes;
    candidate->tls_pair_bytes = pair;
    candidate->tls_per_connection_bytes = total;
    candidate->tls_ops = *o;
    candidate->owned_tls_context = *context_owner;
    *context_owner = NULL;
    *out_server = candidate;
    detail = (vireo_tcp_server_tls_error_t){0};
    return tls_finish(VIREO_OK, &detail, error, saved);
}

vireo_result_t vireo_tcp_server_create_tls_with_all_ops(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_tls_options_t const *tls_options, vireo_tls_context_t **context_owner,
    vireo_tcp_server_ops_t const *base_ops, vireo_tcp_server_listener_ops_t const *listener_ops,
    vireo_tcp_server_client_ops_t const *client_ops,
    vireo_tcp_server_scheduler_ops_t const *scheduler_ops, vireo_tcp_server_tls_ops_t const *tls_ops,
    vireo_tcp_server_t **out_server, vireo_tcp_server_tls_error_t *error)
{
    return create_tls_with_dependencies(options, tls_options, 0, context_owner, base_ops,
        listener_ops, client_ops, scheduler_ops, tls_ops, out_server, error);
}

vireo_result_t vireo_tcp_server_create_tls_with_auxiliary_ops(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_tls_options_t const *tls_options, size_t auxiliary_capacity,
    vireo_tls_context_t **context_owner, vireo_tcp_server_ops_t const *base_ops,
    vireo_tcp_server_t **out_server, vireo_tcp_server_tls_error_t *error)
{
    int const saved = errno;
    vireo_tcp_server_tls_error_t const detail = {0};
    if (auxiliary_capacity == 0)
        return tls_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    return create_tls_with_dependencies(options, tls_options, auxiliary_capacity, context_owner,
        base_ops, NULL, NULL, NULL, NULL, out_server, error);
}

vireo_result_t vireo_tcp_server_create_tls_with_auxiliary_capacity(
    vireo_tcp_server_options_t const *options, vireo_tcp_server_tls_options_t const *tls_options,
    size_t auxiliary_capacity, vireo_tls_context_t **context_owner,
    vireo_tcp_server_t **out_server, vireo_tcp_server_tls_error_t *error)
{
    return vireo_tcp_server_create_tls_with_auxiliary_ops(options, tls_options, auxiliary_capacity,
        context_owner, NULL, out_server, error);
}

vireo_result_t vireo_tcp_server_create_tls_with_ops(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_tls_options_t const *tls_options, vireo_tls_context_t **context_owner,
    vireo_tcp_server_ops_t const *base_ops, vireo_tcp_server_client_ops_t const *client_ops,
    vireo_tcp_server_scheduler_ops_t const *scheduler_ops, vireo_tcp_server_tls_ops_t const *tls_ops,
    vireo_tcp_server_t **out_server, vireo_tcp_server_tls_error_t *error)
{ return vireo_tcp_server_create_tls_with_all_ops(options, tls_options, context_owner,
    base_ops, NULL, client_ops, scheduler_ops, tls_ops, out_server, error); }

vireo_result_t vireo_tcp_server_create_tls(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_tls_options_t const *tls_options, vireo_tls_context_t **context_owner,
    vireo_tcp_server_t **out_server, vireo_tcp_server_tls_error_t *error)
{
    return vireo_tcp_server_create_tls_with_ops(options, tls_options, context_owner,
        NULL, NULL, NULL, NULL, out_server, error);
}

vireo_result_t vireo_tcp_server_tls_inspect(vireo_tcp_server_t const *server,
    vireo_tcp_server_tls_info_t *out_info, vireo_tcp_server_tls_error_t *error)
{
    int const saved = errno;
    vireo_tcp_server_tls_error_t detail = {0};
    if (server == NULL || out_info == NULL)
        return tls_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    if (server->owned_tls_context == NULL)
        return tls_finish(VIREO_RESULT_BUSY, &detail, error, saved);
    detail.stage = VIREO_TCP_SERVER_TLS_INSPECT;
    vireo_tcp_server_info_t base;
    vireo_result_t result = vireo_tcp_server_inspect(server, &base);
    size_t bytes = 0;
    if (result == VIREO_OK)
        result = vireo_checked_size_mul(base.connection_count, server->tls_per_connection_bytes, &bytes);
    if (result != VIREO_OK) return tls_finish(result, &detail, error, saved);
    if (bytes > server->tls_options.max_tls_resource_bytes)
        return tls_finish(VIREO_RESULT_INTERNAL, &detail, error, saved);
    *out_info = (vireo_tcp_server_tls_info_t){server->tls_options, server->tls_per_connection_bytes,
        bytes, server->tls_options.max_tls_resource_bytes - bytes, server->context_wrapper_bytes};
    detail = (vireo_tcp_server_tls_error_t){0};
    return tls_finish(VIREO_OK, &detail, error, saved);
}

/**
 * @brief 经原pool完整租约和server槽核对后短借TLS
 *
 * @param[in] server
 *     非空同Reactor资源根，不获取第二owner。
 * @param[in] client
 *     完整数值身份，不保活。
 * @param[out] connection
 *     非空独立局部短借输出，仅本次使用。
 * @param[out] tls
 *     非空独立局部短借输出，不跨release。
 * @param[in,out] detail
 *     非空本次诊断，只记lookup失败阶段。
 *
 * @return
 *     原lookup/borrow分类，无网络/资源消费。
 *
 * @note 无额外owner/重试或跨线程权限；系统桥接沿原依赖errno/库队列合同，外层恢复errno。
 */
static vireo_result_t tls_lookup(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_connection_t **connection,
    vireo_tls_connection_t **tls, vireo_tcp_server_tls_error_t *detail)
{
    detail->stage = VIREO_TCP_SERVER_TLS_LOOKUP;
    vireo_result_t result = find_client(server, client, connection);
    if (result == VIREO_OK) result = vireo_connection_tls_borrow(*connection, tls);
    return result;
}

vireo_result_t vireo_tcp_server_client_tls_borrow(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tls_connection_t **out_tls,
    vireo_tcp_server_tls_error_t *error)
{
    int const saved = errno;
    vireo_tcp_server_tls_error_t detail = {0};
    if (server == NULL || out_tls == NULL)
        return tls_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    if (server->owned_tls_context == NULL || auxiliary_active(server) || server->running_active)
        return tls_finish(VIREO_RESULT_BUSY, &detail, error, saved);
    vireo_connection_t *connection = NULL;
    vireo_tls_connection_t *tls = NULL;
    vireo_result_t const result = tls_lookup(server, client, &connection, &tls, &detail);
    if (result == VIREO_OK) { *out_tls = tls; detail = (vireo_tcp_server_tls_error_t){0}; }
    return tls_finish(result, &detail, error, saved);
}

/**
 * @brief 复用原TLS接入事务；嵌套serve保留其serving保护
 * @param[in,out] server 存活TLS根，只有可信serve可已持serving。
 * @param[in] budget 原独立正接入数量/调用预算，不保留地址。
 * @param[in,out] out_clients 原独立空租约潜在前缀，只发布admitted项。
 * @param[in] capacity 原数组正元素数，参与条数上限。
 * @param[out] out_info 原报告，前置拒绝保持，合法执行发布真实进度。
 * @param[out] error 原可空完整主因/首清理诊断。
 * @param[in] from_serve 仅本核心已保护的serve为true，公共wrapper恒false。
 * @param[in] gate 可空发布后只读排队故障门，失败不改变owner/状态。
 * @param[in,out] gate_context gate调用期短借，不保存。
 * @return 原admit或gate分类，任何错误都不撤回已发布lease。
 * @note 不放宽调度/业务在途，处理原owner清理；外层恢复errno。
 */
static vireo_result_t tls_admit_batch(vireo_tcp_server_t *server,
    vireo_tcp_server_admit_budget_t const *budget, vireo_connection_pool_lease_t *out_clients,
    size_t capacity, vireo_tcp_server_tls_admit_info_t *out_info, vireo_tcp_server_tls_error_t *error,
    bool from_serve, vireo_tcp_server_tls_application_queue_gate_t gate, void *gate_context)
{
    int const saved = errno;
    vireo_tcp_server_tls_error_t detail = {0};
    if (server == NULL || budget == NULL || out_clients == NULL || out_info == NULL ||
        budget->max_accepts == 0 || budget->max_accept_syscalls == 0)
        return tls_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    if (server->owned_tls_context == NULL || server->closing_active || server->shutdown_active ||
        server->processing_active || server->driving_active || server->scheduling_active ||
        (server->serving_active && !from_serve) || server->running_active)
        return tls_finish(VIREO_RESULT_BUSY, &detail, error, saved);
    if (capacity == 0 || capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        budget->max_accepts > VIREO_TCP_SERVER_MAX_CONNECTIONS)
        return tls_finish(VIREO_RESULT_RANGE, &detail, error, saved);
    size_t const limit = capacity < budget->max_accepts ? capacity : budget->max_accepts;
    for (size_t k = 0; k < limit; ++k)
        if (!lease_empty(out_clients[k]))
            return tls_finish(VIREO_RESULT_INVALID_ARGUMENT, &detail, error, saved);
    if (server->listener == NULL)
        return tls_finish(VIREO_RESULT_NOT_FOUND, &detail, error, saved);
    vireo_tcp_server_tls_info_t resources;
    vireo_result_t result = vireo_tcp_server_tls_inspect(server, &resources, &detail);
    if (result != VIREO_OK) return tls_finish(result, &detail, error, saved);
    vireo_tcp_server_tls_admit_info_t progress = {0};
    vireo_tcp_server_admit_info_t *p = &progress.admission;
    vireo_tcp_server_client_ops_t const *c = &server->client_ops;
    vireo_tcp_server_tls_ops_t const *t = &server->tls_ops;
    if (!from_serve) server->serving_active = true; /* 嵌套调用不撤除外层整段保护。 */
    for (;;) {
        if (p->accepted_count == limit) { p->stop_reason = VIREO_TCP_SERVER_ADMIT_BATCH_LIMIT; break; }
        if (server->client_count == server->options.connection_capacity) {
            p->stop_reason = VIREO_TCP_SERVER_ADMIT_CONNECTION_LIMIT; break;
        }
        if (server->tls_pair_bytes > server->options.max_buffer_bytes - server->buffer_bytes) {
            p->stop_reason = VIREO_TCP_SERVER_ADMIT_BUFFER_LIMIT; break;
        }
        if (server->tls_per_connection_bytes > resources.available_resource_bytes) {
            progress.tls_resource_limited = true;
            p->stop_reason = VIREO_TCP_SERVER_ADMIT_BUFFER_LIMIT; break;
        }
        if (p->accept_calls == budget->max_accept_syscalls) {
            p->stop_reason = VIREO_TCP_SERVER_ADMIT_CALL_LIMIT; break;
        }
        vireo_acceptor_accept_budget_t const allowance = {1, budget->max_accept_syscalls - p->accept_calls};
        vireo_acceptor_accept_info_t accepted = {0};
        int fd = -1;
        vireo_connection_t *connection = NULL, *borrowed = NULL;
        vireo_tls_connection_t *tls = NULL;
        vireo_connection_pool_lease_t lease = {0};
        client_slot_t *slot = NULL;
        detail.stage = VIREO_TCP_SERVER_TLS_ACCEPT;
        detail.client_error.primary.stage = VIREO_TCP_SERVER_CLIENT_ACCEPT;
        result = c->accept(c->context, server->listener, &allowance, &fd, 1, &accepted,
            &detail.client_error.primary.acceptor_error);
        if (accepted.accepted_count > 1 || accepted.accept_calls > allowance.max_syscalls ||
            accepted.transient_errors > accepted.accept_calls || accepted.accepted_count > accepted.accept_calls ||
            (accepted.accepted_count == 1) != (fd >= 0) ||
            vireo_checked_size_add(p->accept_calls, accepted.accept_calls, &p->accept_calls) != VIREO_OK ||
            vireo_checked_size_add(p->transient_errors, accepted.transient_errors, &p->transient_errors) != VIREO_OK) {
            result = VIREO_RESULT_INTERNAL; goto rejected;
        }
        p->accepted_count += accepted.accepted_count;
        if (result != VIREO_OK) goto rejected;
        if (fd < 0) {
            if (accepted.stop_reason == VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK)
                p->stop_reason = VIREO_TCP_SERVER_ADMIT_WOULD_BLOCK;
            else if (accepted.stop_reason == VIREO_ACCEPTOR_ACCEPT_CALL_BUDGET &&
                p->accept_calls == budget->max_accept_syscalls)
                p->stop_reason = VIREO_TCP_SERVER_ADMIT_CALL_LIMIT;
            else { result = VIREO_RESULT_INTERNAL; goto rejected; }
            detail = (vireo_tcp_server_tls_error_t){0}; break;
        }
        vireo_monotonic_ns_t now = 0, due = 0;
        detail.stage = VIREO_TCP_SERVER_TLS_CLOCK;
        detail.client_error.primary = (vireo_tcp_server_client_cause_t){0};
        result = t->now(t->context, &now, &detail.clock_error);
        if (result != VIREO_OK) goto rejected;
        detail.stage = VIREO_TCP_SERVER_TLS_DEADLINE;
        result = vireo_clock_deadline_after(now, server->tls_options.handshake_timeout_ns, &due);
        if (result != VIREO_OK) goto rejected;
        detail.stage = VIREO_TCP_SERVER_TLS_CREATE_CLIENT;
        detail.client_error.primary.stage = VIREO_TCP_SERVER_CLIENT_CREATE;
        vireo_tls_connection_options_t const wrapper = {server->tls_options.max_wrapper_bytes};
        result = t->create(t->context, server->owned_tls_context, &wrapper, &fd, &connection,
            &detail.client_error.primary.connection_error);
        if (result != VIREO_OK) goto rejected;
        detail.client_error.primary = (vireo_tcp_server_client_cause_t){0};
        detail.stage = VIREO_TCP_SERVER_TLS_LOOKUP;
        result = vireo_connection_tls_borrow(connection, &tls);
        if (result != VIREO_OK) goto rejected;
        detail.stage = VIREO_TCP_SERVER_TLS_PREPARE;
        result = t->prepare(t->context, tls, &server->tls_options.io, &detail.tls_error);
        if (result != VIREO_OK) goto rejected;
        detail.stage = VIREO_TCP_SERVER_TLS_ARM;
        result = t->arm(t->context, tls, now, due, &detail.tls_error);
        if (result != VIREO_OK) goto rejected;
        detail.stage = VIREO_TCP_SERVER_TLS_ADOPT;
        detail.client_error.primary.stage = VIREO_TCP_SERVER_CLIENT_ADOPT;
        result = c->adopt(c->context, server->pool, &connection, &lease, &detail.client_error.primary.pool_error);
        if (result != VIREO_OK) goto rejected;
        if (lease_empty(lease) || lease.slot_index >= server->options.connection_capacity) {
            result = VIREO_RESULT_INTERNAL; goto rejected;
        }
        detail.stage = VIREO_TCP_SERVER_TLS_LOOKUP;
        detail.client_error.primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
        result = c->lookup(c->context, server->pool, lease, &borrowed);
        if (result != VIREO_OK) goto rejected;
        if (borrowed == NULL) { result = VIREO_RESULT_INTERNAL; goto rejected; }
        slot = &server->clients[lease.slot_index];
        if (slot->live) { result = VIREO_RESULT_INTERNAL; goto rejected; }
        *slot = (client_slot_t){.lease = lease, .buffer_bytes = server->tls_pair_bytes, .parent = server,
            .queue_prev = SIZE_MAX, .queue_next = SIZE_MAX};
        detail.stage = VIREO_TCP_SERVER_TLS_ATTACH;
        detail.client_error.primary.stage = VIREO_TCP_SERVER_CLIENT_ATTACH;
        result = c->attach(c->context, borrowed, server->loop,
            VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED,
            client_observed, slot, &detail.client_error.primary.loop_error);
        if (result != VIREO_OK) goto rejected;
        /* ADD后先发布owner可达性和真实账；下面无申请的入队若遇坏链也不能隐藏客户。 */
        slot->live = true; slot->bound = true;
        ++server->client_count; ++server->registered_clients;
        server->buffer_bytes += server->tls_pair_bytes;
        resources.available_resource_bytes -= server->tls_per_connection_bytes;
        out_clients[p->admitted_count++] = lease;
        detail = (vireo_tcp_server_tls_error_t){.stage = VIREO_TCP_SERVER_TLS_QUEUE};
        result = gate != NULL ? gate(gate_context, server, lease) : VIREO_OK;
        if (result == VIREO_OK) result = queue_append(server, lease.slot_index);
        if (result != VIREO_OK) { p->stop_reason = VIREO_TCP_SERVER_ADMIT_ERROR; break; }
        detail = (vireo_tcp_server_tls_error_t){0};
        continue;
rejected:
        p->rejected_count = p->accepted_count - p->admitted_count;
        clean_pending(server, &fd, &connection, &lease, &detail.client_error);
        if (slot != NULL && lease_empty(lease))
            *slot = (client_slot_t){.parent = server, .queue_prev = SIZE_MAX, .queue_next = SIZE_MAX};
        p->stop_reason = VIREO_TCP_SERVER_ADMIT_ERROR;
        break;
    }
    if (!from_serve) server->serving_active = false;
    *out_info = progress;
    return tls_finish(result, &detail, error, saved);
}

vireo_result_t vireo_tcp_server_tls_admit_batch(vireo_tcp_server_t *server,
    vireo_tcp_server_admit_budget_t const *budget, vireo_connection_pool_lease_t *out_clients,
    size_t capacity, vireo_tcp_server_tls_admit_info_t *out_info, vireo_tcp_server_tls_error_t *error)
{ return tls_admit_batch(server, budget, out_clients, capacity, out_info, error, false, NULL, NULL); }

/** 两扫描共享同一代码；公开观察握手/活跃关闭的原due，不缓存裸指针或第二期限。 */
static vireo_result_t tls_scan(vireo_tcp_server_t *server, bool enqueue,
    vireo_monotonic_ns_t now, vireo_tcp_server_tls_poll_report_t *report,
    vireo_tcp_server_tls_error_t *detail)
{
    vireo_tcp_server_tls_stage_t const stage = enqueue ? VIREO_TCP_SERVER_TLS_SCAN_AFTER :
        VIREO_TCP_SERVER_TLS_SCAN_BEFORE;
    detail->stage = stage;
    for (size_t k = 0; k < server->options.connection_capacity; ++k) {
        ++report->scanned_slots;
        client_slot_t const *slot = &server->clients[k];
        if (!slot->live) continue;
        vireo_connection_t *connection = NULL;
        vireo_tls_connection_t *tls = NULL;
        vireo_result_t result = tls_lookup(server, slot->lease, &connection, &tls, detail);
        detail->stage = stage;
        if (result != VIREO_OK) return result;
        vireo_tls_connection_info_t state = {0};
        result = server->tls_ops.inspect(server->tls_ops.context, tls, &state, &detail->tls_error);
        if (result != VIREO_OK) return result;
        vireo_monotonic_ns_t due = 0;
        if (state.handshake_state == VIREO_TLS_HANDSHAKE_ESTABLISHED) {
            vireo_tls_close_info_t close = {0};
            result = server->tls_ops.close_inspect(server->tls_ops.context, tls, &close,
                &detail->tls_error);
            if (result != VIREO_OK) return result;
            if (close.state == VIREO_TLS_CLOSE_NONE || close.state == VIREO_TLS_CLOSE_COMPLETE ||
                close.state == VIREO_TLS_CLOSE_FAILED) continue;
            if (close.state < VIREO_TLS_CLOSE_DRAINING || close.state > VIREO_TLS_CLOSE_WAIT_PEER)
                return VIREO_RESULT_INTERNAL;
            due = close.deadline_ns;
        } else {
            if (state.handshake_state == VIREO_TLS_HANDSHAKE_FAILED) continue;
            if (state.handshake_state != VIREO_TLS_HANDSHAKE_INITIAL &&
                state.handshake_state != VIREO_TLS_HANDSHAKE_HANDSHAKING) return VIREO_RESULT_INTERNAL;
            vireo_tls_handshake_deadline_info_t deadline = {0};
            result = server->tls_ops.deadline(server->tls_ops.context, tls, &deadline, &detail->tls_error);
            if (result != VIREO_OK) return result;
            if (!deadline.armed) return VIREO_RESULT_INTERNAL;
            due = deadline.deadline_ns;
        }
        if (!enqueue && (!report->has_deadline || due < report->nearest_deadline_ns)) {
            report->has_deadline = true;
            report->nearest_deadline_ns = due;
        }
        if (enqueue && now >= due) {
            ++report->expired_clients;
            result = queue_append(server, k);
            if (result != VIREO_OK) return result;
        }
    }
    return VIREO_OK;
}

/**
 * @brief 检查TLS子阶段在途，可信客户轮仅可越过自身scheduling标记
 * @param[in] server 非空存活根短借。
 * @param[in] from_round 仅内部客户轮为true，公共wrapper恒false。
 * @param[in] from_serve 仅可信服务嵌套允许自身serving标记，公共wrapper恒false。
 * @return 存在不允许的在途时true，不修改状态。
 * @note 保持driving/processing等全部保护，无临时撤标记或跨线程许可。
 */
static bool tls_stage_active(vireo_tcp_server_t const *server, bool from_round, bool from_serve)
{
    return server->closing_active || server->shutdown_active || server->processing_active ||
        server->driving_active || (server->serving_active && !from_serve) || server->running_active ||
        (server->scheduling_active && !from_round);
}

/**
 * @brief 复用原握手单步，内部客户轮仅豁免自身调度标记
 * @param[in,out] server 同Reactor存活TLS根，其他在途仍拒绝。
 * @param[in] client 当前完整绑定租约。
 * @param[out] out_info 非空独立握手/关注事实。
 * @param[out] error 可空原完整主/次原因。
 * @param[in] from_round 仅可信内部客户轮为true，公共入口false。
 * @param[in] from_serve 仅原服务core可信调用可越过自身serving，其他保护保持。
 * @return 原握手/观察/MOD分类，不回滚已建立状态。
 * @note 原采时/一次native/首错/恢复合同保持，无owner交接；保持errno。
 */
static vireo_result_t tls_handshake_step(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_handshake_info_t *out_info,
    vireo_tcp_server_tls_error_t *error, bool from_round, bool from_serve)
{
    int const saved = errno;
    vireo_tcp_server_tls_error_t detail = {0};
    vireo_tcp_server_tls_handshake_info_t progress = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || out_info == NULL) goto finish;
    if (server->owned_tls_context == NULL || tls_stage_active(server, from_round, from_serve)) {
        result = VIREO_RESULT_BUSY; goto finish;
    }
    vireo_connection_t *connection = NULL;
    vireo_tls_connection_t *tls = NULL;
    result = tls_lookup(server, client, &connection, &tls, &detail);
    if (result != VIREO_OK) goto finish;
    if (!server->clients[client.slot_index].bound) { result = VIREO_RESULT_NOT_FOUND; goto finish; }
    server->driving_active = true;
    detail.stage = VIREO_TCP_SERVER_TLS_INSPECT;
    vireo_connection_info_t current = {0};
    result = server->client_ops.inspect(server->client_ops.context, connection, &current);
    if (result != VIREO_OK) goto driven;
    progress.interests = current.loop_interests;
    detail.stage = VIREO_TCP_SERVER_TLS_CLOCK;
    result = server->tls_ops.now(server->tls_ops.context, &progress.now_ns, &detail.clock_error);
    if (result != VIREO_OK) goto driven;
    progress.sampled = true;
    detail.stage = VIREO_TCP_SERVER_TLS_HANDSHAKE;
    /* 非法枚举哨兵仅局部使用：原生前拒绝保持输出时，绝不能据全零误同步。 */
    progress.handshake.state = (vireo_tls_handshake_state_t)-1;
    progress.step_called = true;
    result = server->tls_ops.step(server->tls_ops.context, tls, progress.now_ns,
        &progress.handshake, &detail.tls_error);
    if (progress.handshake.state == (vireo_tls_handshake_state_t)-1) {
        progress.handshake = (vireo_tls_handshake_info_t){0}; goto driven;
    }
    progress.handshake_reported = true;
    uint32_t desired = VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED;
    if (progress.handshake.state == VIREO_TLS_HANDSHAKE_ESTABLISHED) {
        desired |= VIREO_EPOLL_INTEREST_READ; progress.application_ready = true;
    } else if (progress.handshake.state == VIREO_TLS_HANDSHAKE_FAILED) desired = 0;
    else if (progress.handshake.state == VIREO_TLS_HANDSHAKE_HANDSHAKING &&
        progress.handshake.wait == VIREO_TLS_HANDSHAKE_WAIT_READ) desired |= VIREO_EPOLL_INTEREST_READ;
    else if (progress.handshake.state == VIREO_TLS_HANDSHAKE_HANDSHAKING &&
        progress.handshake.wait == VIREO_TLS_HANDSHAKE_WAIT_WRITE) desired |= VIREO_EPOLL_INTEREST_WRITE;
    else { result = VIREO_RESULT_INTERNAL; goto driven; }
    if (desired != current.loop_interests) {
        progress.sync_called = true;
        detail.sync_result = server->client_ops.set_interests(server->client_ops.context,
            connection, desired, &detail.sync_loop_error);
        if (detail.sync_result == VIREO_OK) progress.interests = desired;
        else {
            detail.queue_result = queue_append(server, client.slot_index);
            progress.retry_pending = detail.queue_result == VIREO_OK;
            if (result == VIREO_OK) { result = detail.sync_result; detail.stage = VIREO_TCP_SERVER_TLS_SYNC; }
        }
    }
driven:
    server->driving_active = false;
finish:
    if (result == VIREO_OK) detail = (vireo_tcp_server_tls_error_t){0};
    if (out_info != NULL) *out_info = progress;
    return tls_finish(result, &detail, error, saved);
}


vireo_result_t vireo_tcp_server_client_tls_handshake_step(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_handshake_info_t *out_info,
    vireo_tcp_server_tls_error_t *error)
{ return tls_handshake_step(server, client, out_info, error, false, false); }

vireo_result_t vireo_tcp_server_tls_poll_ready_once(vireo_tcp_server_t *server,
    int timeout_ms, size_t max_clients, vireo_tcp_server_ready_client_t *out_clients,
    size_t capacity, vireo_tcp_server_tls_poll_report_t *report, vireo_tcp_server_tls_error_t *error)
{
    int const saved = errno;
    vireo_tcp_server_tls_poll_report_t progress = {0};
    vireo_tcp_server_tls_error_t detail = {0};
    vireo_result_t const result = poll_ready(server, timeout_ms, max_clients, out_clients, capacity,
        report != NULL ? &progress.poll : NULL, NULL, NULL, &progress.listener_events, &progress, &detail);
    if (result == VIREO_OK) detail = (vireo_tcp_server_tls_error_t){0};
    if (report != NULL) *report = progress;
    return tls_finish(result, &detail, error, saved);
}

/* 应用组合层只保存本轮值；没有第二份长期TLS状态、due或待办队列。 */
/**
 * @brief 统一提交应用诊断并恢复最外层errno
 *
 * @param[in] result
 *     已选主要分类。
 * @param[in] detail
 *     必需完整初始化局部值。
 * @param[out] error
 *     可空独立输出，存在则覆盖。
 * @param[in] saved
 *     最外层入口errno。
 *
 * @return
 *     result原样返回，不按次因覆盖。
 *
 * @note 不保存地址、分配或访问网络。
 */
static vireo_result_t tls_application_finish(vireo_result_t result,
    vireo_tcp_server_tls_application_error_t const *detail,
    vireo_tcp_server_tls_application_error_t *error, int saved)
{
    if (error != NULL) *error = *detail;
    errno = saved;
    return result;
}

/**
 * @brief 核验当前绑定与真实TLS阶段，拒绝时不推进数据或修改关注
 *
 * @param[in] server
 *     必需同Reactor资源根，调用者已检查无其他阶段在途。
 * @param[in] client
 *     当前完整数值租约。
 * @param[out] connection
 *     必需局部短借输出，不取得owner。
 * @param[out] tls
 *     必需局部短借输出，仅活至本轮返回。
 * @param[out] io
 *     必需独立应用状态/容量快照。
 * @param[in,out] detail
 *     必需本轮主诊断，失败保存阶段及依赖原因。
 * @param[in] from_round
 *     仅可信内部客户轮允许自身scheduling标记；其他保护保持。
 * @param[in] from_serve
 *     仅本核心serve嵌套允许自己的serving；公共调用恒false。
 *
 * @return
 *     OK、原lookup/观察分类、模式/阶段BUSY或矛盾状态INTERNAL。
 *
 * @note 无网络/分配/MOD；TLS观察清库队列，errno由最外层恢复。
 */
static vireo_result_t tls_application_lookup(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_t **connection,
    vireo_tls_connection_t **tls, vireo_tls_io_info_t *io,
    vireo_tcp_server_tls_application_error_t *detail, bool from_round, bool from_serve)
{
    if (server->owned_tls_context == NULL || tls_stage_active(server, from_round, from_serve))
        return VIREO_RESULT_BUSY;
    detail->stage = VIREO_TCP_SERVER_TLS_APPLICATION_LOOKUP;
    detail->client_error.primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
    vireo_result_t result = find_client(server, client, connection);
    if (result != VIREO_OK) return result;
    if (!server->clients[client.slot_index].bound) return VIREO_RESULT_NOT_FOUND;
    result = vireo_connection_tls_borrow(*connection, tls);
    if (result != VIREO_OK) return result;
    detail->client_error = (vireo_tcp_server_client_error_t){0};
    detail->stage = VIREO_TCP_SERVER_TLS_APPLICATION_INSPECT;
    vireo_tcp_server_tls_ops_t const *ops = &server->tls_ops;
    vireo_tls_connection_info_t handshake = {0};
    result = ops->inspect(ops->context, *tls, &handshake, &detail->tls_error);
    if (result != VIREO_OK) return result;
    if (handshake.handshake_state != VIREO_TLS_HANDSHAKE_ESTABLISHED) {
        if (handshake.handshake_state < VIREO_TLS_HANDSHAKE_INITIAL ||
            handshake.handshake_state > VIREO_TLS_HANDSHAKE_FAILED) return VIREO_RESULT_INTERNAL;
        detail->stage = VIREO_TCP_SERVER_TLS_APPLICATION_NONE;
        return VIREO_RESULT_BUSY;
    }
    vireo_tls_close_info_t close_info = {0};
    result = ops->close_inspect(ops->context, *tls, &close_info, &detail->tls_error);
    if (result != VIREO_OK) return result;
    if (close_info.state != VIREO_TLS_CLOSE_NONE) {
        if (close_info.state < VIREO_TLS_CLOSE_NONE || close_info.state > VIREO_TLS_CLOSE_FAILED)
            return VIREO_RESULT_INTERNAL;
        detail->stage = VIREO_TCP_SERVER_TLS_APPLICATION_NONE;
        return VIREO_RESULT_BUSY;
    }
    result = ops->io_inspect(ops->context, *tls, io, &detail->tls_error);
    if (result != VIREO_OK) return result;
    if (io->state == VIREO_TLS_IO_DISABLED || io->state == VIREO_TLS_IO_PREPARED) {
        detail->stage = VIREO_TCP_SERVER_TLS_APPLICATION_NONE;
        return VIREO_RESULT_BUSY;
    }
    if ((io->state != VIREO_TLS_IO_OPEN && io->state != VIREO_TLS_IO_FAILED) ||
        io->read_size > io->options.read_capacity || io->write_size > io->options.write_capacity)
        return VIREO_RESULT_INTERNAL;
    vireo_connection_info_t current = {0};
    result = server->client_ops.inspect(server->client_ops.context, *connection, &current);
    if (result != VIREO_OK) return result;
    if (!current.loop_attached) return VIREO_RESULT_NOT_FOUND;
    detail->stage = VIREO_TCP_SERVER_TLS_APPLICATION_NONE;
    return VIREO_OK;
}

/**
 * @brief 按原处理停止原因判断一次保守缓存续探，NEED_MORE不会反复排队
 *
 * @param[in] process
 *     可空成功处理报告；NULL表示没有允许续探的处理阶段。
 * @param[in] io
 *     必需真实最终应用快照。
 * @param[in] response_limit
 *     本轮最大响应帧，已经验证可容纳。
 *
 * @return
 *     是否有已停止的缓存处理且写区余量足够再次保守尝试。
 *
 * @note 不peek/CRC检查预算后帧，不保证下一帧完整；无副作用。
 */
static bool tls_processing_pending(vireo_tcp_server_process_info_t const *process,
    vireo_tls_io_info_t const *io, size_t response_limit)
{
    if (process == NULL || io->state != VIREO_TLS_IO_OPEN || io->read_size == 0 ||
        io->write_size > io->options.write_capacity ||
        io->options.write_capacity - io->write_size < response_limit) return false;
    vireo_tcp_server_process_stop_t const stop = process->stop_reason;
    return stop == VIREO_TCP_SERVER_PROCESS_MESSAGE_BUDGET ||
        stop == VIREO_TCP_SERVER_PROCESS_REQUEST_BUDGET ||
        stop == VIREO_TCP_SERVER_PROCESS_RESPONSE_BUDGET ||
        stop == VIREO_TCP_SERVER_PROCESS_WRITE_FULL;
}

/**
 * @brief 一次末尾观察/flow/MOD及去重入队，独立保存同步与队列次因
 *
 * @param[in,out] server
 *     已持有driving_active的本轮资源根。
 * @param[in] client
 *     已核验当前租约。
 * @param[in,out] connection
 *     当前connection短借，只经公开依赖同步mask。
 * @param[in,out] tls
 *     同一TLS短借，状态不复制为长期字段。
 * @param[in] allow_continuation
 *     数据主过程成功时true，失败时只允许MOD恢复入队。
 * @param[in] process
 *     可空已成功处理报告，决定缓存续探。
 * @param[in] response_limit
 *     已验证最大响应长度，无process时不用。
 * @param[out] needs_processing
 *     可空独立提示，按真实最终FIFO派生。
 * @param[out] info
 *     必需typed零局部报告，逐提交填写实际事实。
 * @param[in,out] detail
 *     必需主诊断，只修改sync/queue字段，不覆盖数据首因。
 * @param[in] gate
 *     可空本核心短借故障门，失败不得修改server或伪造提交。
 * @param[in,out] gate_context
 *     可空上下文，仅借至本轮返回，不保存。
 *
 * @return
 *     同步失败优先，其次队列结果；二者独立保存。
 *
 * @note 无native/handler/资源清理；MOD失败不假装回滚，queue_append至多一次。
 */
static vireo_result_t tls_application_sync(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_t *connection,
    vireo_tls_connection_t *tls, bool allow_continuation,
    vireo_tcp_server_process_info_t const *process, size_t response_limit,
    bool *needs_processing, vireo_tcp_server_tls_flow_info_t *info,
    vireo_tcp_server_tls_application_error_t *detail,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *gate_context)
{
    vireo_tcp_server_tls_ops_t const *ops = &server->tls_ops;
    vireo_tls_io_info_t io = {0};
    detail->sync_stage = VIREO_TCP_SERVER_TLS_APPLICATION_INSPECT;
    vireo_result_t result = ops->io_inspect(ops->context, tls, &io, &detail->sync_tls_error);
    if (result != VIREO_OK) goto done;
    if ((io.state != VIREO_TLS_IO_OPEN && io.state != VIREO_TLS_IO_FAILED) ||
        io.read_size > io.options.read_capacity || io.write_size > io.options.write_capacity) {
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }
    detail->sync_stage = VIREO_TCP_SERVER_TLS_APPLICATION_FLOW;
    result = ops->flow_refresh(ops->context, tls, &info->flow, &detail->sync_tls_error);
    if (result != VIREO_OK) goto done;
    info->flow_reported = true;
    detail->sync_stage = VIREO_TCP_SERVER_TLS_APPLICATION_INSPECT;
    vireo_connection_info_t current = {0};
    result = server->client_ops.inspect(server->client_ops.context, connection, &current);
    if (result != VIREO_OK) goto done;
    info->interests = current.loop_interests;
    uint32_t desired = 0;
    if (io.state == VIREO_TLS_IO_OPEN) {
        desired = VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED;
        if (info->flow.want_read) desired |= VIREO_EPOLL_INTEREST_READ;
        if (info->flow.want_write) desired |= VIREO_EPOLL_INTEREST_WRITE;
    }
    if (desired != info->interests) {
        info->sync_called = true;
        detail->sync_stage = VIREO_TCP_SERVER_TLS_APPLICATION_SYNC;
        result = server->client_ops.set_interests(server->client_ops.context, connection,
            desired, &detail->sync_loop_error);
        if (result == VIREO_OK) info->interests = desired;
    }
    bool const processing = allow_continuation && tls_processing_pending(process, &io, response_limit);
    if (needs_processing != NULL) *needs_processing = processing;
    if ((allow_continuation && (processing || info->flow.resume_read || info->flow.resume_write)) ||
        (info->sync_called && result != VIREO_OK)) {
        info->queue_called = true;
        detail->queue_result = gate != NULL ? gate(gate_context, server, client) : VIREO_OK;
        if (detail->queue_result == VIREO_OK)
            detail->queue_result = queue_append(server, client.slot_index);
        info->continuation_pending = detail->queue_result == VIREO_OK;
    }
done:
    detail->sync_result = result;
    if (result == VIREO_OK) {
        detail->sync_stage = VIREO_TCP_SERVER_TLS_APPLICATION_NONE;
        detail->sync_tls_error = (vireo_tls_connection_error_t){0};
        detail->sync_loop_error = (vireo_connection_loop_error_t){0};
    }
    return result != VIREO_OK ? result : detail->queue_result;
}

vireo_result_t vireo_tcp_server_client_tls_flow_refresh_with_gate(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_flow_info_t *out_info,
    vireo_tcp_server_tls_application_error_t *error,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *gate_context)
{
    int const saved = errno;
    vireo_tcp_server_tls_application_error_t detail = {0};
    vireo_tcp_server_tls_flow_info_t progress = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || out_info == NULL) goto finish;
    vireo_connection_t *connection = NULL;
    vireo_tls_connection_t *tls = NULL;
    vireo_tls_io_info_t io = {0};
    result = tls_application_lookup(server, client, &connection, &tls, &io, &detail, false, false);
    if (result != VIREO_OK) goto finish;
    server->driving_active = true;
    result = tls_application_sync(server, client, connection, tls, true, NULL, 0, NULL,
        &progress, &detail, gate, gate_context);
    server->driving_active = false;
    if (result != VIREO_OK) detail.stage = detail.sync_result != VIREO_OK
        ? detail.sync_stage : VIREO_TCP_SERVER_TLS_APPLICATION_QUEUE;
finish:
    if (out_info != NULL) *out_info = progress;
    return tls_application_finish(result, &detail, error, saved);
}

/**
 * @brief 判断原TLS是否真正发布子报告，并检查其预算与枚举不变量
 *
 * @param[in,out] progress
 *     必需局部报告；入口用非法stop哨兵识别原生前保持，未发布时清typed零。
 * @param[in] budget
 *     必需已复制的本方向预算。
 * @param[out] reported
 *     必需独立bool，发布时true。
 * @param[in] result
 *     原调用分类，OK却未发布视为不变量失败。
 *
 * @return
 *     原分类，或报告违约INTERNAL。
 *
 * @note 不把非法枚举传播给caller，不按报告猜测原生已经发送。
 */
static vireo_result_t tls_io_report(vireo_tls_io_progress_t *progress,
    vireo_tls_io_budget_t const *budget, bool *reported, vireo_result_t result)
{
    if (progress->stop_reason == (vireo_tls_io_stop_t)-1) {
        *progress = (vireo_tls_io_progress_t){0};
        return result == VIREO_OK ? VIREO_RESULT_INTERNAL : result;
    }
    *reported = true;
    if (progress->stop_reason < VIREO_TLS_IO_STOP_WOULD_BLOCK ||
        progress->stop_reason > VIREO_TLS_IO_STOP_FLOW_PAUSED ||
        progress->wait < VIREO_TLS_IO_WAIT_NONE || progress->wait > VIREO_TLS_IO_WAIT_WRITE ||
        progress->bytes > budget->max_bytes || progress->native_calls > budget->max_native_calls) {
        *progress = (vireo_tls_io_progress_t){0};
        *reported = false;
        return VIREO_RESULT_INTERNAL;
    }
    return result;
}

/** 已核容量上的稳定重试下限；原生scratch上限是公共TLS常量。 */
static size_t tls_minimum_budget(size_t capacity)
{ return capacity < VIREO_TLS_IO_SCRATCH_BYTES ? capacity : VIREO_TLS_IO_SCRATCH_BYTES; }

/**
 * @brief 复用原应用有界核心并保留整轮调度保护
 * @param[in,out] server 存活TLS根，无其他不允许的在途。
 * @param[in] client 当前完整租约。
 * @param[in] options 原帧上限，入口复制。
 * @param[in] budget 原三预算，入口复制且各自本轮只用一次。
 * @param[in,out] wire_workspace caller独立响应工作区短借。
 * @param[in] workspace_capacity 实际字节容量。
 * @param[in] handler 原有界同步回调。
 * @param[in,out] context 可空handler短借上下文。
 * @param[out] out_info 必需原阶段事实报告。
 * @param[out] error 可空原完整主/次诊断。
 * @param[in] gate 可空原本core排队故障门。
 * @param[in,out] gate_context gate短借上下文。
 * @param[in] from_round 仅内部客户轮为true，公共wrapper为false。
 * @param[in] from_serve 仅原服务core可信调用可越过自身serving，其他保护保持。
 * @return 原应用drive分类，不重放或回滚已经提交的业务。
 * @note 仅改变可信组合门禁，原预算/重试/flow合同保持；保持errno。
 */
static vireo_result_t tls_drive(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_tls_drive_budget_t const *budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_drive_info_t *out_info, vireo_tcp_server_tls_application_error_t *error,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *gate_context, bool from_round, bool from_serve)
{
    int const saved = errno;
    vireo_tcp_server_tls_application_error_t detail = {0};
    vireo_tcp_server_tls_drive_info_t progress = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || options == NULL || budget == NULL || wire_workspace == NULL ||
        handler == NULL || out_info == NULL) goto finish;
    vireo_tcp_server_process_options_t const limits = *options;
    vireo_tcp_server_tls_drive_budget_t const allowance = *budget;
    size_t const head = VIREO_PROTOCOL_HEADER_SIZE;
    result = VIREO_RESULT_RANGE;
    if (limits.max_request_frame_bytes < head || limits.max_response_frame_bytes < head ||
        limits.max_request_frame_bytes - head > VIREO_PROTOCOL_MAX_BODY_SIZE ||
        limits.max_response_frame_bytes - head > VIREO_PROTOCOL_MAX_BODY_SIZE ||
        workspace_capacity < limits.max_response_frame_bytes ||
        allowance.receive.max_bytes == 0 || allowance.receive.max_native_calls == 0 ||
        allowance.send.max_bytes == 0 || allowance.send.max_native_calls == 0 ||
        allowance.process.max_messages == 0 ||
        allowance.process.max_request_bytes < limits.max_request_frame_bytes ||
        allowance.process.max_response_bytes < limits.max_response_frame_bytes) goto finish;
    vireo_connection_t *connection = NULL;
    vireo_tls_connection_t *tls = NULL;
    vireo_tls_io_info_t io = {0};
    result = tls_application_lookup(server, client, &connection, &tls, &io, &detail, from_round, from_serve);
    if (result != VIREO_OK) goto finish;
    result = VIREO_RESULT_RANGE;
    if (limits.max_request_frame_bytes > io.options.max_read_unit_bytes ||
        limits.max_request_frame_bytes > io.options.read_capacity ||
        limits.max_response_frame_bytes > io.options.write_capacity ||
        allowance.receive.max_bytes < tls_minimum_budget(io.options.read_capacity) ||
        allowance.send.max_bytes < tls_minimum_budget(io.options.write_capacity) ||
        allowance.receive.max_bytes < io.read_retry_bytes ||
        allowance.send.max_bytes < io.write_retry_bytes) goto finish;
    server->driving_active = true;
    vireo_tcp_server_tls_ops_t const *ops = &server->tls_ops;
    vireo_tls_io_flow_t flow = {0};
    if (io.state == VIREO_TLS_IO_FAILED) {
        /* 公开receive重现缓存首错，FAILED保证零native，不能进入handler。 */
        detail.stage = VIREO_TCP_SERVER_TLS_APPLICATION_RECEIVE;
        goto receive;
    }
    detail.stage = VIREO_TCP_SERVER_TLS_APPLICATION_FLOW;
    result = ops->flow_refresh(ops->context, tls, &flow, &detail.tls_error);
    if (result != VIREO_OK) goto final_sync;
    if (flow.priority_retry == VIREO_TLS_IO_OPERATION_WRITE) {
        detail.stage = VIREO_TCP_SERVER_TLS_APPLICATION_SEND;
        progress.send_called = true;
        progress.send.stop_reason = (vireo_tls_io_stop_t)-1;
        result = ops->send(ops->context, tls, &allowance.send, &progress.send, &detail.tls_error);
        result = tls_io_report(&progress.send, &allowance.send, &progress.send_reported, result);
        if (result != VIREO_OK) goto final_sync;
        detail.stage = VIREO_TCP_SERVER_TLS_APPLICATION_FLOW;
        result = ops->flow_refresh(ops->context, tls, &flow, &detail.tls_error);
        if (result != VIREO_OK) goto final_sync;
    }
    if (flow.application_read_enabled || flow.priority_retry == VIREO_TLS_IO_OPERATION_READ) {
receive:
        detail.stage = VIREO_TCP_SERVER_TLS_APPLICATION_RECEIVE;
        progress.receive_called = true;
        progress.receive.stop_reason = (vireo_tls_io_stop_t)-1;
        result = ops->receive(ops->context, tls, &allowance.receive, &progress.receive, &detail.tls_error);
        result = tls_io_report(&progress.receive, &allowance.receive, &progress.receive_reported, result);
        if (result != VIREO_OK) goto final_sync;
    }
    detail.stage = VIREO_TCP_SERVER_TLS_APPLICATION_PROCESS;
    progress.process_called = true;
    result = process_client(server, client, &limits, &allowance.process, wire_workspace,
        workspace_capacity, handler, context, &progress.process, &detail.client_error, true);
    if (result != VIREO_OK) goto final_sync;
    if (!progress.send_called) {
        detail.stage = VIREO_TCP_SERVER_TLS_APPLICATION_FLOW;
        result = ops->flow_refresh(ops->context, tls, &flow, &detail.tls_error);
        if (result != VIREO_OK) goto final_sync;
        if (flow.want_write || flow.priority_retry == VIREO_TLS_IO_OPERATION_WRITE) {
            /* READ-WANT_WRITE也需要WRITE关注，但不能趁机执行另一原操作。 */
            if (flow.priority_retry != VIREO_TLS_IO_OPERATION_READ) {
                detail.stage = VIREO_TCP_SERVER_TLS_APPLICATION_SEND;
                progress.send_called = true;
                progress.send.stop_reason = (vireo_tls_io_stop_t)-1;
                result = ops->send(ops->context, tls, &allowance.send, &progress.send, &detail.tls_error);
                result = tls_io_report(&progress.send, &allowance.send, &progress.send_reported, result);
            }
        }
    }
final_sync:
    {
        vireo_result_t const synced = tls_application_sync(server, client, connection, tls,
            result == VIREO_OK, result == VIREO_OK && progress.process_called ? &progress.process : NULL,
            limits.max_response_frame_bytes, &progress.needs_processing, &progress.sync, &detail,
            gate, gate_context);
        if (result == VIREO_OK) {
            result = synced;
            detail.stage = detail.sync_result != VIREO_OK ? detail.sync_stage :
                (detail.queue_result != VIREO_OK ? VIREO_TCP_SERVER_TLS_APPLICATION_QUEUE :
                    VIREO_TCP_SERVER_TLS_APPLICATION_NONE);
        }
    }
    server->driving_active = false;
finish:
    if (result == VIREO_OK) detail = (vireo_tcp_server_tls_application_error_t){0};
    if (out_info != NULL) *out_info = progress;
    return tls_application_finish(result, &detail, error, saved);
}

/* 公共入口不开放故障门；本core测试的短借hook不改变生产依赖表。 */
vireo_result_t vireo_tcp_server_client_tls_drive_with_gate(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_tls_drive_budget_t const *budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_drive_info_t *out_info, vireo_tcp_server_tls_application_error_t *error,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *gate_context)
{ return tls_drive(server, client, options, budget, wire_workspace, workspace_capacity,
    handler, context, out_info, error, gate, gate_context, false, false); }

vireo_result_t vireo_tcp_server_client_tls_flow_refresh(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_flow_info_t *out_info,
    vireo_tcp_server_tls_application_error_t *error)
{
    return vireo_tcp_server_client_tls_flow_refresh_with_gate(server, client, out_info, error, NULL, NULL);
}

vireo_result_t vireo_tcp_server_client_tls_drive(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_process_options_t const *options,
    vireo_tcp_server_tls_drive_budget_t const *budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_drive_info_t *out_info, vireo_tcp_server_tls_application_error_t *error)
{
    return vireo_tcp_server_client_tls_drive_with_gate(server, client, options, budget,
        wire_workspace, workspace_capacity, handler, context, out_info, error, NULL, NULL);
}

/**
 * @brief 发布完整诊断并恢复入口errno。
 * @param[in] result 已决定的主分类。
 * @param[in] detail 必需独立typed诊断短借。
 * @param[out] error 可空独立可写诊断。
 * @param[in] saved 入口errno。
 * @return 原result，无资源交接或其他副作用。
 */
static vireo_result_t tls_close_finish(vireo_result_t result,
    vireo_tcp_server_tls_close_error_t const *detail,
    vireo_tcp_server_tls_close_error_t *error, int saved)
{
    if (error != NULL) *error = *detail;
    errno = saved;
    return result;
}

/**
 * @brief 在入口持有driving_active后取得短借并核三阶段及真实绑定。
 * @param[in,out] server 本轮TLS资源根，调用者已禁止重入。
 * @param[in] client 当前完整租约。
 * @param[out] connection 必需独立短借，不跨release。
 * @param[out] tls 必需独立TLS短借，不跨release。
 * @param[out] io 必需独立应用容量/阶段快照。
 * @param[out] close 必需独立关闭快照。
 * @param[in,out] detail 必需本轮主诊断，仅记录前置失败。
 * @return 原观察/租约分类；阶段不满足BUSY，矛盾状态INTERNAL。
 * @note 不采时/native/MOD/移交owner，外层恢复errno。
 */
static vireo_result_t tls_close_lookup(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_t **connection,
    vireo_tls_connection_t **tls, vireo_tls_io_info_t *io, vireo_tls_close_info_t *close,
    vireo_tcp_server_tls_close_error_t *detail)
{
    detail->stage = VIREO_TCP_SERVER_TLS_CLOSE_LOOKUP;
    detail->client_error.primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
    vireo_result_t result = find_client(server, client, connection);
    if (result != VIREO_OK) return result;
    if (!server->clients[client.slot_index].bound) return VIREO_RESULT_NOT_FOUND;
    result = vireo_connection_tls_borrow(*connection, tls);
    if (result != VIREO_OK) return result;
    detail->client_error = (vireo_tcp_server_client_error_t){0};
    detail->stage = VIREO_TCP_SERVER_TLS_CLOSE_INSPECT;
    vireo_tcp_server_tls_ops_t const *ops = &server->tls_ops;
    vireo_tls_connection_info_t handshake = {0};
    result = ops->inspect(ops->context, *tls, &handshake, &detail->tls_error);
    if (result != VIREO_OK) return result;
    if (handshake.handshake_state < VIREO_TLS_HANDSHAKE_INITIAL ||
        handshake.handshake_state > VIREO_TLS_HANDSHAKE_FAILED) return VIREO_RESULT_INTERNAL;
    if (handshake.handshake_state != VIREO_TLS_HANDSHAKE_ESTABLISHED) return VIREO_RESULT_BUSY;
    result = ops->close_inspect(ops->context, *tls, close, &detail->tls_error);
    if (result != VIREO_OK) return result;
    if (close->state < VIREO_TLS_CLOSE_NONE || close->state > VIREO_TLS_CLOSE_FAILED)
        return VIREO_RESULT_INTERNAL;
    result = ops->io_inspect(ops->context, *tls, io, &detail->tls_error);
    if (result != VIREO_OK) return result;
    if (io->state == VIREO_TLS_IO_DISABLED || io->state == VIREO_TLS_IO_PREPARED)
        return VIREO_RESULT_BUSY;
    if ((io->state != VIREO_TLS_IO_OPEN && io->state != VIREO_TLS_IO_FAILED) ||
        io->read_size > io->options.read_capacity || io->write_size > io->options.write_capacity)
        return VIREO_RESULT_INTERNAL;
    vireo_connection_info_t current = {0};
    result = server->client_ops.inspect(server->client_ops.context, *connection, &current);
    if (result != VIREO_OK) return result;
    if (!current.loop_attached) return VIREO_RESULT_NOT_FOUND;
    detail->stage = VIREO_TCP_SERVER_TLS_CLOSE_NONE;
    return VIREO_OK;
}

/**
 * @brief 一次最终关闭观察、实际MOD及去重入队，保留全部次因。
 * @param[in,out] server 本轮已持driving_active资源根。
 * @param[in] client 已核有效租约。
 * @param[in,out] connection 同一存活短借，只经公开依赖修改mask。
 * @param[in] tls 同一存活TLS短借，只观察。
 * @param[in] allow_continuation 主过程成功才正常续排；MOD失败仍可恢复入队。
 * @param[out] info 必需typed零报告，逐阶段填写真实事实。
 * @param[in,out] detail 必需诊断，只改sync/queue，不覆盖主因。
 * @param[in] gate 可空本server单次只读故障门。
 * @param[in,out] context 可空gate上下文，仅借至返回，不保存。
 * @return 同步错误优先于队列错误，无回滚/native/handler/owner移交。
 */
static vireo_result_t tls_close_sync(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_connection_t *connection,
    vireo_tls_connection_t const *tls, bool allow_continuation,
    vireo_tcp_server_tls_close_flow_info_t *info, vireo_tcp_server_tls_close_error_t *detail,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *context)
{
    detail->sync_stage = VIREO_TCP_SERVER_TLS_CLOSE_INSPECT;
    vireo_result_t result = server->tls_ops.close_inspect(server->tls_ops.context, tls,
        &info->close, &detail->sync_tls_error);
    if (result != VIREO_OK) goto done;
    info->close_reported = true;
    if (info->close.state < VIREO_TLS_CLOSE_DRAINING || info->close.state > VIREO_TLS_CLOSE_FAILED ||
        info->close.wait < VIREO_TLS_IO_WAIT_NONE || info->close.wait > VIREO_TLS_IO_WAIT_WRITE) {
        result = VIREO_RESULT_INTERNAL; goto done;
    }
    vireo_connection_info_t current = {0};
    result = server->client_ops.inspect(server->client_ops.context, connection, &current);
    if (result != VIREO_OK) goto done;
    info->interests = current.loop_interests;
    if (!current.loop_attached) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    bool const active = info->close.state <= VIREO_TLS_CLOSE_WAIT_PEER;
    bool const runnable = active && !info->close.needs_consume;
    uint32_t desired = 0;
    if (runnable) {
        desired = VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED;
        if (info->close.wait == VIREO_TLS_IO_WAIT_READ) desired |= VIREO_EPOLL_INTEREST_READ;
        if (info->close.wait == VIREO_TLS_IO_WAIT_WRITE) desired |= VIREO_EPOLL_INTEREST_WRITE;
    }
    if (desired != info->interests) {
        info->sync_called = true;
        detail->sync_stage = VIREO_TCP_SERVER_TLS_CLOSE_SYNC;
        result = server->client_ops.set_interests(server->client_ops.context, connection,
            desired, &detail->sync_loop_error);
        if (result == VIREO_OK) info->interests = desired;
    }
    if ((allow_continuation && runnable && info->close.resume) ||
        (info->sync_called && result != VIREO_OK)) {
        info->queue_called = true;
        detail->queue_result = gate != NULL ? gate(context, server, client) : VIREO_OK;
        if (detail->queue_result == VIREO_OK)
            detail->queue_result = queue_append(server, client.slot_index);
        info->continuation_pending = detail->queue_result == VIREO_OK;
    }
done:
    detail->sync_result = result;
    if (result == VIREO_OK) {
        detail->sync_stage = VIREO_TCP_SERVER_TLS_CLOSE_NONE;
        detail->sync_tls_error = (vireo_tls_connection_error_t){0};
        detail->sync_loop_error = (vireo_connection_loop_error_t){0};
    }
    return result != VIREO_OK ? result : detail->queue_result;
}

/**
 * @brief 最终同步次因提升阶段；已有request/step首因时不使用。
 * @param[in] detail 必需独立局部诊断，只读短借。
 * @return 同步失败阶段，否则QUEUE；无状态修改/资源交接。
 */
static vireo_tcp_server_tls_close_stage_t tls_close_sync_stage(
    vireo_tcp_server_tls_close_error_t const *detail)
{ return detail->sync_result != VIREO_OK ? detail->sync_stage : VIREO_TCP_SERVER_TLS_CLOSE_QUEUE; }

vireo_result_t vireo_tcp_server_client_tls_close_request_with_gate(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint64_t timeout_ns,
    vireo_tcp_server_tls_close_request_info_t *out_info, vireo_tcp_server_tls_close_error_t *error,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *context)
{
    int const saved = errno;
    vireo_tcp_server_tls_close_request_info_t info = {0};
    vireo_tcp_server_tls_close_error_t detail = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || out_info == NULL || timeout_ns == 0) goto finish;
    if (server->owned_tls_context == NULL || auxiliary_active(server) || server->running_active) {
        result = VIREO_RESULT_BUSY; goto finish;
    }
    server->driving_active = true;
    vireo_connection_t *connection = NULL;
    vireo_tls_connection_t *tls = NULL;
    vireo_tls_io_info_t io = {0};
    vireo_tls_close_info_t close = {0};
    result = tls_close_lookup(server, client, &connection, &tls, &io, &close, &detail);
    if (result != VIREO_OK) goto driven;
    if (close.state != VIREO_TLS_CLOSE_NONE) { result = VIREO_RESULT_BUSY; goto driven; }
    vireo_tcp_server_tls_ops_t const *ops = &server->tls_ops;
    if (io.state != VIREO_TLS_IO_FAILED) {
        detail.stage = VIREO_TCP_SERVER_TLS_CLOSE_CLOCK;
        result = ops->now(ops->context, &info.now_ns, &detail.clock_error);
        if (result != VIREO_OK) goto driven;
        info.sampled = true;
        detail.stage = VIREO_TCP_SERVER_TLS_CLOSE_DEADLINE;
        result = vireo_clock_deadline_after(info.now_ns, timeout_ns, &info.deadline_ns);
        if (result != VIREO_OK) goto driven;
        info.deadline_computed = true;
    }
    detail.stage = VIREO_TCP_SERVER_TLS_CLOSE_REQUEST;
    info.request_called = true;
    result = ops->close_request(ops->context, tls, info.now_ns, info.deadline_ns, &detail.tls_error);
    if (result != VIREO_OK) goto driven;
    /* FAILED应用必须拒绝，不接受违约依赖假装成功封口。 */
    if (io.state == VIREO_TLS_IO_FAILED) { result = VIREO_RESULT_INTERNAL; goto driven; }
    info.requested = true;
    detail.stage = VIREO_TCP_SERVER_TLS_CLOSE_NONE;
    result = tls_close_sync(server, client, connection, tls, true, &info.sync, &detail, gate, context);
    if (result != VIREO_OK) detail.stage = tls_close_sync_stage(&detail);
driven:
    server->driving_active = false;
finish:
    if (out_info != NULL) *out_info = info;
    return tls_close_finish(result, &detail, error, saved);
}

/**
 * @brief 复用原关闭单步并保持客户轮外层保护
 * @param[in,out] server 同Reactor存活TLS根。
 * @param[in] client 当前已绑定且已请求关闭的完整租约。
 * @param[in] max_bytes 原正关闭单步字节预算。
 * @param[out] out_info 必需原关闭/同步事实。
 * @param[out] error 可空原完整主/次原因。
 * @param[in] gate 可空本core排队故障门。
 * @param[in,out] context gate短借上下文。
 * @param[in] from_round 仅可信内部客户轮true，其他在途仍拒绝。
 * @param[in] from_serve 仅原服务core可信调用可越过自身serving，其他保护保持。
 * @return 原关闭/采时/MOD分类，终态不执行native。
 * @note 不消费尾部、不调用handler/归还；保持原固定due及入口errno。
 */
static vireo_result_t tls_close_step(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, size_t max_bytes,
    vireo_tcp_server_tls_close_step_info_t *out_info, vireo_tcp_server_tls_close_error_t *error,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *context, bool from_round, bool from_serve)
{
    int const saved = errno;
    vireo_tcp_server_tls_close_step_info_t info = {0};
    vireo_tcp_server_tls_close_error_t detail = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || out_info == NULL) goto finish;
    if (server->owned_tls_context == NULL || tls_stage_active(server, from_round, from_serve)) {
        result = VIREO_RESULT_BUSY; goto finish;
    }
    server->driving_active = true;
    vireo_connection_t *connection = NULL;
    vireo_tls_connection_t *tls = NULL;
    vireo_tls_io_info_t io = {0};
    vireo_tls_close_info_t close = {0};
    result = tls_close_lookup(server, client, &connection, &tls, &io, &close, &detail);
    if (result != VIREO_OK) goto driven;
    if (close.state == VIREO_TLS_CLOSE_NONE) { result = VIREO_RESULT_BUSY; goto driven; }
    if (max_bytes == 0 || max_bytes < tls_minimum_budget(io.options.read_capacity) ||
        max_bytes < tls_minimum_budget(io.options.write_capacity)) {
        result = VIREO_RESULT_RANGE; goto driven;
    }
    vireo_tcp_server_tls_ops_t const *ops = &server->tls_ops;
    if (close.state <= VIREO_TLS_CLOSE_WAIT_PEER) {
        detail.stage = VIREO_TCP_SERVER_TLS_CLOSE_CLOCK;
        result = ops->now(ops->context, &info.now_ns, &detail.clock_error);
        if (result != VIREO_OK) goto driven;
        info.sampled = true;
    }
    detail.stage = VIREO_TCP_SERVER_TLS_CLOSE_STEP;
    info.step_called = true;
    info.progress.stop_reason = (vireo_tls_close_stop_t)-1;
    result = ops->close_step_at(ops->context, tls, info.now_ns, max_bytes,
        &info.progress, &detail.tls_error);
    if (info.progress.stop_reason == (vireo_tls_close_stop_t)-1) {
        info.progress = (vireo_tls_close_progress_t){0};
        if (result == VIREO_OK) result = VIREO_RESULT_INTERNAL;
    } else if (info.progress.stop_reason < VIREO_TLS_CLOSE_STOP_PROGRESS ||
        info.progress.stop_reason > VIREO_TLS_CLOSE_STOP_ERROR ||
        info.progress.read_bytes > max_bytes || info.progress.write_bytes > max_bytes ||
        info.progress.info.state < VIREO_TLS_CLOSE_DRAINING ||
        info.progress.info.state > VIREO_TLS_CLOSE_FAILED) {
        info.progress = (vireo_tls_close_progress_t){0};
        result = VIREO_RESULT_INTERNAL;
    } else info.progress_reported = true;
    if (result == VIREO_OK) detail.stage = VIREO_TCP_SERVER_TLS_CLOSE_NONE;
    vireo_result_t const sync = tls_close_sync(server, client, connection, tls, result == VIREO_OK,
        &info.sync, &detail, gate, context);
    if (result == VIREO_OK && sync != VIREO_OK) { result = sync; detail.stage = tls_close_sync_stage(&detail); }
driven:
    server->driving_active = false;
finish:
    if (out_info != NULL) *out_info = info;
    return tls_close_finish(result, &detail, error, saved);
}

vireo_result_t vireo_tcp_server_client_tls_close_step_with_gate(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, size_t max_bytes,
    vireo_tcp_server_tls_close_step_info_t *out_info, vireo_tcp_server_tls_close_error_t *error,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *context)
{ return tls_close_step(server, client, max_bytes, out_info, error, gate, context, false, false); }

vireo_result_t vireo_tcp_server_client_tls_close_flow_refresh_with_gate(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_close_flow_info_t *out_info,
    vireo_tcp_server_tls_close_error_t *error, vireo_tcp_server_tls_application_queue_gate_t gate,
    void *context)
{
    int const saved = errno;
    vireo_tcp_server_tls_close_flow_info_t info = {0};
    vireo_tcp_server_tls_close_error_t detail = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || out_info == NULL) goto finish;
    if (server->owned_tls_context == NULL || auxiliary_active(server) || server->running_active) {
        result = VIREO_RESULT_BUSY; goto finish;
    }
    server->driving_active = true;
    vireo_connection_t *connection = NULL;
    vireo_tls_connection_t *tls = NULL;
    vireo_tls_io_info_t io = {0};
    vireo_tls_close_info_t close = {0};
    result = tls_close_lookup(server, client, &connection, &tls, &io, &close, &detail);
    if (result == VIREO_OK && close.state == VIREO_TLS_CLOSE_NONE) result = VIREO_RESULT_BUSY;
    if (result == VIREO_OK) {
        result = tls_close_sync(server, client, connection, tls, true, &info, &detail, gate, context);
        if (result != VIREO_OK) detail.stage = tls_close_sync_stage(&detail);
    }
    server->driving_active = false;
finish:
    if (out_info != NULL) *out_info = info;
    return tls_close_finish(result, &detail, error, saved);
}

vireo_result_t vireo_tcp_server_client_tls_close_request(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint64_t timeout_ns,
    vireo_tcp_server_tls_close_request_info_t *out_info, vireo_tcp_server_tls_close_error_t *error)
{ return vireo_tcp_server_client_tls_close_request_with_gate(server, client, timeout_ns, out_info,
    error, NULL, NULL); }

vireo_result_t vireo_tcp_server_client_tls_close_step(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, size_t max_bytes,
    vireo_tcp_server_tls_close_step_info_t *out_info, vireo_tcp_server_tls_close_error_t *error)
{ return vireo_tcp_server_client_tls_close_step_with_gate(server, client, max_bytes, out_info,
    error, NULL, NULL); }

vireo_result_t vireo_tcp_server_client_tls_close_flow_refresh(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_close_flow_info_t *out_info,
    vireo_tcp_server_tls_close_error_t *error)
{ return vireo_tcp_server_client_tls_close_flow_refresh_with_gate(server, client, out_info, error,
    NULL, NULL); }

/**
 * @brief 在等待前按固定TLS容量核共同预算，不根据当前阶段放宽参数
 * @param[in] server 非空TLS根短借，只读固定配置。
 * @param[in] o 非空入口复制的选项。
 * @param[in] workspace 字节容量，须容纳最大响应整帧。
 * @return 预算和帧兼容时true，无观察/native/分配。
 * @note 差值只在验证帧不小于头后计算；locked请求仍由原客户核心核验。
 */
static bool tls_round_values(vireo_tcp_server_t const *server,
    vireo_tcp_server_tls_round_options_t const *o, size_t workspace)
{
    size_t const head = VIREO_PROTOCOL_HEADER_SIZE;
    vireo_tls_io_options_t const *io = &server->tls_options.io;
    return o->process.max_request_frame_bytes >= head && o->process.max_response_frame_bytes >= head &&
        o->process.max_request_frame_bytes - head <= VIREO_PROTOCOL_MAX_BODY_SIZE &&
        o->process.max_response_frame_bytes - head <= VIREO_PROTOCOL_MAX_BODY_SIZE &&
        o->process.max_request_frame_bytes <= io->read_capacity &&
        o->process.max_request_frame_bytes <= io->max_read_unit_bytes &&
        o->process.max_response_frame_bytes <= io->write_capacity &&
        workspace >= o->process.max_response_frame_bytes &&
        o->drive.receive.max_native_calls > 0 && o->drive.send.max_native_calls > 0 &&
        o->drive.receive.max_bytes >= tls_minimum_budget(io->read_capacity) &&
        o->drive.send.max_bytes >= tls_minimum_budget(io->write_capacity) &&
        o->drive.process.max_messages > 0 &&
        o->drive.process.max_request_bytes >= o->process.max_request_frame_bytes &&
        o->drive.process.max_response_bytes >= o->process.max_response_frame_bytes &&
        o->close_max_bytes >= tls_minimum_budget(io->read_capacity) &&
        o->close_max_bytes >= tls_minimum_budget(io->write_capacity);
}

/**
 * @brief 按当前完整身份和真实公开TLS状态分派唯一阶段
 * @param[in,out] server 非空TLS根，整轮scheduling_active保持。
 * @param[in] o 已验证局部配置，短借至返回。
 * @param[in,out] workspace caller独立响应工作区短借。
 * @param[in] capacity 工作区实际容量。
 * @param[in] handler 原有界同步回调，不修改同根。
 * @param[in,out] context 可空handler短借上下文。
 * @param[in,out] turn 已撤取客户的局部typed报告，尚无阶段进度。
 * @param[in] gate 可空本core交接排队测试门，只观察、不改变资源。
 * @param[in,out] gate_context gate短借上下文。
 * @param[in] from_serve 仅可信服务轮传递的外层保护来源，不放宽其他在途。
 * @return 原阶段或交接分类；成功typed清诊断，失败保留已提交事实。
 * @note 无第二owner/状态缓存；关闭不自动消费/handler/归还，原恢复次因保持。
 */
static vireo_result_t tls_round_dispatch(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_round_options_t const *o, uint8_t *workspace, size_t capacity,
    vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_turn_result_t *turn,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *gate_context, bool from_serve)
{
    vireo_tcp_server_tls_round_error_t *e = &turn->error;
    vireo_connection_t *connection = NULL;
    vireo_tls_connection_t *tls = NULL;
    e->stage = VIREO_TCP_SERVER_TLS_ROUND_LOOKUP;
    e->client_error.primary.stage = VIREO_TCP_SERVER_CLIENT_LOOKUP;
    vireo_result_t result = find_client(server, turn->client, &connection);
    if (result != VIREO_OK) return result;
    if (!server->clients[turn->client.slot_index].bound) return VIREO_RESULT_NOT_FOUND;
    result = vireo_connection_tls_borrow(connection, &tls);
    if (result != VIREO_OK) return result;
    e->client_error = (vireo_tcp_server_client_error_t){0};
    e->stage = VIREO_TCP_SERVER_TLS_ROUND_INSPECT;
    e->client_error.primary.stage = VIREO_TCP_SERVER_CLIENT_INSPECT;
    vireo_connection_info_t current = {0};
    result = server->client_ops.inspect(server->client_ops.context, connection, &current);
    if (result != VIREO_OK) return result;
    if (!current.loop_attached) return VIREO_RESULT_NOT_FOUND;
    e->client_error = (vireo_tcp_server_client_error_t){0};
    vireo_tls_connection_info_t state = {0};
    result = server->tls_ops.inspect(server->tls_ops.context, tls, &state, &e->tls_error);
    if (result != VIREO_OK) return result;
    if (state.handshake_state < VIREO_TLS_HANDSHAKE_INITIAL ||
        state.handshake_state > VIREO_TLS_HANDSHAKE_FAILED) return VIREO_RESULT_INTERNAL;
    if (state.handshake_state != VIREO_TLS_HANDSHAKE_ESTABLISHED) {
        turn->path = VIREO_TCP_SERVER_TLS_TURN_HANDSHAKE;
        e->stage = VIREO_TCP_SERVER_TLS_ROUND_HANDSHAKE;
        result = tls_handshake_step(server, turn->client, &turn->handshake, &e->handshake_error, true, from_serve);
        if (result == VIREO_OK && turn->handshake.application_ready) {
            e->stage = VIREO_TCP_SERVER_TLS_ROUND_HANDOFF_QUEUE;
            result = gate != NULL ? gate(gate_context, server, turn->client) : VIREO_OK;
            if (result == VIREO_OK) result = queue_append(server, turn->client.slot_index);
        }
    } else {
        vireo_tls_close_info_t close = {0};
        result = server->tls_ops.close_inspect(server->tls_ops.context, tls, &close, &e->tls_error);
        if (result != VIREO_OK) return result;
        if (close.state < VIREO_TLS_CLOSE_NONE || close.state > VIREO_TLS_CLOSE_FAILED)
            return VIREO_RESULT_INTERNAL;
        if (close.state == VIREO_TLS_CLOSE_NONE) {
            turn->path = VIREO_TCP_SERVER_TLS_TURN_APPLICATION;
            e->stage = VIREO_TCP_SERVER_TLS_ROUND_APPLICATION;
            result = tls_drive(server, turn->client, &o->process, &o->drive, workspace,
                capacity, handler, context, &turn->application, &e->application_error, NULL, NULL, true, from_serve);
        } else {
            turn->path = VIREO_TCP_SERVER_TLS_TURN_CLOSE;
            e->stage = VIREO_TCP_SERVER_TLS_ROUND_CLOSE;
            result = tls_close_step(server, turn->client, o->close_max_bytes,
                &turn->close, &e->close_error, NULL, NULL, true, from_serve);
        }
    }
    if (result == VIREO_OK) *e = (vireo_tcp_server_tls_round_error_t){0};
    return result;
}

/**
 * @brief 原客户轮与服务轮共用的有限TLS调度core
 * @param[in,out] server 原TLS根，可信serve可已持serving，不撤标记。
 * @param[in] options 原完整数值选项，入口复制。
 * @param[in,out] wire_workspace 原独立响应工作区短借。
 * @param[in] workspace_capacity 原实际字节数。
 * @param[in] handler 原有界非阻塞回调，禁止同根可变重入。
 * @param[in,out] context 原可空短借上下文。
 * @param[out] out_turns 原真实撤取前缀，含首失败客户。
 * @param[in] turn_capacity 原正数组容量。
 * @param[out] out_info 原每可写路径事实。
 * @param[out] error 原可空完整typed错误。
 * @param[in] gate 可空握手交接只读排队故障门。
 * @param[in,out] gate_context gate调用期短借。
 * @param[in] from_serve 仅可信serve为true，公共wrapper恒false。
 * @return 原客户轮分类，首错suffix/两扫描/停止语义保持。
 * @note 只取得自身scheduling保护并原样解除；外层serving保持，恢复errno。
 */
static vireo_result_t tls_run_once(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_round_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_turn_result_t *out_turns, size_t turn_capacity,
    vireo_tcp_server_tls_round_info_t *out_info, vireo_tcp_server_tls_round_error_t *error,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *gate_context, bool from_serve)
{
    int const saved = errno;
    vireo_tcp_server_tls_round_info_t progress = {0};
    vireo_tcp_server_tls_round_error_t detail = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || options == NULL || wire_workspace == NULL || handler == NULL ||
        out_turns == NULL || out_info == NULL) goto finish;
    vireo_tcp_server_tls_round_options_t const o = *options;
    if (o.timeout_ms < 0) goto finish;
    if (server->owned_tls_context == NULL || tls_stage_active(server, false, from_serve)) {
        result = VIREO_RESULT_BUSY; goto finish;
    }
    if (turn_capacity == 0 || turn_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        o.round.max_clients == 0 || o.round.max_clients > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        !tls_round_values(server, &o, workspace_capacity)) {
        result = VIREO_RESULT_RANGE; goto finish;
    }
    if (server->listener == NULL || !server->listener_bound) {
        result = VIREO_RESULT_NOT_FOUND; goto finish;
    }
    if (!queue_valid(server)) {
        result = VIREO_RESULT_INTERNAL; detail.stage = VIREO_TCP_SERVER_TLS_ROUND_QUEUE; goto finish;
    }
    progress.queued_before_wait = server->queue_count;
    progress.remaining_count = server->queue_count;
    result = stop_snapshot(server, &progress.stopped);
    if (result != VIREO_OK) { detail.stage = VIREO_TCP_SERVER_TLS_ROUND_WAIT; goto finish; }
    if (progress.stopped) goto finish;
    server->scheduling_active = true;
    vireo_tcp_server_tls_poll_report_t waited = {0};
    waited.poll.queued_before_wait = server->queue_count;
    waited.poll.effective_timeout_ms = server->queue_count != 0 ? 0 : o.timeout_ms;
    result = ready_wait(server, &waited.poll, &waited.listener_events, &waited, &detail.wait_error);
    progress.wait = waited.poll.wait;
    progress.wait_called = waited.poll.wait_called;
    progress.stopped = waited.poll.stopped;
    progress.effective_timeout_ms = waited.poll.effective_timeout_ms;
    progress.listener_events = waited.listener_events;
    progress.scanned_slots = waited.scanned_slots;
    progress.expired_clients = waited.expired_clients;
    progress.has_deadline = waited.has_deadline;
    progress.nearest_deadline_ns = waited.nearest_deadline_ns;
    progress.before_wait_ns = waited.before_wait_ns;
    progress.after_wait_ns = waited.after_wait_ns;
    progress.queued_after_wait = waited.poll.queued_after_wait;
    if (result != VIREO_OK) { detail.stage = VIREO_TCP_SERVER_TLS_ROUND_WAIT; goto done; }
    detail.wait_error = (vireo_tcp_server_tls_error_t){0};
    if (progress.stopped) goto done;
    size_t count = progress.queued_after_wait;
    if (count > o.round.max_clients) count = o.round.max_clients;
    if (count > turn_capacity) count = turn_capacity;
    for (size_t k = 0; k < count; ++k) {
        size_t const index = server->queue_head;
        if (index >= server->options.connection_capacity) {
            result = VIREO_RESULT_INTERNAL; detail.stage = VIREO_TCP_SERVER_TLS_ROUND_QUEUE; break;
        }
        client_slot_t const *slot = &server->clients[index];
        vireo_tcp_server_tls_turn_result_t turn = {.client = slot->lease, .events = slot->pending_events};
        result = queue_remove(server, index);
        if (result != VIREO_OK) { detail.stage = VIREO_TCP_SERVER_TLS_ROUND_QUEUE; break; }
        turn.result = tls_round_dispatch(server, &o, wire_workspace, workspace_capacity,
            handler, context, &turn, gate, gate_context, from_serve);
        result = turn.result;
        if (result != VIREO_OK) {
            turn.error.client = turn.client;
            detail = turn.error;
            ++progress.failed_count;
        } else ++progress.succeeded_count;
        out_turns[progress.turn_count++] = turn;
        if (result != VIREO_OK) break;
    }
done:
    progress.remaining_count = server->queue_count;
    server->scheduling_active = false;
finish:
    if (out_info != NULL) *out_info = progress;
    if (error != NULL) *error = detail;
    errno = saved;
    return result;
}

vireo_result_t vireo_tcp_server_tls_run_once_with_gate(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_round_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_turn_result_t *out_turns, size_t turn_capacity,
    vireo_tcp_server_tls_round_info_t *out_info, vireo_tcp_server_tls_round_error_t *error,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *gate_context)
{ return tls_run_once(server, options, wire_workspace, workspace_capacity, handler, context,
    out_turns, turn_capacity, out_info, error, gate, gate_context, false); }

vireo_result_t vireo_tcp_server_tls_run_once(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_round_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_turn_result_t *out_turns, size_t turn_capacity,
    vireo_tcp_server_tls_round_info_t *out_info, vireo_tcp_server_tls_round_error_t *error)
{ return vireo_tcp_server_tls_run_once_with_gate(server, options, wire_workspace, workspace_capacity,
    handler, context, out_turns, turn_capacity, out_info, error, NULL, NULL); }

/**
 * @brief 在外层整段保护内按固定真账同步监听，省略同值MOD
 * @param[in,out] server 非空TLS根，已owned/bound监听且持serving_active。
 * @param[out] info 非空局部五事实，先typed零，数值拒绝不发布假actual。
 * @param[out] error 非空局部监听原因，只有真实MOD失败标UPDATE。
 * @return OK目标已成立，INTERNAL坏账，其他为原set_read分类。
 * @note 不计算count*per或未验证减法；无申请/采时/owner，外层恢复errno。
 */
static vireo_result_t tls_admission_sync(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_admission_info_t *info, vireo_tcp_server_listener_error_t *error)
{
    *info = (vireo_tcp_server_tls_admission_info_t){0};
    *error = (vireo_tcp_server_listener_error_t){0};
    size_t const per = server->tls_per_connection_bytes;
    size_t const maximum = server->tls_options.max_tls_resource_bytes;
    if (server->client_count > server->options.connection_capacity ||
        server->buffer_bytes > server->options.max_buffer_bytes ||
        server->tls_pair_bytes == 0 || server->tls_pair_bytes > server->options.max_buffer_bytes ||
        per == 0 || per > maximum || server->client_count > maximum / per)
        return VIREO_RESULT_INTERNAL;
    *info = (vireo_tcp_server_tls_admission_info_t){
        .connection_limited = server->client_count == server->options.connection_capacity,
        .buffer_limited = server->tls_pair_bytes > server->options.max_buffer_bytes - server->buffer_bytes,
        .tls_resource_limited = server->client_count == maximum / per,
        .listener_read_enabled = server->listener_read_enabled};
    bool const desired = !info->connection_limited && !info->buffer_limited && !info->tls_resource_limited;
    if (desired == server->listener_read_enabled) return VIREO_OK;
    info->sync_called = true;
    vireo_result_t const result = server->listener_ops.set_read(server->listener_ops.context,
        server->listener, desired, &error->acceptor_error);
    if (result == VIREO_OK) server->listener_read_enabled = desired;
    else error->stage = VIREO_TCP_SERVER_LISTENER_UPDATE;
    info->listener_read_enabled = server->listener_read_enabled;
    return result;
}

vireo_result_t vireo_tcp_server_tls_admission_refresh(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_admission_info_t *out_info, vireo_tcp_server_listener_error_t *error)
{
    int const saved = errno;
    vireo_tcp_server_tls_admission_info_t info = {0};
    vireo_tcp_server_listener_error_t detail = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || out_info == NULL) goto finish;
    if (server->owned_tls_context == NULL || tls_stage_active(server, false, false)) {
        result = VIREO_RESULT_BUSY; goto finish;
    }
    if (server->listener == NULL || !server->listener_bound) {
        result = VIREO_RESULT_NOT_FOUND; goto finish;
    }
    server->serving_active = true;
    result = tls_admission_sync(server, &info, &detail);
    server->serving_active = false;
finish:
    if (out_info != NULL) *out_info = info;
    return listener_finish(result, &detail, error, saved);
}

vireo_result_t vireo_tcp_server_tls_serve_once_with_gate(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_serve_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_tcp_server_tls_serve_info_t *out_info, vireo_tcp_server_tls_serve_error_t *error,
    vireo_tcp_server_tls_application_queue_gate_t gate, void *gate_context)
{
    int const saved = errno;
    vireo_tcp_server_tls_serve_info_t progress = {0};
    vireo_tcp_server_tls_serve_error_t detail = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || options == NULL || wire_workspace == NULL || handler == NULL ||
        out_turns == NULL || out_clients == NULL || out_info == NULL) goto finish;
    vireo_tcp_server_tls_serve_options_t const o = *options;
    if (o.round.timeout_ms < 0 || o.admit.max_accepts == 0 || o.admit.max_accept_syscalls == 0)
        goto finish;
    if (server->owned_tls_context == NULL || tls_stage_active(server, false, false)) {
        result = VIREO_RESULT_BUSY; goto finish;
    }
    if (turn_capacity == 0 || turn_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        client_capacity == 0 || client_capacity > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        o.round.round.max_clients == 0 || o.round.round.max_clients > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        o.admit.max_accepts > VIREO_TCP_SERVER_MAX_CONNECTIONS ||
        !tls_round_values(server, &o.round, workspace_capacity)) {
        result = VIREO_RESULT_RANGE; goto finish;
    }
    size_t const limit = o.admit.max_accepts < client_capacity ? o.admit.max_accepts : client_capacity;
    for (size_t k = 0; k < limit; ++k) {
        if (!lease_empty(out_clients[k])) {
            result = VIREO_RESULT_INVALID_ARGUMENT; goto finish;
        }
    }
    if (server->listener == NULL || !server->listener_bound) {
        result = VIREO_RESULT_NOT_FOUND; goto finish;
    }
    if (!queue_valid(server)) {
        result = VIREO_RESULT_INTERNAL;
        detail.stage = VIREO_TCP_SERVER_TLS_SERVE_ROUND;
        detail.round_error.stage = VIREO_TCP_SERVER_TLS_ROUND_QUEUE;
        goto finish;
    }
    server->serving_active = true;
    result = stop_snapshot(server, &progress.stopped);
    if (result != VIREO_OK) { detail.stage = VIREO_TCP_SERVER_TLS_SERVE_STOP; goto done; }
    if (progress.stopped) goto done;
    progress.pre_sync_called = true;
    result = tls_admission_sync(server, &progress.pre_sync, &detail.listener_error);
    if (result != VIREO_OK) { detail.stage = VIREO_TCP_SERVER_TLS_SERVE_PRE_SYNC; goto done; }
    result = tls_run_once(server, &o.round, wire_workspace, workspace_capacity, handler, context,
        out_turns, turn_capacity, &progress.round, &detail.round_error, NULL, NULL, true);
    if (result != VIREO_OK) { detail.stage = VIREO_TCP_SERVER_TLS_SERVE_ROUND; goto sync; }
    progress.stopped = progress.round.stopped;
    if (progress.stopped) goto sync;
    result = stop_snapshot(server, &progress.stopped);
    if (result != VIREO_OK) { detail.stage = VIREO_TCP_SERVER_TLS_SERVE_STOP; goto sync; }
    if (progress.stopped) goto sync;
    if ((progress.round.listener_events & (VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP)) != 0) {
        result = VIREO_RESULT_IO;
        detail.stage = VIREO_TCP_SERVER_TLS_SERVE_LISTENER_EVENT;
        goto sync;
    }
    if ((progress.round.listener_events & VIREO_EPOLL_EVENT_READ) != 0) {
        progress.admission_called = true;
        result = tls_admit_batch(server, &o.admit, out_clients, client_capacity,
            &progress.admission, &detail.admission_error, true, gate, gate_context);
        if (result != VIREO_OK) detail.stage = VIREO_TCP_SERVER_TLS_SERVE_ADMIT;
    }
sync:
    /* 已经进入的服务进度不能回滚；末尾失败保留最先的业务/接入原因。 */
    progress.post_sync_called = true;
    vireo_tcp_server_listener_error_t sync_error = {0};
    vireo_result_t const synced = tls_admission_sync(server, &progress.post_sync, &sync_error);
    if (synced != VIREO_OK) {
        if (result == VIREO_OK) {
            result = synced;
            detail.stage = VIREO_TCP_SERVER_TLS_SERVE_POST_SYNC;
            detail.listener_error = sync_error;
        } else {
            detail.sync_result = synced;
            detail.sync_error = sync_error;
        }
    }
done:
    server->serving_active = false;
finish:
    if (out_info != NULL) *out_info = progress;
    if (error != NULL) *error = detail;
    errno = saved;
    return result;
}

vireo_result_t vireo_tcp_server_tls_serve_once(vireo_tcp_server_t *server,
    vireo_tcp_server_tls_serve_options_t const *options, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_tls_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_tcp_server_tls_serve_info_t *out_info, vireo_tcp_server_tls_serve_error_t *error)
{ return vireo_tcp_server_tls_serve_once_with_gate(server, options, wire_workspace, workspace_capacity,
    handler, context, out_turns, turn_capacity, out_clients, client_capacity, out_info, error, NULL, NULL); }
