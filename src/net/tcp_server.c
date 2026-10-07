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
    return create_with_dependencies(options, ops, listener_ops, &system_client_ops, &system_scheduler_ops, &system_stop_ops, out_server, error);
}

vireo_result_t vireo_tcp_server_create_with_client_ops(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_ops_t const *ops, vireo_tcp_server_listener_ops_t const *listener_ops,
    vireo_tcp_server_client_ops_t const *client_ops, vireo_tcp_server_t **out_server,
    vireo_tcp_server_error_t *error)
{
    return create_with_dependencies(options, ops != NULL ? ops : &system_ops,
        listener_ops != NULL ? listener_ops : &system_listener_ops, client_ops, &system_scheduler_ops, &system_stop_ops, out_server, error);
}

vireo_result_t vireo_tcp_server_create_with_scheduler_ops(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_ops_t const *ops, vireo_tcp_server_listener_ops_t const *listener_ops,
    vireo_tcp_server_client_ops_t const *client_ops,
    vireo_tcp_server_scheduler_ops_t const *scheduler_ops, vireo_tcp_server_t **out_server,
    vireo_tcp_server_error_t *error)
{
    return create_with_dependencies(options, ops != NULL ? ops : &system_ops,
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
    return create_with_dependencies(options, ops != NULL ? ops : &system_ops,
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
    size_t registered = 0;
    if (server->registered_clients > server->client_count ||
        vireo_checked_size_add(server->registered_clients, server->listener_bound ? 1 : 0,
                                &registered) != VIREO_OK ||
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
            server->admission_pair_bytes <= server->options.max_buffer_bytes - server->buffer_bytes
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
    owner->ops.deallocate(owner->ops.context, owner);
    *server = NULL;
    return finish(result, &detail, error, saved_errno);
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
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || (server->serving_active && !from_serve)) return client_finish(VIREO_RESULT_BUSY, &detail, error, saved_errno);
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
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active ||
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
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || ((server->serving_active || server->running_active) && !from_serve))
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
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active)
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
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active)
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
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active)
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
    if (server->closing_active || server->shutdown_active || server->processing_active || server->driving_active || server->scheduling_active || server->serving_active || (server->running_active && !from_run))
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
    if (server->closing_active || server->shutdown_active || server->running_active || server->processing_active || server->driving_active ||
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
    if (server->processing_active || server->driving_active || server->scheduling_active ||
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
    if (server->closing_active || server->shutdown_active || server->processing_active ||
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
