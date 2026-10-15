/*
 * PROJECT : VIREO
 * FILE    : async_round.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 有界FIFO轮次、逐客户配置及失败后缀责任
 */
#ifndef VIREO_NET_ASYNC_ROUND_H
#define VIREO_NET_ASYNC_ROUND_H
#include <vireo/net/async_client_drive.h>

/** 本次客户配置；值由provider填写，指针只借到对应driver返回。 */
typedef struct vireo_async_round_config {
    vireo_async_client_drive_options_t options; /**< 原五数值，具体准入沿driver。 */
    vireo_async_client_drive_budget_t budget; /**< 原收发正字节/次数预算，各客户独立。 */
    vireo_task_cancel_t *cancel; /**< 可空来源强引用，不消费或保存。 */
    vireo_async_request_pending_t *pending; /**< 必需每完整租约唯一caller值，不能指向provider栈。 */
} vireo_async_round_config_t;

/**
 * @brief
 *     有界非阻塞配置函数；仅填独立out和读取caller配置，返回后才驱动。
 *
 * @param[in,out] context
 *     可空短借context；caller保证同步和配置地址稳定。
 * @param[in] client
 *     原完整租约与事件值，不保活；events为0也是合法缓存待办。
 * @param[out] out
 *     本次先逻辑清零的四字段值；非OK时不读取半成品。
 *
 * @return
 *     OK沿driver校验；非OK原样停批，不请求重试或清理。
 *
 * @note
 *     正常返回、不递归轮次/驱动、不操作或销毁借用资源，不返回栈内指针。
 */
typedef vireo_result_t (*vireo_async_round_configure_fn)(void *context,
    vireo_tcp_server_ready_client_t client, vireo_async_round_config_t *out);

/** 独立阶段；旧poll/driver枚举与报告保持。 */
typedef enum vireo_async_round_stage {
    VIREO_ASYNC_ROUND_NONE = 0,
    VIREO_ASYNC_ROUND_POLL = 1,
    VIREO_ASYNC_ROUND_CONFIGURE = 2,
    VIREO_ASYNC_ROUND_DRIVE = 3,
    VIREO_ASYNC_ROUND_SCHEDULE = 4
} vireo_async_round_stage_t;

/** 实际尝试的每客户值；called说明嵌套值的来源，不保存借用指针。 */
typedef struct vireo_async_round_turn {
    vireo_tcp_server_ready_client_t client; /**< poll原完整租约/events，失败也供恢复。 */
    bool configure_called; /**< 本次已尝试配置；失败项也计入turn前缀。 */
    vireo_result_t configure_result; /**< 原callback结果，不自动转换。 */
    bool drive_called; /**< callback OK后实际一次driver。 */
    vireo_result_t drive_result; /**< 原driver结果，不等worker/响应完成。 */
    vireo_async_client_drive_report_t drive_report; /**< 原请求头/移交/消费/IO/pending全部进度。 */
    bool schedule_called; /**< 仅driver OK且needs_reschedule后一次排尾。 */
    vireo_result_t schedule_result; /**< 原排尾结果，不内部重试。 */
    vireo_tcp_server_client_error_t schedule_error; /**< 独立原排尾诊断。 */
} vireo_async_round_turn_t;

/** 每可写路径发布，prefix/后缀各有caller义务；报告不拥有任何资源。 */
typedef struct vireo_async_round_report {
    vireo_async_round_stage_t stage; /**< 主错步骤；全部OK或基本拒绝NONE。 */
    bool poll_called; /**< 已实际一次poll，即使等待或取出失败。 */
    size_t effective_max_clients; /**< max_clients与两数组容量的最小值，基本拒绝为0。 */
    vireo_result_t poll_result; /**< 原poll结果，called才有来源意义。 */
    vireo_tcp_server_poll_report_t poll_report; /**< 全部已取ready前缀、实际等待和剩余原队列。 */
    size_t turn_count; /**< 实际配置尝试数，包含失败当前项。 */
    size_t drive_calls; /**< 真实driver调用数，包含失败调用。 */
    size_t requeued_count; /**< schedule返回OK次数，不包含失败尝试。 */
    size_t unprocessed_begin; /**< 等于turn_count；ready此下标到selected尚未处理。 */
} vireo_async_round_report_t;

/**
 * @brief
 *     一次poll取冻结FIFO批次，逐客户配置/单driver/成功缓存排尾。
 *
 * @param[in,out] server
 *     必需存活根，全部Reactor-only；只能原run之外串行安全点调用。
 * @param[in,out] store
 *     必需固定在途表；原登记/名额/取消引用及撤销规则沿driver。
 * @param[in,out] pool
 *     必需固定池，管理caller串行，worker可并发领取独立task。
 * @param[in] timeout_ms
 *     非负int毫秒上限，无-1；已有待办沿poll强制0。
 * @param[in] max_clients
 *     正size_t且≤65535，本轮客户上限，无默认或额外探空。
 * @param[in,out] configure
 *     必需有界非阻塞配置函数；每客户仅一次，不操作或销毁借用资源。
 * @param[in,out] context
 *     可空本次短借context；配置四字段地址/唯一pending稳定到driver返回。
 * @param[out] ready
 *     独立可写数组，保存poll实际取出全部前缀，含未处理后缀；未写尾保持。
 * @param[in] ready_capacity
 *     正size_t≤65535，与max_clients/turn_capacity取min传poll。
 * @param[out] turns
 *     独立可写数组，只写实际尝试前缀；逐项保存原header及完整进度。
 * @param[in] turn_capacity
 *     正size_t≤65535，不重叠ready或其他输入输出，未写尾保持。
 * @param[out] remaining_task
 *     必需独占入口NULL；创建后未移交的失败task交caller配对清理。
 * @param[out] report
 *     必需独立完整报告，每可写路径发布；失败不能忽略已取ready。
 *
 * @retval VIREO_OK
 *     有限轮步骤完成；原预stop为OK/零驱动，既有待办保持，不恢复分发。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL/空callback/负timeout/零数量/非空remaining，数组和资源保持。
 * @retval VIREO_RESULT_RANGE
 *     任一数量超过65535；配置及其他范围原错误透传。
 * @return
 *     poll/callback/driver/schedule原错透传，首错停批、真实前缀不回滚。
 *
 * @note
 *     不accept/消费notifier或结果/自动响应/关闭归还/采样/运行完整服务或join。
 *     不新建长期对象或申请；原task复制仍可能malloc，不保证整段硬实时。
 *     每冻结客户至多一次driver/首帧；成功缓存排尾不再进入本轮。
 *
 * @note
 *     ready[0:selected_count)均已取出；turns[0:turn_count)实际尝试，含失败当前项。
 *     ready[unprocessed_begin:selected_count)未配置驱动，poll错时该起点为0。
 *     caller处理失败当前项和整个后缀，不自动重排/恢复pending/丢owner/重放。
 *     每真实task移交的原header/metadata由caller逐项保存，不能只保最后report。
 *
 * @note
 *     全调用禁POSIX取消；所有地址独立稳定对齐不重叠。配置callback限制由caller保证，
 *     无新增递归检测/运行锁。所有受控路径保持入口errno，停止观察不是同步屏障。
 */
vireo_result_t vireo_async_round_once(vireo_tcp_server_t *server, vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool, int timeout_ms, size_t max_clients, vireo_async_round_configure_fn configure,
    void *context, vireo_tcp_server_ready_client_t *ready, size_t ready_capacity,
    vireo_async_round_turn_t *turns, size_t turn_capacity, vireo_task_t **remaining_task,
    vireo_async_round_report_t *report);
#endif /* VIREO_NET_ASYNC_ROUND_H */
