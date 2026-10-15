/*
 * PROJECT : VIREO
 * FILE    : inflight_client_cleanup.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 按完整历史客户身份有界请求取消并清退登记
 */
#ifndef VIREO_NET_INFLIGHT_CLIENT_CLEANUP_H
#define VIREO_NET_INFLIGHT_CLIENT_CLEANUP_H
#include <vireo/net/inflight_store.h>

/** 仅本清退入口发布的阶段，原inflight枚举不变。 */
typedef enum vireo_inflight_client_cleanup_stage {
    VIREO_INFLIGHT_CLIENT_CLEANUP_NONE = 0,
    VIREO_INFLIGHT_CLIENT_CLEANUP_CHECK_RECORD = 1,
    VIREO_INFLIGHT_CLIENT_CLEANUP_REQUEST_CANCEL = 2,
    VIREO_INFLIGHT_CLIENT_CLEANUP_RELEASE_CANCEL = 3
} vireo_inflight_client_cleanup_stage_t;

/** COMPLETE只表示本次扫描抵达容量，不认证worker已退出。 */
typedef enum vireo_inflight_client_cleanup_stop {
    VIREO_INFLIGHT_CLIENT_CLEANUP_STOP_NONE = 0,
    VIREO_INFLIGHT_CLIENT_CLEANUP_COMPLETE = 1,
    VIREO_INFLIGHT_CLIENT_CLEANUP_BUDGET = 2,
    VIREO_INFLIGHT_CLIENT_CLEANUP_ERROR = 3
} vireo_inflight_client_cleanup_stop_t;

/** 每可写路径完整发布的事实快照，无拥有型指针或保活作用。 */
typedef struct vireo_inflight_client_cleanup_report {
    vireo_inflight_client_cleanup_stage_t stage; /**< 首错来源，成功及前置拒绝NONE。 */
    vireo_inflight_client_cleanup_stop_t stop_reason; /**< 正常COMPLETE/BUDGET，执行错误ERROR。 */
    size_t next_index; /**< 形态通过后从begin起；完成槽才前进，失败停当前槽。 */
    size_t scanned_slots; /**< 包括空槽、其他客户及失败槽的检查次数。 */
    size_t matched_records; /**< 本次目标记录数，包含执行失败当前项。 */
    size_t cancel_requests; /**< request返回OK次数，重复已取消对象也计数。 */
    size_t without_cancel; /**< 匹配时无关联的记录数，不等worker已停止。 */
    size_t removed_records; /**< 本次已移除并退还登记名额的数量。 */
    vireo_task_metadata_t last_metadata; /**< matched_records非零时为最后匹配的原快照。 */
    bool last_cancel_requested; /**< 最后匹配项的request已返回OK，不代表worker已观察。 */
} vireo_inflight_client_cleanup_report_t;

/**
 * @brief
 *     在固定表内按槽预算，取消并清退完整历史客户的登记。
 *
 * @param[in,out] store
 *     必需存活表，Reactor串行安全点短借，整个调用禁止POSIX线程取消。
 * @param[in] client
 *     原完整历史租约，只校验形态；不查server、当前性或实际客户槽容量。
 * @param[in] begin_index
 *     0..store.capacity，无回绕；跨次续扫须同一存活表及同一客户。
 * @param[in] max_slots
 *     正size_t且最多65536，空槽/他客户槽也计预算，无默认或隐藏全表扫描。
 * @param[out] report
 *     必需独立报告，每可写路径发布，不重叠资源、输入或errno存储。
 *
 * @retval VIREO_OK
 *     扫至容量COMPLETE或用完预算BUDGET，不表示worker退出或业务回滚。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、零预算或客户pool/generation半空畸形。
 * @retval VIREO_RESULT_NOT_FOUND
 *     客户三字段全零；有效但无匹配客户正常返回OK。
 * @retval VIREO_RESULT_RANGE
 *     begin超过表容量或max_slots超过65536。
 * @retval VIREO_RESULT_INTERNAL
 *     表计数违反局部不变量，不修复损坏对象。
 *
 * @return
 *     取消或表份引用释放的原错误，首错停失败槽，不自动重试。
 *
 * @note
 *     顺序：基本地址/零预算→范围→客户形态→计数不变量→逐槽匹配。
 *     前置拒绝报告逻辑零；有效扫描后next从begin起，begin等于容量为零扫描COMPLETE。
 *     计数检查只读局部字段，不遍历全表；不保证检测任意损坏结构。
 *
 * @note
 *     每个目标有cancel则request一次；随后释放表所持引用并清记录/退count。
 *     无关联也移除，原task仍可运行，迟到completion沿原消费规则清理。
 *     已request而释放失败保记录/引用及当前next，但取消标志不回滚；成功前缀不放回。
 *     last_metadata只在本次匹配过时有效，不对应最后一个空槽或其他客户槽。
 *
 * @note
 *     caller须阻止该身份新增登记，否则已扫前缀的新记录不在本次完成保证内。
 *     只按完整owner/slot/generation删除记录；共享cancel影响所有共享持有者，
 *     不承诺取消组隔离。独立task/caller引用有效，表引用不需要额外retain。
 *     不查或关闭客户，不领队列、销毁外部task、等待取消确认或执行完整停机。
 *
 * @note
 *     无新增申请、持久状态、预算或扩容；扫描限制动作次数，不保证硬实时/lock-free。
 *     对象/地址有效独立对齐，输出只短借到返回，不向worker发布store。
 *     所有路径保持入口errno；合法取消primitive正常只返回OK，异常不承诺通用修复。
 */
vireo_result_t vireo_inflight_store_cancel_client_batch(vireo_inflight_store_t *store,
    vireo_connection_pool_lease_t client, size_t begin_index, size_t max_slots,
    vireo_inflight_client_cleanup_report_t *report);
#endif /* VIREO_NET_INFLIGHT_CLIENT_CLEANUP_H */
