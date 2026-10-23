/* PROJECT: VIREO; DATE: 2026-10-24; BRIEF: 八命令MKDIR Reactor装配与观察。 */
#ifndef VIREO_NET_DIRECTORY_MKDIR_REACTOR_H
#define VIREO_NET_DIRECTORY_MKDIR_REACTOR_H
#include <vireo/net/directory_list_reactor.h>
/** @brief 最近once的去敏值；无actor/name/key/SQL，无资源所有权。 */
typedef struct vireo_directory_mkdir_reactor_report {
    size_t submitted; /**< 实际转移task数；非OK也可能转移。 */
    size_t rejected; /**< 本地拒绝整帧首次入FIFO数。 */
    size_t completions; /**< 实际销毁并结束的完成数，含正常丢弃。 */
    size_t identity_discarded; /**< 当前绑定失效或变化，旧成功/错误均丢弃。 */
    size_t late_discarded; /**< 原客户或记录正常结束的迟到清理。 */
    size_t deadline_downgraded; /**< 身份仍有效但首次enqueue时到期，投TIMEOUT。 */
    bool response_blocked; /**< FIFO空间不足，本轮保head/receipt。 */
    bool completion_pending; /**< 本服务仍owns已pop的MKDIR completion。 */
    size_t expected_requests; /**< 全部八命令已提交镜像数，含take后待交付。 */
} vireo_directory_mkdir_reactor_report_t;
/**
 * @brief 创建完整八命令服务，返回原auth_service owner
 * @param[in] resources 原认证依赖，长期借用，queue专属认证。
 * @param[in] options 原配置按值复制，八命令共享限额/软期限/总申请预算。
 * @param[in,out] stat_queue,root_queue,list_queue,mkdir_queue 四专属完成queue，与认证queue两两不同；prepared、开放、空，无外部consumer。
 * @param[in] stat_operation,root_operation,list_operation,mkdir_operation 非零且与认证四标签合为八个互异值；非wire编号。
 * @param[in] list_completion_bytes_per_turn 保留LIST消费预留预算23558..64MiB。
 * @param[out] owner 必需独占空地址；成功沿原once/quiesce/destroy管理。
 * @retval VIREO_OK 固定申请和唯一notifier注册完成，未创建线程、接客户或SQL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL/非空owner、queue重复、标签零或重复、零预算。
 * @retval VIREO_RESULT_RANGE 原配置超限；读区或max_read_unit不足323、read_low不足322、写FIFO不足23510；LIST预算不足23558/超64MiB、TLS收发预算不足或总申请预算不足。
 * @retval VIREO_RESULT_OVERFLOW store容量加5或任一数组乘加不可表示。
 * @retval VIREO_RESULT_BUSY 原server/store/queue非空、池未放行或资源观察竞争。
 * @retval VIREO_RESULT_CANCELLED server/pool停止或任一queue关闭。
 * @retval VIREO_RESULT_NOT_FOUND listener未绑定、queue未prepare或辅助槽不可用。
 * @retval VIREO_RESULT_NO_MEMORY 固定申请失败，逆序回滚，不发布半owner。
 * @return 原公开依赖观察/注册错误透传。
 * @note Reactor-only，禁POSIX取消，保持errno。地址稳定有效对齐独立、不重叠资源/errno；失败owner保持空。
 * 不接管依赖，不保存options地址；五queue共用notifier，caller保活至所有producer退出和最终drain。
 * 使用八命令混合callback、五故障域和六queue关闭协议；旧四至七命令factory语义/模式不改。
 * C+5镜像含五个take后receipt；LIST side镜像同C+5，MKDIR side仅保存原handle/key，不重复保存名字。
 * @note MKDIR framing/read续处理/半帧扫描上界323，原命令仍各自严格codec；非MKDIR超旧共同156界限按PROTOCOL关闭。
 * schema错本地BAD_REQUEST、无绑定UNAUTHORIZED、限额/分配耗尽OVERLOADED；CRC/framing错或跨八命令未完成重复sequence关闭。
 * 可信user/session由完整当前客户和handle查得，原wire/键复制后才consume，submit按真实transferred/record_retained记账，不重投。
 * @note 专用VMC1 decode核metadata/实例/路由/op/deadline/seq、actor及原handle/key与镜像；原parent/name已在04发布时与task匹配，本层不假称再次比对它们。
 * 每次首次enqueue（含FIFO阻塞恢复）重核客户传输资格、UTC绑定与MONOTONIC；身份变化/失效先丢旧成功及旧错误，再判断请求期限。
 * 身份有效且到期只发送32字节TIMEOUT；否则按01 codec重编码32/64字节wire，绝不发送VMC1。
 * 入FIFO不可逆，其后只refresh/schedule/destroy，不重take/重复enqueue/撤回已入FIFO字节。
 * 超时/断连/DB_ERROR不证明未提交；不自动重做SQL，客户端保原parent/name/key以当前有效Session恢复。
 * @note once consume共享提示一次，hint0仍轮转五queue。auth/STAT/ROOT/MKDIR各至多K次，LIST保原min(K,floor(B/23558))，补提示不表示硬时延。
 * 队列类间推进，单类pending可阻塞同类；MKDIR最大payload112，无新字节预算。缺完成/清理债交app故障清退。
 * 六queue分别close成功后才join；join后无条件drain五完成queue，保留可信迟到LOGOUT。无SQL/join硬时限。
 */
vireo_result_t vireo_directory_mkdir_reactor_create(
    const vireo_auth_service_resources_t *resources, const vireo_auth_service_options_t *options,
    vireo_completion_queue_t *stat_queue, uint32_t stat_operation,
    vireo_completion_queue_t *root_queue, uint32_t root_operation,
    vireo_completion_queue_t *list_queue, uint32_t list_operation,
    size_t list_completion_bytes_per_turn,
    vireo_completion_queue_t *mkdir_queue, uint32_t mkdir_operation,
    vireo_auth_service_t **owner);
/**
 * @brief 复制最近once的MKDIR报告，不推进网络
 * @param[in] service 必需存活八命令服务，短借并排除并发销毁。
 * @param[out] out 必需独立有效对齐输出；成功覆盖，失败含padding保持。
 * @retval VIREO_OK 已复制最近值，含失败once的不可逆进度，不证明对端已收到。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL，输出保持。
 * @retval VIREO_RESULT_NOT_FOUND 原四至七模式未启MKDIR，输出保持。
 * @note Reactor-only，保持errno；无申请/I/O/等待，不与资源/errno重叠。
 */
vireo_result_t vireo_directory_mkdir_reactor_inspect(
    const vireo_auth_service_t *service, vireo_directory_mkdir_reactor_report_t *out);
#endif
