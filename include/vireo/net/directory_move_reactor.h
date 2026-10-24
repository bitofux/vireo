/*
- PROJECT : VIREO
- FILE    : directory_move_reactor.h
- AUTHOR  : bitofux
- DATE    : 2026-10-25
- BRIEF   : 九命令MOVE Reactor装配与去敏进度观察。
 */
#ifndef VIREO_NET_DIRECTORY_MOVE_REACTOR_H
#define VIREO_NET_DIRECTORY_MOVE_REACTOR_H
#include <vireo/net/directory_mkdir_reactor.h>

/** @brief 最近once的去敏进度，不拥有资源，不含actor、源ID、名字、键或SQL。 */
typedef struct vireo_directory_move_reactor_report {
    size_t submitted; /**< task真实交接数，非OK也可已经交接。 */
    size_t rejected; /**< 本地拒绝首次成功入FIFO数，不代表送达。 */
    size_t completions; /**< 实际消费并结束的MOVE完成数，含丢弃。 */
    size_t identity_discarded; /**< 当前身份失效或变化而丢弃旧成功/旧错误数。 */
    size_t late_discarded; /**< 原客户或请求已正常终结的迟到清理数。 */
    size_t deadline_downgraded; /**< 身份有效但首次enqueue到期，实际入FIFO的TIMEOUT数。 */
    bool response_blocked; /**< 当前轮整帧FIFO无空间，保留head/receipt。 */
    bool completion_pending; /**< 服务仍拥有已pop的MOVE completion。 */
    size_t expected_requests; /**< 九命令共有已提交镜像数，含take后待结束项。 */
} vireo_directory_move_reactor_report_t;

/**
 * @brief 创建认证四命令加STAT、ROOT、LIST、MKDIR、MOVE的完整九命令服务
 *
 * @param[in] resources
 *     必需原认证依赖，长期借用；原queue专属认证，与五目录queue不同。
 * @param[in] options
 *     必需原配置，按值复制；九命令共享在途限额、软期限和总申请预算。
 * @param[in,out] stat_queue
 *     必需专属STAT完成queue，prepared、开放、空，无其他consumer，长借。
 * @param[in] stat_operation
 *     STAT可信内部非零标签，非wire命令编号。
 * @param[in,out] root_queue
 *     必需专属ROOT完成queue，前置及借用同stat_queue。
 * @param[in] root_operation
 *     ROOT可信内部非零标签。
 * @param[in,out] list_queue
 *     必需专属LIST完成queue，前置及借用同stat_queue。
 * @param[in] list_operation
 *     LIST可信内部非零标签。
 * @param[in] list_completion_bytes_per_turn
 *     保持LIST独立字节预算23558..64MiB，不因MOVE减小。
 * @param[in,out] mkdir_queue
 *     必需专属MKDIR完成queue，前置及借用同stat_queue。
 * @param[in] mkdir_operation
 *     MKDIR可信内部非零标签。
 * @param[in,out] move_queue
 *     必需专属MOVE完成queue，前置及借用同stat_queue。
 * @param[in] move_operation
 *     MOVE可信内部非零标签，与前八标签互异。
 * @param[out] owner
 *     必需独占空地址；成功以原auth_service_once/quiesce/destroy管理。
 *
 * @retval VIREO_OK
 *     固定申请和唯一notifier注册完成，未创建线程、接收客户或执行SQL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、非空owner、六queue重复、九operation零/重复或零预算。
 * @retval VIREO_RESULT_RANGE
 *     原配置越界；读容量/max_read_unit不足335、read_low不足334、写FIFO不足23510，
 *     LIST预算不在23558..64MiB、TLS预算或总申请预算不足。
 * @retval VIREO_RESULT_OVERFLOW
 *     C+6或数组字节/总预算乘加不可表示。
 * @retval VIREO_RESULT_BUSY
 *     server/store/queue非空、池未放行或依赖观察竞争。
 * @retval VIREO_RESULT_CANCELLED
 *     server/pool停止或任一queue关闭。
 * @retval VIREO_RESULT_NOT_FOUND
 *     listener未绑定、queue未prepare或辅助槽不可用。
 * @retval VIREO_RESULT_NO_MEMORY
 *     固定申请失败，逆序回滚，不发布半owner。
 * @return 原公开依赖观察/注册错误透传。
 *
 * @note Reactor-only，禁POSIX取消，保持errno；输入/输出独立有效对齐、不重叠资源或errno。
 *     失败owner保持空，不接管依赖、不保存options地址。所有借用活至producer退出和最终drain。
 *     六完成queue共用原notifier；九标签/六故障域/七queue关闭。旧四至八命令factory模式保持。
 * @note 共有expected、LIST side和MKDIR side容量均为C+6；MOVE side仅保存原source/handle/key，
 *     不重复保存目标parent/name。每客户九命令共享min(max_client_requests,8)未完成上限；
 *     跨命令未完成重复sequence关闭。任一未消费head禁止receive改写读区，task只owned于原slot.task。
 * @note MOVE共同观察335；逐命令上界MOVE335/MKDIR323/其他156，含无deadline模式。
 *     schema错BAD_REQUEST、无有效绑定UNAUTHORIZED、共享限额/本地申请耗尽OVERLOADED；
 *     CRC/framing错关闭。可信actor从当前完整客户/handle查得，原wire复制后才consume。
 *     submit依真实transferred/record_retained保存不可逆进度，不凭rc重复投递。
 * @note MVC1专用decode后核完整metadata、actor、原source/handle/16字节key与可信镜像。
 *     当前连接传输资格、UTC绑定及MONOTONIC在每次首次enqueue尝试重核；
 *     身份变化/失效先丢旧成功/旧错误，再判断请求期限。有效身份到期仅32字节TIMEOUT，
 *     否则用node_move codec重编码32/64字节wire。内层成功node必须为原source，绝不发送MVC1。
 *     本层不能从MVC1再次验证目标parent/name，不把结构自洽当来源认证。
 * @note FIFO首次成功入队不可逆，只续refresh/schedule/destroy，不重take、不重复enqueue。
 *     超时、断连、UNKNOWN或DB_ERROR均不证明未提交；不重做SQL、不换event/key。
 * @note once消费共享提示一次，hint0也轮转六queue；除LIST保min(K,floor(B/23558))外各至多K次，
 *     MOVE payload最大120无需另增字节预算。某类pending仅阻塞本类，计数不构成硬时延承诺。
 *     task与六完成queue逐一close成功才join，join后无条件drain六queue，保持迟到LOGOUT效果。
 */
vireo_result_t vireo_directory_move_reactor_create(
    const vireo_auth_service_resources_t *resources, const vireo_auth_service_options_t *options,
    vireo_completion_queue_t *stat_queue, uint32_t stat_operation,
    vireo_completion_queue_t *root_queue, uint32_t root_operation,
    vireo_completion_queue_t *list_queue, uint32_t list_operation,
    size_t list_completion_bytes_per_turn,
    vireo_completion_queue_t *mkdir_queue, uint32_t mkdir_operation,
    vireo_completion_queue_t *move_queue, uint32_t move_operation,
    vireo_auth_service_t **owner);

/**
 * @brief 复制最近once的MOVE报告，不推进网络或消费完成项
 * @param[in] service
 *     必需存活九命令服务，短借并排除并发销毁。
 * @param[out] out
 *     必需独立有效对齐输出；仅成功覆盖，失败整个对象含padding保持。
 * @retval VIREO_OK
 *     已复制最近值，包括失败once的真实进度；不证明对端收到响应。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL，输出保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     原四至八模式未启MOVE，输出保持。
 * @note Reactor-only，保持errno，无申请/I/O/等待；地址不重叠资源/errno。
 */
vireo_result_t vireo_directory_move_reactor_inspect(
    const vireo_auth_service_t *service, vireo_directory_move_reactor_report_t *out);
#endif
