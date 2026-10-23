/* PROJECT: VIREO; FILE: directory_list_reactor.h; DATE: 2026-10-23.
 * 公共合同：七命令单Reactor、整页LIST消费和当前身份重核。 */
#ifndef VIREO_NET_DIRECTORY_LIST_REACTOR_H
#define VIREO_NET_DIRECTORY_LIST_REACTOR_H
#include <vireo/net/directory_root_reactor.h>
/** 最近once的LIST去敏事实，首次once前逻辑零，不拥有资源。 */
typedef struct vireo_directory_list_reactor_report {
    size_t submitted; /**< 实际转移LIST task数，非OK也可转移。 */
    size_t rejected; /**< 本地拒绝首次整帧enqueue数。 */
    size_t completions; /**< 已结束消费且实际销毁的LIST completion数，含丢弃。 */
    size_t identity_discarded; /**< 首次enqueue前当前身份失效/变化而丢弃数。 */
    size_t late_discarded; /**< 原客户/请求已结束的正常迟到清理数。 */
    size_t deadline_downgraded; /**< 身份有效且软期限已到，首次enqueue TIMEOUT数。 */
    bool response_blocked; /**< 本轮本地拒绝或整页响应遇到FIFO空间不足。 */
    bool completion_pending; /**< 返回时尚有本服务独占LIST completion owner。 */
    size_t expected_requests; /**< 返回时所有已启用命令已提交镜像数，含take后待交付。 */
    size_t completion_bytes_charged; /**< 每次消费尝试预留23558字节的累计额，不是实际wire/RSS。 */
} vireo_directory_list_reactor_report_t;
/**
 * @brief 固定申请七命令服务及整页工作区，注册唯一共享notifier，返回原服务owner
 * @param[in] resources 原认证依赖，全部长期借用；queue专用于认证。
 * @param[in] options 原配置复制，限额/软期限/总申请预算七命令共享。
 * @param[in,out] stat_queue STAT专用prepared、开放、入口空队列，长期借用。
 * @param[in] stat_operation 非零内部标签，与其余六项互异。
 * @param[in,out] root_queue ROOT专用prepared、开放、入口空队列，长期借用。
 * @param[in] root_operation 非零内部标签，与其余六项互异。
 * @param[in,out] list_queue LIST专用prepared、开放、入口空队列，长期借用。
 * @param[in] list_operation 非零内部标签，与其余六项互异，不是wire 0x0401。
 * @param[in] completion_bytes_per_turn LIST每once消费预留字节正预算23558..64MiB。
 * @param[out] owner 必需独占空owner，成功沿auth_service once/quiesce/destroy管理。
 * @retval VIREO_OK 完整固定初始化/唯一注册成功；未创建worker、接客户或查询DB。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL/非空owner/四queue重复/七标签零或重复/零预算。
 * @retval VIREO_RESULT_RANGE 原配置超限，读区/max_read_unit不足156，写FIFO不足23510，
 * 字节预算非零却不足23558或超64MiB，TLS收发预算不兼容或本服务固定申请超预算。
 * @retval VIREO_RESULT_BUSY 原server/store非空、任一queue非空、池未放行或资源观察竞争。
 * @retval VIREO_RESULT_CANCELLED 原server/pool停止或任一queue关闭。
 * @retval VIREO_RESULT_NOT_FOUND listener未绑定、任一queue未prepare或无可用辅助槽。
 * @retval VIREO_RESULT_OVERFLOW store容量加4、任一数组乘加不可表示。
 * @retval VIREO_RESULT_NO_MEMORY 固定申请失败，逆序释放本次资源，owner保持空。
 * @return 原资源观察/注册错误透传，失败不发布半owner。
 * @note Reactor-only、禁POSIX取消、保持errno。地址有效对齐、独立、不与资源/errno重叠。
 * 四queue两两不同，无外部consumer；producer共用resources->notifier并活到退出。
 * 不拥有依赖，不保存options地址；caller须用完整七命令混合callback及全服务故障协议。
 * 原四/五/六命令factory保持模式与政策；七模式独立使用C+4镜像，旧模式仍C+2/C+3。
 * @note 准入取当前handle的可信user/session，复制完整50/150字节LIST请求；
 * 同完整客户未完成交付的跨七命令重复sequence关闭。CRC/framing错仍关闭，schema错本地BAD_REQUEST。
 * 限额/申请失败投OVERLOADED，身份拒绝投UNAUTHORIZED，不由客户端传actor。
 * @note VLC1只经07专用decode；核原metadata/实例/路由/op/deadline/sequence/handle/actor/
 * 目录/page_size/原token存在性。每次首次enqueue恢复都重新核完整客户/当前绑定与UTC、MONOTONIC。
 * 身份变化/失效丢弃旧成功及旧错误；身份有效到期则完整TIMEOUT，绝不夹带页。
 * 本层不再验MAC/签名/续期；原token已由worker发布前完整配对。只发送05 codec的wire，绝不发送VLC1。
 * 整帧入FIFO后仅refresh/schedule/destroy，不重核撤回已提交字节或重复enqueue。
 * @note once只consume一次共享提示，hint0仍轮转auth/STAT/ROOT/LIST；旧三类各至多K次，
 * LIST至多min(K,floor(completion_bytes_per_turn/23558))次，每次含保留receipt恢复预留23558。
 * 空队列不计charge；实际取得/持有owner后才计，不把预算称为实际处理字节或时间上界。
 * 字节耗尽补提示，FIFO阻塞保owner并继续其他队列/网络发送，不等待、不内部忙重试。
 * @note 完成outcome/响应DTO/wire均放七模式固定heap；本层不额外栈复制整页。
 * 既有codec/decode仍有自己的约23/46KiB嵌套原生栈，须实测，不宣称全链小栈。
 * 缺completion/清理债由app永久故障域清退；task及四完成queue分别确认关闭后join，
 * join后无条件drain四完成queue，保留可信迟到LOGOUT，再销毁依赖/key。无SQL硬时限。
 */
vireo_result_t vireo_directory_list_reactor_create(
    const vireo_auth_service_resources_t *resources, const vireo_auth_service_options_t *options,
    vireo_completion_queue_t *stat_queue, uint32_t stat_operation,
    vireo_completion_queue_t *root_queue, uint32_t root_operation,
    vireo_completion_queue_t *list_queue, uint32_t list_operation,
    size_t completion_bytes_per_turn, vireo_auth_service_t **owner);
/**
 * @brief 复制最近once的LIST报告，不推进网络/队列
 * @param[in] service 必需存活七模式服务，Reactor短借并排除并发销毁。
 * @param[out] out 必需独立有效对齐输出，仅成功覆盖；失败含padding保持。
 * @retval VIREO_OK 最近报告已复制，含失败once的不可逆进度；不证明对端收到。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL，输出保持。
 * @retval VIREO_RESULT_NOT_FOUND 原四/五/六模式未启用LIST，输出保持。
 * @note Reactor-only、禁POSIX取消、保持errno，无申请/采时/I/O/等待，地址不重叠资源/errno。
 */
vireo_result_t vireo_directory_list_reactor_inspect(
    const vireo_auth_service_t *service, vireo_directory_list_reactor_report_t *out);
#endif
