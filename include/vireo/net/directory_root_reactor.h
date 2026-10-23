/* PROJECT: VIREO; FILE: directory_root_reactor.h; AUTHOR: bitofux;
 * DATE: 2026-10-22; BRIEF: 认证四命令、STAT与ROOT的单Reactor。 */
#ifndef VIREO_NET_DIRECTORY_ROOT_REACTOR_H
#define VIREO_NET_DIRECTORY_ROOT_REACTOR_H
#include <vireo/net/directory_stat_reactor.h>
/** @brief 最近once的ROOT去敏事实；首次once前逻辑为零，无资源owner。 */
typedef struct vireo_directory_root_reactor_report {
    size_t submitted; /**< ROOT任务实际转移数，含非OK但已转移。 */
    size_t rejected; /**< ROOT本地拒绝首次整帧enqueue数。 */
    size_t completions; /**< ROOT结果已结束消费且销毁数，含丢弃。 */
    size_t identity_discarded; /**< 首次enqueue前身份失效或变化的丢弃数。 */
    size_t late_discarded; /**< 原客户/请求已经结束的正常迟到清理数。 */
    size_t deadline_downgraded; /**< 身份有效且到期，首次enqueue TIMEOUT数。 */
    bool response_blocked; /**< 本轮ROOT本地拒绝或结果曾受FIFO背压。 */
    bool completion_pending; /**< 返回时服务仍有ROOT completion owner。 */
    size_t expected_requests; /**< 返回时六命令镜像提交项数，含take后待交付项。 */
} vireo_directory_root_reactor_report_t;
/**
 * @brief 创建显式启用六命令的单一TLS服务owner
 * @param[in] resources 必需原认证依赖，长期借至destroy，queue仅收认证结果。
 * @param[in] options 必需原配置，复制；限额/软期限/总申请预算为六命令共享。
 * @param[in,out] stat_queue 必需prepared、开放、入口为空的STAT专用队列，长期借用。
 * @param[in] stat_operation 非零内部STAT标签，与四认证及ROOT标签互异。
 * @param[in,out] root_queue 必需prepared、开放、入口为空的ROOT专用队列，长期借用。
 * @param[in] root_operation 非零内部ROOT标签，与其余五标签互异，不是wire 0x0406。
 * @param[out] owner 必需独占空owner，成功后用原auth_service生命周期API管理。
 * @retval VIREO_OK 固定申请和唯一共享notifier注册成功；未启动线程/接客户。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL、非空owner、三队列重复、六标签重复/零或零预算。
 * @retval VIREO_RESULT_RANGE 原配置超限、读区/max_read_unit不足156、写FIFO不足393或总内存超预算。
 * @retval VIREO_RESULT_BUSY 原server/store非空、任一完成队列非空、池未放行或依赖竞争。
 * @retval VIREO_RESULT_CANCELLED server/pool停止或任一完成队列关闭。
 * @retval VIREO_RESULT_NOT_FOUND listener未绑定、任一队列未prepare或缺唯一辅助槽。
 * @retval VIREO_RESULT_OVERFLOW store容量加3或数组乘加不可表示。
 * @retval VIREO_RESULT_NO_MEMORY 固定申请失败，释放本次自有申请，不发布半owner。
 * @return 其他原资源观察/notifier注册错误透传；所有失败保持owner。
 * @note Reactor-only，构造/销毁排除并发，禁POSIX取消，保持errno；输入输出有效对齐，
 * 独立且不重叠资源/errno。不保存options地址、不接管依赖、不创建worker。
 * 三队列两两不同且不外部pop，producer共用resources->notifier，活到所有producer退出。
 * 原四命令和五命令factory合同保持；新factory的once总计数汇总六命令，原认证报告仍仅认证，
 * STAT inspect仅STAT，ROOT inspect仅ROOT，两个expected_requests均表示全部启用命令。
 * @note 镜像容量store.capacity+3，保存完整metadata和命令专属请求/可信actor。
 * 同完整客户租约尚未完成交付的重复sequence关闭连接。ROOT只收32字节空body，
 * 不含node ID；可信actor来自原handle绑定。NO_MEMORY本地投OVERLOADED。
 * @note ROOT结果先专用decode，核原metadata/实例/路由/标签/期限/seq/handle/actor；
 * 首次完整enqueue前每次恢复采UTC/MONOTONIC，核当前完整客户租约和handle持久user/session。
 * 身份改变/失效丢弃旧结果及旧错误；身份有效但到期改TIMEOUT。只编码32/44字节网络响应，
 * 不发送VRC1前缀。整帧入FIFO后仅refresh/destroy，不撤回、不重复enqueue。
 * @note 每轮三队列各至多max_completions次尝试，轮首consume一次共享提示，提示0仍检查全部；
 * 首队列按auth/STAT/ROOT轮转，各自有一个保留receipt，单类背压不阻断其他类。
 * @note 应用必须使用六命令混合callback，每轮前后采三域永久故障；故障停止新任务/客户，
 * 独立确认task/auth/STAT/ROOT四队列关闭后join，join后无条件drain三完成队列并清退
 * inflight/镜像/客户后逆序销毁。保留可信迟到LOGOUT效果；本层不等待SQL、不join或决定进程退出。
 */
vireo_result_t vireo_directory_root_reactor_create(vireo_auth_service_resources_t const *resources,
    vireo_auth_service_options_t const *options, vireo_completion_queue_t *stat_queue,
    uint32_t stat_operation, vireo_completion_queue_t *root_queue, uint32_t root_operation,
    vireo_auth_service_t **owner);
/**
 * @brief 读取最近once的ROOT事实，不推进网络或队列
 * @param[in] service 必需存活服务，Reactor短借，创建和访问排除并发。
 * @param[out] out 必需独立有效对齐输出，成功覆盖，失败含padding保持。
 * @retval VIREO_OK 已复制报告，包括失败once前缀；不证明对端收到。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL，out保持。
 * @retval VIREO_RESULT_NOT_FOUND 四/五命令模式未启用ROOT，out保持。
 * @note Reactor-only、禁POSIX取消、保持errno；地址不重叠资源/errno，无申请/I/O/采时/等待。
 */
vireo_result_t vireo_directory_root_reactor_inspect(vireo_auth_service_t const *service,
    vireo_directory_root_reactor_report_t *out);
#endif
