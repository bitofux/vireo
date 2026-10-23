/*
 * PROJECT : VIREO
 * FILE    : directory_stat_reactor.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : 显式启用认证四命令与NODE_STAT的同一Reactor服务。
 */
#ifndef VIREO_NET_DIRECTORY_STAT_REACTOR_H
#define VIREO_NET_DIRECTORY_STAT_REACTOR_H
#include <vireo/net/auth_service.h>

/** @brief 最近一轮STAT的去敏事实；不含节点内容、持久身份、owner或借用地址。 */
typedef struct vireo_directory_stat_reactor_report {
    size_t submitted; /**< 本轮STAT task真实转移数，非OK提交也按transferred计。 */
    size_t rejected; /**< 本轮本地拒绝整帧首次入FIFO数，不是收到/发送数。 */
    size_t completions; /**< 本轮STAT队列结果完成消费/丢弃并销毁数。 */
    size_t identity_discarded; /**< 本轮首次enqueue前当前身份失效/替换导致的丢弃数。 */
    size_t late_discarded; /**< 本轮原客户/请求已结束的正常迟到清理数。 */
    size_t deadline_downgraded; /**< 本轮最终以TIMEOUT首次入FIFO数，非历史重复尝试数。 */
    bool response_blocked; /**< 本轮STAT本地拒绝/结果曾因FIFO空间不足保留进度。 */
    bool completion_pending; /**< 返回时仍持STAT completion owner；与队列深度无关。 */
    size_t expected_requests; /**< 返回时全部启用命令镜像表已提交项数（五/六/七/八模式），含已take但尚未结束交付项。 */
} vireo_directory_stat_reactor_report_t;

/**
 * @brief 构造显式支持四认证命令及NODE_STAT的单一TLS服务owner
 *
 * @param[in] resources
 *     必需原认证资源；长期借用至destroy，原queue仅接认证结果，notifier由两类producer共用。
 * @param[in] options
 *     必需原显式配置，复制值；task/每客户限额/期限/内存预算为五命令共享政策。
 * @param[in,out] stat_queue
 *     必需prepared、未关闭、入口为空且与resources->queue不同的STAT专用队列；
 *     不接管，不外部pop，生产者必须使用resources->notifier，活到destroy及所有producer退出。
 * @param[in] stat_operation
 *     非零内部标签，与四认证标签互不相同；须与worker混合callback配置相同，不是wire命令号。
 * @param[out] owner
 *     必需独占空owner地址，成功后经原auth_service_once/quiesce/disconnect/destroy管理。
 *
 * @retval VIREO_OK
 *     固定分配状态、请求镜像及双队列恢复区，并注册唯一共享notifier；未接客户或启动线程。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、非空owner、队列相同、零标签/预算或五标签重复。
 * @retval VIREO_RESULT_RANGE
 *     原配置超限、TLS读区/max_read_unit不足156、写FIFO不足393，或新增镜像/状态超总内存预算。
 * @retval VIREO_RESULT_BUSY
 *     原server/store非空、任一完成队列非空、池未放行或原依赖竞争；失败保持owner。
 * @retval VIREO_RESULT_CANCELLED
 *     server/pool停止或任一完成队列已关闭。
 * @retval VIREO_RESULT_NOT_FOUND
 *     缺listener绑定、queue未prepare或原server未预留唯一辅助槽。
 * @retval VIREO_RESULT_OVERFLOW
 *     store容量加2、数组乘加或原申请计算不可表示。
 * @retval VIREO_RESULT_NO_MEMORY
 *     固定申请失败；未发布半owner，释放本次自有申请。
 * @return 其他原观察或唯一notifier注册错误透传。
 *
 * @note 同资源Reactor-only，创建/销毁排除全部并发访问，禁POSIX取消，所有路径保持errno。
 *     所有地址独立有效对齐、不重叠资源/errno；不保存options指针，不拥有依赖或worker。
 *     原auth_service_create仍为四命令模式；本入口不改变其标签、资源结构或行为。
 * @note once原总计数汇总五命令；旧head/rejection/consumer字段仍仅表示最近一次认证事实。
 *     STAT事实经本头inspect获取；每轮两queue各最多options.max_completions次尝试，
 *     轮首只消费一次共享提示，count=0仍检查两队列；满一类FIFO不阻断另一类队列。
 * @note 固定镜像容量为store.capacity+2，保存五命令完整metadata及STAT原请求/可信actor。
 *     同客户尚未完成交付的重复sequence作为协议错误关闭；不改旧四命令模式的重复策略。
 *     STAT原请求44字节、VDS1 task68字节，原protocol/service/03合同不变。
 * @note STAT回包前核完整路由/实例/operation/deadline及原node/handle/actor，再按当前完整
 *     客户租约lookup原handle并比较持久user/session。失效或身份变化只结束旧请求并丢弃，
 *     不向新身份发送旧结果或旧错误；同持久身份/同handle再绑定沿03授权等价限制。
 *     首次完整enqueue前每次恢复重新采可信UTC/MONOTONIC并重核；身份有效但软期限已到
 *     改为TIMEOUT空body。整帧入FIFO后只补refresh/destroy，不撤字节或重发。
 * @note 接入本入口不代表应用已闭环：caller须用混合callback并在每轮前后检查双方永久故障。
 *     任一未回投故障按既有应用政策停止新任务、stop客户、确认task/auth/stat三个队列关闭
 *     后才join，并最终无条件排空两完成队列、清退所有inflight/镜像/连接，再逆序销毁。
 *     quiesce本身仍只禁止新任务；本层不join/等待SQL/管理DB或决定进程退出。
 */
vireo_result_t vireo_directory_stat_reactor_create(vireo_auth_service_resources_t const *resources,
    vireo_auth_service_options_t const *options, vireo_completion_queue_t *stat_queue,
    uint32_t stat_operation, vireo_auth_service_t **owner);

/**
 * @brief 读取启用STAT服务的最近一次once事实，不推进队列、网络或请求
 *
 * @param[in] service
 *     必需本头create成功的存活owner，仅借至返回；首次once前为逻辑零报告。
 * @param[out] out
 *     必需独立可写输出，成功覆盖，失败整个对象含padding保持，不拥有资源。
 *
 * @retval VIREO_OK
 *     最近一次once（包括失败前缀）的STAT报告已复制，不证明对端收到或worker已退出。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL；out非NULL时也保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     由原四命令create创建，未启用STAT，out保持。
 *
 * @note Reactor-only，禁POSIX取消，保持errno；无分配/I/O/等待/采时或内存所有权转移。
 *     输入/输出有效对齐、不重叠资源或errno；快照不保活原服务或任何客户。
 */
vireo_result_t vireo_directory_stat_reactor_inspect(vireo_auth_service_t const *service,
    vireo_directory_stat_reactor_report_t *out);
#endif
