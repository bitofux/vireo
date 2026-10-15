/*
 * PROJECT : VIREO
 * FILE    : inflight_completion.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : Reactor 只读核验独立完成结果与当前客户、在途请求的关联
 */
#ifndef VIREO_NET_INFLIGHT_COMPLETION_H
#define VIREO_NET_INFLIGHT_COMPLETION_H

#include <vireo/net/inflight_store.h>
#include <vireo/thread/completion.h>

/**
 * @brief
 *     本次关联核验成功的独立值快照，不拥有或保活任何资源。
 *
 * @note
 *     不表示结果已消费、业务成功、期限未过、未取消或允许发送。
 *     后续取出记录、归还客户或关闭变化可使该快照失去当前性。
 *     成功只保证逻辑字段，不承诺 padding、ABI 或 wire 表示。
 */
typedef struct vireo_inflight_completion_match {
    vireo_task_metadata_t metadata; /**< 原登记的完整请求描述，不是结果的业务分类。 */
    vireo_connection_close_state_t close_state; /**< 核验时 OPEN/DRAINING/READY，不授回写权限。 */
} vireo_inflight_completion_match_t;

/**
 * @brief
 *     只读匹配完成结果的当前客户、在途请求及原登记快照。
 *
 * @param[in] store
 *     必需存活的固定记录表，只借至返回；同表全部访问 Reactor-only。
 * @param[in] server
 *     必需存活资源根，只借至返回；同 server 全部访问 Reactor-only。
 * @param[in] completion
 *     必需存活的已公开构造对象，只读短借至返回，期间不得移动或销毁。
 *     来源与关联真实性由 caller 保证，普通数值检查不是安全认证。
 * @param[out] out_match
 *     必需存活、对齐、独占可写值输出，成功可覆盖已有值。
 * @param[out] stage
 *     可空独立阶段输出，每可写路径覆盖，成功和基本 NULL 拒绝为 NONE。
 *
 * @retval VIREO_OK
 *     两字段快照已发布；completion 中的业务 result 可为失败分类。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、无效完整完成描述、跨客户拥有域，或相同键的快照不一致。
 * @retval VIREO_RESULT_NOT_FOUND
 *     客户已失效（CHECK_CLIENT）或请求不再登记（CHECK_RECORD）。
 * @retval VIREO_RESULT_RANGE
 *     客户同拥有域槽号越界，沿公开核验返回。
 *
 * @return
 *     其他公开依赖错误原样返回并保留阶段，不将异常改成正常迟到。
 *
 * @note
 *     顺序：基本地址→公开 inspect/完整完成描述校验→当前客户→在途记录→快照。
 *     键为完整 route 加 instance；operation 与 deadline_ns 必须等于原登记。
 *     result 和 suggested_status 仅验证注册形态，不参与身份或快照相等判断。
 *     当前 closing/停止 server 内仍有效客户允许核验；发送策略由 caller 决定。
 *
 * @note
 *     deadline 为同域 MONOTONIC 纳秒，0/MAX 有限；只比较原快照，不采样或判断到期。
 *     无申请、内部锁、队列领取、取出登记、取消、销毁、收发、回滚或内部重试。
 *     NOT_FOUND 不清结果或历史登记；caller 结束借用后分别显式处理清理义务。
 *
 * @note
 *     失败保持整个主输出、表和 completion，所有路径保持入口 errno。
 *     输出彼此独立，不重叠输入资源、响应数据、其他输出或 errno 存储。
 *     输入/输出须存活且正确对齐，独立值不保活；发布与对象寿命由 caller 同步。
 */
vireo_result_t vireo_inflight_store_check_completion(vireo_inflight_store_t const *store,
    vireo_tcp_server_t const *server, vireo_completion_t const *completion,
    vireo_inflight_completion_match_t *out_match, vireo_inflight_stage_t *stage);

/** 单项消费阶段，独立于既有 inflight 阶段，不重排其数值。 */
typedef enum vireo_inflight_consume_stage {
    VIREO_INFLIGHT_CONSUME_NONE = 0, /**< 完成或基本参数/空源拒绝。 */
    VIREO_INFLIGHT_CONSUME_INSPECT = 1, /**< 读取原完成描述。 */
    VIREO_INFLIGHT_CONSUME_CHECK_MATCH = 2, /**< 公开核验客户及请求关联。 */
    VIREO_INFLIGHT_CONSUME_CHECK_RECORD = 3, /**< 旧客户的历史记录及快照核对。 */
    VIREO_INFLIGHT_CONSUME_TAKE_RECORD = 4, /**< 结束登记并释放表份取消引用。 */
    VIREO_INFLIGHT_CONSUME_DELIVER = 5, /**< 已结束登记后的同步交付。 */
    VIREO_INFLIGHT_CONSUME_DESTROY = 6 /**< 清理唯一拥有的完成对象。 */
} vireo_inflight_consume_stage_t;

/** 关联分类只在核验明确后发布，不是业务 result 或发送状态。 */
typedef enum vireo_inflight_completion_disposition {
    VIREO_INFLIGHT_COMPLETION_NONE = 0, /**< 尚未完成分类或异常身份。 */
    VIREO_INFLIGHT_COMPLETION_MATCHED = 1, /**< 当前客户与请求及快照匹配。 */
    VIREO_INFLIGHT_COMPLETION_CLIENT_GONE = 2, /**< 原客户已失效，跳过交付。 */
    VIREO_INFLIGHT_COMPLETION_REQUEST_GONE = 3 /**< 当前客户有效但原请求无登记。 */
} vireo_inflight_completion_disposition_t;

/**
 * @brief
 *     在登记已经结束后，同步短借匹配结果给 caller 选择处理策略。
 *
 * @param[in,out] context
 *     可空短借上下文，不保存；其寿命与同步由 caller 保证。
 * @param[in] completion
 *     存活结果，仅只读借到该次调用返回，不移动、销毁或保存裸指针。
 * @param[in] match
 *     原登记及核验时关闭阶段的独立按值快照，不保活或授发送权。
 *
 * @return
 *     交付结果；非 OK 原样返回并保留 completion，但已结束登记不回滚。
 *
 * @note
 *     必须有界非阻塞、正常返回并结束所有结果借用，不 longjmp 或 pthread_exit。
 *     不销毁借用 store/server，不递归消费，不改变原 completion owner 存储。
 *     可按公开合同操作其他记录/客户；关闭、期限、取消或响应策略由 caller 决定。
 */
typedef vireo_result_t (*vireo_inflight_completion_deliver_fn)(void *context,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match);

/**
 * @brief
 *     每可写路径发布的独立真实进度；非 OK 不代表资源整体未变。
 *
 * @note
 *     未调用的结果逻辑 OK 不能当作执行成功；对应 called 标志决定有效性。
 *     仅 completion_inspected 时元数据有效，仅 MATCHED 时 match 有效。
 *     不保存资源指针或响应数据，不保活原客户、请求或结果。
 */
typedef struct vireo_inflight_completion_consume_report {
    vireo_inflight_consume_stage_t stage; /**< 主错误位置，成功/基本拒绝 NONE。 */
    vireo_inflight_completion_disposition_t disposition; /**< 匹配或正常迟到分类。 */
    bool completion_inspected; /**< 已取得原结果的独立描述。 */
    vireo_completion_metadata_t completion_metadata; /**< 原描述，包括工作结果及建议状态。 */
    vireo_inflight_completion_match_t match; /**< MATCHED 时核验的原登记及关闭阶段。 */
    bool record_consumed; /**< 本次成功 take，名额及表份引用已归还。 */
    bool delivery_called; /**< 本次实际同步调用过一次回调。 */
    vireo_result_t delivery_result; /**< 回调原返回，仅 delivery_called 时有效。 */
    bool destroy_called; /**< 本次实际调用过一次公开结果销毁。 */
    bool completion_consumed; /**< 原 owner 已被清空，不能再次使用旧别名。 */
    vireo_inflight_stage_t inflight_stage; /**< 原依赖错误阶段或正常迟到的识别阶段。 */
    vireo_result_t destroy_result; /**< 公开销毁原返回，仅 destroy_called 时有效。 */
} vireo_inflight_completion_consume_report_t;

/**
 * @brief
 *     消费 caller 已拥有的单项结果，结束登记并处理正常迟到的清理。
 *
 * @param[in,out] store
 *     必需存活表，Reactor-only，仅短借；成功 take 释放表份但不请求取消。
 * @param[in] server
 *     必需存活资源根，Reactor-only，仅短借，不自动释放客户。
 * @param[in,out] owner
 *     必需独占非空结果 owner 地址，入口全部旧操作/借用已结束。
 * @param[in] deliver
 *     必需符合上述合同的有界同步入口，只在 MATCHED 且 take 成功后调用。
 * @param[in,out] context
 *     可空短借上下文，入口不保存或释放。
 * @param[out] report
 *     必需独立、对齐、可写输出，每可写路径发布，失败也发布真实进度。
 *
 * @retval VIREO_OK
 *     匹配结果已交付并销毁，或正常迟到已清理；owner 清 NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL/空回调，跨域/畸形或相同键的原快照不一致。
 * @retval VIREO_RESULT_NOT_FOUND
 *     基本校验后的空 owner，或不属于两种正常迟到的其他依赖缺失。
 *
 * @return
 *     其他依赖或回调错误原样返回，按 report 判断已经发生的消费。
 *
 * @note
 *     MATCHED 先 take 再回调；回调非 OK 保 owner，不再 destroy 或回滚登记。
 *     只有 CHECK_CLIENT/CHECK_RECORD 的 NOT_FOUND 作为正常迟到且不交付。
 *     旧客户若有历史记录，先公开 get 并严格核对 operation/deadline，再 take。
 *     没有记录只销毁结果；跨域、越界、快照错或 take 错不消费 owner/登记。
 *
 * @note
 *     当前 closing/停止 server 内仍匹配者照常交付，快照不授发送权。
 *     不采样、选择期限/取消策略、领取队列、自动收发、申请、回滚或内部重试。
 *     回调失败后的恢复/清理由 caller 决定；重调用会将已结束请求识别为迟到。
 *
 * @note
 *     全部路径保持入口 errno；callback 外部副作用和已发生 take 不保证恢复。
 *     地址有效、对齐且独立，report/owner 不重叠资源、响应数据、context 或 errno。
 *     所有旧借用在入口前结束，回调借用在返回前结束，销毁后旧别名失效。
 */
vireo_result_t vireo_inflight_store_consume_completion(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_completion_t **owner,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_inflight_completion_consume_report_t *report);

#endif /* VIREO_NET_INFLIGHT_COMPLETION_H */
