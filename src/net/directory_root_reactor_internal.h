/* PROJECT: VIREO; FILE: directory_root_reactor_internal.h;
 * AUTHOR: bitofux; DATE: 2026-10-22; BRIEF: 同net层ROOT恢复接口。 */
#ifndef VIREO_NET_DIRECTORY_ROOT_REACTOR_INTERNAL_H
#define VIREO_NET_DIRECTORY_ROOT_REACTOR_INTERNAL_H
#include "directory_stat_reactor_internal.h"
/**
 * @brief 初始化本层默认公开操作表，不访问资源
 * @param[out] out 必需存活独占输出，全部字段覆盖。
 * @note Reactor启动排他，无分配/等待，不触errno。
 */
void vireo_root_reactor_default_ops(vireo_root_reactor_ops_t *out);
/**
 * @brief 固化一次ROOT处理事实并尝试源消费/本地拒绝后续进度
 * @param[in,out] service 存活新模式owner。
 * @param[in,out] slot 当前客户唯一槽，空head才进入新处理。
 * @param[in] view 已共同framing校验的原首帧，所有源借用在消费前结束。
 * @param[in,out] report 本轮独立总计数，保不可逆前缀。
 * @return 原客户错误或基础设施错误，后者同时写service.infrastructure_result。
 * @note 不receive/send，不等待queue；原转移/consume各一次，Reactor-only，外层保持errno。
 */
vireo_result_t vireo_root_reactor_head(vireo_auth_service_t *service,client_slot_t *slot,
    vireo_connection_frame_view_t view,vireo_auth_service_report_t *report);
/**
 * @brief 只恢复既有ROOT首帧消费/拒绝，不再提交
 * @param[in,out] service 存活新模式owner。
 * @param[in,out] slot 原客户槽，非空ROOT head。
 * @param[in,out] report 本轮总计数。
 * @return 原公开依赖错；FIFO RANGE保进度并以OK返回、标response_blocked。
 * @note Reactor-only，外层保持errno，不发号/SQL/重投。
 */
vireo_result_t vireo_root_reactor_finish_head(vireo_auth_service_t *service,client_slot_t *slot,
    vireo_auth_service_report_t *report);
/**
 * @brief 独立预算消费ROOT queue及唯一恢复owner
 * @param[in,out] service 存活新模式owner，不consume共享提示。
 * @param[in,out] report 本轮总计数，失败保前缀。
 * @return 原基础设施错误；FIFO满保owner/receipt以OK返回。
 * @note Reactor-only，不等待，外层保持errno；当前身份每次首次enqueue前重核。
 */
vireo_result_t vireo_root_reactor_completions(vireo_auth_service_t *service,vireo_auth_service_report_t *report);
/**
 * @brief 显式丢弃ROOT pending owner并结束对应镜像，无网络副作用
 * @param[in,out] service 存活新模式owner，原owner可NULL。
 * @return 原inspect/destroy错误；实际owner清空才清receipt/镜像。
 * @note 不代替尚在store的登记清理；Reactor-only，外层保持errno。
 */
vireo_result_t vireo_root_reactor_discard(vireo_auth_service_t *service);
#endif
