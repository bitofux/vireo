/* PROJECT: VIREO; FILE: directory_stat_reactor_internal.h;
 * AUTHOR: bitofux; DATE: 2026-10-22; BRIEF: 同一服务轮的私有STAT状态，不跨层借私有布局。 */
#ifndef VIREO_NET_DIRECTORY_STAT_REACTOR_INTERNAL_H
#define VIREO_NET_DIRECTORY_STAT_REACTOR_INTERNAL_H
#include <vireo/net/directory_stat_reactor.h>
#include <vireo/service/directory_stat_completion.h>
#include <vireo/net/directory_root_reactor.h>
#include <vireo/service/directory_root_completion.h>
#include <vireo/net/auth_service_deadline.h>
#include <vireo/net/client_deadline.h>

/** 每客户一个timer指向phase/frame的较早期限；完整绑定兼顾两种代次。 */
typedef struct vireo_auth_client_deadline {
    vireo_client_deadline_binding_t binding;
    uint64_t phase_ns, frame_ns;
    uint32_t authenticated_handle; /**< 只记录consumer实际commit后的handle，无秘密。 */
} vireo_auth_client_deadline_t;

/** Reactor独占镜像；command非零占槽，提交前只占数值路由，committed才计count。 */
typedef struct vireo_stat_expected {
    vireo_command_t command; /**< 启用命令之一；0为空槽。 */
    bool committed; /**< 已交接或撤销残留，metadata完整。 */
    vireo_task_metadata_t metadata; /**< route/实例/op/期限独立原值。 */
    vireo_node_root_request_t root_request; /**< 仅ROOT原请求值，无node ID。 */
    vireo_node_stat_request_t request; /**< 仅STAT原帧独立解码值。 */
    vireo_mysql_node_actor_t actor; /**< STAT/ROOT原可信持久身份。 */
} vireo_stat_expected_t;
/** 每客户唯一STAT首帧门禁，复用slot.task拥有未转移task，不复制owner。 */
typedef struct vireo_stat_head {
    unsigned state; /**< 0空/1待consume/2已consume，非公共ABI。 */
    size_t frame_bytes; /**< 原精确首帧长，成功消费前读区保持。 */
    uint32_t sequence; /**< 原共同framing非零序号。 */
    vireo_status_t status; /**< 未移交时有效的本地空body拒绝状态。 */
    bool transferred; /**< 原submit真实交接，非OK也不能重投。 */
    vireo_result_t fatal; /**< 原基础设施主错，consume恢复不覆盖。 */
    unsigned rejection; /**< 0待enqueue/1待refresh/2已refresh。 */
    vireo_inflight_submit_report_t submit; /**< 一次登记/转移/撤销进度。 */
} vireo_stat_head_t;
typedef struct vireo_root_head {
    unsigned state; /**< 0空/1待consume/2已consume，非公共ABI。 */
    size_t frame_bytes; /**< 原精确首帧长，成功消费前读区保持。 */
    uint32_t sequence; /**< 原共同framing非零序号。 */
    vireo_status_t status; /**< 未移交时有效的本地空body拒绝状态。 */
    bool transferred; /**< 原submit真实交接，非OK也不能重投。 */
    vireo_result_t fatal; /**< 原基础设施主错，consume恢复不覆盖。 */
    unsigned rejection; /**< 0待enqueue/1待refresh/2已refresh。 */
    vireo_inflight_submit_report_t submit; /**< 一次登记/转移/撤销进度。 */
} vireo_root_head_t;
/** 原客户槽，任一head非空即禁止新首帧；task只由一个分支拥有。 */
typedef struct client_slot {
    vireo_connection_pool_lease_t client;
    vireo_auth_request_head_receipt_t head;
    vireo_auth_request_rejection_receipt_t rejection;
    vireo_task_t *task;
    bool audit_decided,closing;
    size_t cleanup_index;
    vireo_root_head_t root_head; /**< ROOT独立首帧恢复状态。 */
    vireo_stat_head_t stat_head; /**< 仅新模式使用。 */
    bool records_cleaned; /**< 原inflight批清理完成，可进入镜像阶段。 */
    size_t expected_cursor; /**< 镜像0..expected_capacity有界清理恢复点。 */
    vireo_auth_client_deadline_t deadline;
} client_slot_t;
/** take后保存独立值，0空/1待enqueue/2待refresh/3待destroy；不再take。 */
typedef struct vireo_stat_receipt {
    unsigned state;
    vireo_directory_stat_completion_outcome_t outcome;
    vireo_inflight_completion_match_t match;
} vireo_stat_receipt_t;
/** 本层单调用公开依赖接点；默认表只调用公开API，可在同层测试排他替换。 */
typedef struct vireo_stat_reactor_ops {
    void *context; /**< service访问期间借用；测试必须保活。 */
    vireo_result_t (*utc)(void *,uint64_t *); /**< 可信UTC毫秒，成功才写输出。 */
    vireo_result_t (*monotonic)(void *,uint64_t *); /**< 同域MONOTONIC，成功才写输出。 */
    vireo_result_t (*consume)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t,size_t); /**< 原帧消费一次。 */
    vireo_result_t (*enqueue)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t,unsigned char const *,size_t); /**< 公开整帧原子入队。 */
    vireo_result_t (*refresh)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t); /**< 公开TLS flow刷新。 */
    vireo_result_t (*submit)(void *,vireo_inflight_store_t *,vireo_tcp_server_t const *,vireo_thread_pool_t *,size_t,vireo_task_t **,vireo_inflight_submit_report_t *); /**< 原transfer/rollback合同。 */
} vireo_stat_reactor_ops_t;
typedef struct vireo_root_receipt {
    unsigned state;
    vireo_directory_root_completion_outcome_t outcome;
    vireo_inflight_completion_match_t match;
} vireo_root_receipt_t;
typedef struct vireo_root_reactor_ops {
    void *context; /**< service访问期间借用；测试必须保活。 */
    vireo_result_t (*utc)(void *,uint64_t *); /**< 可信UTC毫秒，成功才写输出。 */
    vireo_result_t (*monotonic)(void *,uint64_t *); /**< 同域MONOTONIC，成功才写输出。 */
    vireo_result_t (*consume)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t,size_t); /**< 原帧消费一次。 */
    vireo_result_t (*enqueue)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t,unsigned char const *,size_t); /**< 公开整帧原子入队。 */
    vireo_result_t (*refresh)(void *,vireo_tcp_server_t *,vireo_connection_pool_lease_t); /**< 公开TLS flow刷新。 */
    vireo_result_t (*submit)(void *,vireo_inflight_store_t *,vireo_tcp_server_t const *,vireo_thread_pool_t *,size_t,vireo_task_t **,vireo_inflight_submit_report_t *); /**< 原transfer/rollback合同。 */
    vireo_result_t (*create_task)(void *,vireo_task_metadata_t,uint32_t,unsigned char const *,size_t,vireo_mysql_node_actor_t const *,size_t,vireo_task_t **); /**< 原ROOT task创建合同；无cancel。 */
} vireo_root_reactor_ops_t;
struct vireo_auth_service {
    vireo_auth_service_resources_t r;
    vireo_auth_service_options_t o;
    vireo_event_loop_handle_t handle;
    size_t capacity,active,sweep,ready_count,ready_next;
    size_t closing_count; /**< 已标记但尚未release的客户数；清理债禁止poll等待。 */
    bool quiescing;
    client_slot_t *slots;
    vireo_tcp_server_ready_client_t *ready;
    vireo_connection_pool_lease_t *accepted;
    vireo_completion_t *completion;
    vireo_auth_response_consumer_receipt_t receipt;
    vireo_completion_queue_t *stat_queue; /**< NULL即原四命令模式。 */
    uint32_t stat_operation;
    vireo_stat_expected_t *expected;
    size_t expected_capacity,expected_count;
    vireo_completion_t *stat_completion;
    vireo_stat_receipt_t stat_receipt;
    vireo_directory_stat_reactor_report_t stat_report;
    bool stat_first; /**< 每轮切换队列先后次序。 */
    vireo_result_t infrastructure_result; /**< application返回客户错之外的服务级首错。 */
    vireo_stat_reactor_ops_t stat_ops;
    vireo_completion_queue_t *root_queue; /**< 六模式长期借用。 */
    uint32_t root_operation;
    vireo_completion_t *root_completion; /**< pop后独占owner。 */
    vireo_root_receipt_t root_receipt;
    vireo_directory_root_reactor_report_t root_report;
    vireo_root_reactor_ops_t root_ops;
    unsigned completion_cursor; /**< 六模式轮首0..2。 */
    vireo_timer_wheel_t *deadline_wheel; /**< 显式启用后长期独占借用，app拥有。 */
    vireo_auth_service_deadline_options_t deadline_options;
    vireo_client_deadline_binding_t *deadline_routes; /**< wheel槽仅作索引，随后核验完整身份。 */
    size_t deadline_capacity;
    vireo_result_t (*deadline_now)(uint64_t *,vireo_clock_error_t *); /**< 默认公开CLOCK_MONOTONIC；本层测试可替换。 */
};

/** 本层统一关闭意图，幂等记账；release成功后才归还closing_count。 */
static inline void vireo_auth_service_close_slot(vireo_auth_service_t *s,client_slot_t *slot)
{ if(!slot->closing) { slot->closing=true; ++s->closing_count; } }

/* 本层期限操作：均Reactor-only、短借参数、保持外层errno；失败保可清理前缀。
 * guard先拒绝原到期，再核当前绑定；返回OK时仍可能已标closing，调用者必须检查。
 * start只在握手成功点调用；frames在receive后且消费前扫描固定FIFO的帧边界，
 * old_size为receive前读区长度；activity只接受实际绑定/成功交接事实。
 * pump有界推进并领取，pending时外层停止新业务；cancel先于客户release。
 * expired只供本层真实历史通知，完整身份不匹配空操作，支持旧代回归验证。 */
vireo_result_t vireo_auth_deadline_start(vireo_auth_service_t *,client_slot_t *);
vireo_result_t vireo_auth_deadline_guard(vireo_auth_service_t *,client_slot_t *,vireo_auth_service_report_t *);
vireo_result_t vireo_auth_deadline_frames(vireo_auth_service_t *,client_slot_t *,size_t,vireo_auth_service_report_t *);
vireo_result_t vireo_auth_deadline_activity(vireo_auth_service_t *,client_slot_t *,uint32_t,bool,vireo_auth_service_report_t *);
vireo_result_t vireo_auth_deadline_pump(vireo_auth_service_t *,vireo_auth_service_report_t *);
vireo_result_t vireo_auth_deadline_cancel(vireo_auth_service_t *,client_slot_t *);
vireo_result_t vireo_auth_deadline_expired(vireo_auth_service_t *,vireo_timer_wheel_expired_t const *,vireo_auth_service_report_t *);
/**
 * @brief 初始化本层默认公开操作表，不访问资源
 * @param[out] out 必需存活独占输出，全部字段覆盖。
 * @note Reactor启动排他，无分配/等待，不触errno。
 */
void vireo_stat_reactor_default_ops(vireo_stat_reactor_ops_t *out);
/**
 * @brief 同客户活动sequence查重并为可能登记的新请求reserve镜像
 * @param[in,out] service 必需新模式存活owner，Reactor-only。
 * @param[in] client 当前完整客户，数值不保活。
 * @param[in] sequence 非零原序号。
 * @param[in] command 已分发的启用命令之一。
 * @param[out] index 独立输出；SIZE_MAX表示store已满，不会有新登记。
 * @return OK；活动重复PROTOCOL；原观察错误透传，失败无reserve。
 * @note 只借用值，无资源转移/发号，外层保持errno。
 */
vireo_result_t vireo_stat_reactor_reserve(vireo_auth_service_t *service,
    vireo_connection_pool_lease_t client,uint32_t sequence,vireo_command_t command,size_t *index);
/**
 * @brief 原auth head返回后提交或撤销本次reserve
 * @param[in,out] service 存活新模式owner。
 * @param[in] index 原reserve位置或SIZE_MAX。
 * @param[in] report 原一次auth head的submit事实，借至返回。
 * @return OK；发生不可能无reserve而已转移/保登记时INTERNAL。
 * @note 不修改原task/登记，无SQL或重投，外层保持errno。
 */
vireo_result_t vireo_stat_reactor_commit_auth(vireo_auth_service_t *service,size_t index,
    vireo_auth_request_submit_report_t const *report);
/**
 * @brief 仅按完整请求键结束对应镜像，不触资源
 * @param[in,out] service 存活新模式owner。
 * @param[in] metadata 原完整请求值；键含完整route/instance，不能清新请求。
 * @note Reactor-only，重复无动作，外层保持errno。
 */
void vireo_stat_reactor_forget(vireo_auth_service_t *service,vireo_task_metadata_t metadata);
/**
 * @brief 固化一次STAT处理事实并尝试源消费/本地拒绝后续进度
 * @param[in,out] service 存活新模式owner。
 * @param[in,out] slot 当前客户唯一槽，空head才进入新处理。
 * @param[in] view 已共同framing校验的原首帧，所有源借用在消费前结束。
 * @param[in,out] report 本轮独立总计数，保不可逆前缀。
 * @return 原客户错误或基础设施错误，后者同时写service.infrastructure_result。
 * @note 不receive/send，不等待queue；原转移/consume各一次，Reactor-only，外层保持errno。
 */
vireo_result_t vireo_stat_reactor_head(vireo_auth_service_t *service,client_slot_t *slot,
    vireo_connection_frame_view_t view,vireo_auth_service_report_t *report);
/**
 * @brief 只恢复既有STAT首帧消费/拒绝，不再提交
 * @param[in,out] service 存活新模式owner。
 * @param[in,out] slot 原客户槽，非空STAT head。
 * @param[in,out] report 本轮总计数。
 * @return 原公开依赖错；FIFO RANGE保进度并以OK返回、标response_blocked。
 * @note Reactor-only，外层保持errno，不发号/SQL/重投。
 */
vireo_result_t vireo_stat_reactor_finish_head(vireo_auth_service_t *service,client_slot_t *slot,
    vireo_auth_service_report_t *report);
/**
 * @brief 独立预算消费STAT queue及唯一恢复owner
 * @param[in,out] service 存活新模式owner，不consume共享提示。
 * @param[in,out] report 本轮总计数，失败保前缀。
 * @return 原基础设施错误；FIFO满保owner/receipt以OK返回。
 * @note Reactor-only，不等待，外层保持errno；当前身份每次首次enqueue前重核。
 */
vireo_result_t vireo_stat_reactor_completions(vireo_auth_service_t *service,vireo_auth_service_report_t *report);
/**
 * @brief 显式丢弃STAT pending owner并结束对应镜像，无网络副作用
 * @param[in,out] service 存活新模式owner，原owner可NULL。
 * @return 原inspect/destroy错误；实际owner清空才清receipt/镜像。
 * @note 不代替尚在store的登记清理；Reactor-only，外层保持errno。
 */
vireo_result_t vireo_stat_reactor_discard(vireo_auth_service_t *service);
/**
 * @brief 在auth原consumer前核新模式镜像，正常迟到仍沿旧consumer
 * @param[in] service 存活新模式owner。
 * @return OK或原关联/内部异常，失败不take/修改owner。
 * @note 不阻断后续abandon的原LOGOUT效果；Reactor-only，外层保持errno。
 */
vireo_result_t vireo_stat_reactor_check_auth(vireo_auth_service_t const *service);
#endif
