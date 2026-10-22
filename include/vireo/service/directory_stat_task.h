/* PROJECT: VIREO; FILE: directory_stat_task.h; DATE: 2026-10-22.
 * BRIEF: NODE_STAT可信身份的拥有型task及同worker同步执行。 */
#ifndef VIREO_SERVICE_DIRECTORY_STAT_TASK_H
#define VIREO_SERVICE_DIRECTORY_STAT_TASK_H
#include <vireo/protocol/node_stat.h>
#include <vireo/service/directory_service.h>
#include <vireo/thread/task.h>

/** @brief VDS1内部封装68字节，不是客户端wire或sizeof(C结构)。 */
#define VIREO_DIRECTORY_STAT_TASK_PAYLOAD_SIZE ((size_t)68)

/** @brief 可信提交端的独立快照；普通数值形态不能证明身份来源。 */
typedef struct vireo_directory_stat_input {
    vireo_task_metadata_t metadata; /**< 完整route/实例/operation/deadline。 */
    vireo_node_stat_request_t request; /**< 原完整44字节请求的独立值；handle须非零。 */
    vireo_mysql_node_actor_t actor; /**< 服务端当前绑定的非零user/session；不从客户端取。 */
} vireo_directory_stat_input_t;

/** @brief 与未来Reactor提交端同源的显式配置，无隐式操作号或超时。 */
typedef struct vireo_directory_stat_task_options {
    uint32_t stat_operation; /**< 非零内部标签；装配保证与全部其他命令标签不冲突。 */
    uint32_t pool_timeout_ms; /**< 0..60000，仅pool等待，不是SQL硬期限。 */
} vireo_directory_stat_task_options_t;

/** @brief 最后阶段；SERVICE是实际至多一次service调用事实。 */
typedef enum vireo_directory_stat_task_stage {
    VIREO_DIRECTORY_STAT_TASK_NONE = 0, /**< 必需地址不齐，未读task。 */
    VIREO_DIRECTORY_STAT_TASK_CONTEXT = 1, /**< 配置/metadata前置，亦允许worker资源前置失败。 */
    VIREO_DIRECTORY_STAT_TASK_DECODE = 2, /**< 读取VDS1与完整请求。 */
    VIREO_DIRECTORY_STAT_TASK_MATCH = 3, /**< operation/sequence/身份形态关联。 */
    VIREO_DIRECTORY_STAT_TASK_CANCEL = 4, /**< 执行前一次协作取消观察。 */
    VIREO_DIRECTORY_STAT_TASK_DEADLINE = 5, /**< 执行前一次软期限检查。 */
    VIREO_DIRECTORY_STAT_TASK_SERVICE = 6 /**< 已进入同步STAT，不提供自动重放许可。 */
} vireo_directory_stat_task_stage_t;

/** @brief caller独占结果，不是completion或资源owner；不可memcpy上网。 */
typedef struct vireo_directory_stat_task_result {
    vireo_directory_stat_task_stage_t stage; /**< 当前阶段；失败也记录。 */
    vireo_result_t result; /**< execute原返回，与业务类别/清理责任分别读取。 */
    vireo_directory_stat_input_t input; /**< read成功后有效，不保活连接/task。 */
    vireo_node_stat_issue_t request_issue; /**< 本地帧拒绝分类，无原始文本。 */
    vireo_directory_stat_result_t service; /**< 原service结果，未调用时各成员零。 */
    vireo_mysql_node_error_t error; /**< 原service去敏诊断，未调用时零。 */
} vireo_directory_stat_task_result_t;

/**
 * @brief Reactor从已核当前绑定和完整帧创建独立NODE_STAT task
 * @param[in] metadata 正常完整route、非零实例/operation，seq与帧一致，deadline有限。
 * @param[in] stat_operation 非零，与metadata.operation一致；标签唯一由装配保证。
 * @param[in] wire 必需稳定44字节完整帧，短借；本API不证明TLS或身份来源。
 * @param[in] wire_size 必须44；帧经既有NODE_STAT decoder完整验证。
 * @param[in] actor 必需服务端生产的非零持久身份，只借至返回；原handle须非零。
 * @param[in] allocation_budget 正且不超task硬限，包含控制块+68字节副本。
 * @param[in] cancel 可NULL；非NULL须存活到retain成功，由task持有公开引用。
 * @param[out] owner 必需独占空owner；成功caller owns，须destroy或真实交接一次。
 * @retval VIREO_OK 独立复制完成，输入原帧/actor随后可失效。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL/非空owner、零actor/handle/标签、operation关联或metadata形态不符。
 * @retval VIREO_RESULT_PROTOCOL 帧、命令或seq不符，未创建task。
 * @return 原task构造RANGE/OVERFLOW/NO_MEMORY及其他依赖错误透传；失败owner保持空。
 * @note VDS1：magic4/reserved4为零/user u64/session u64/原44字节wire，显式大端。
 *     不发号/登记inflight/入队，不含连接指针或fd；magic不认证来源。
 *     保持errno，无DB/锁/网络I/O，但公开分配不承诺硬实时；地址独立、不重叠、不指errno。
 *     独立owner可并发创建；输入在短借期间稳定，共享cancel遵守公开引用并发合同。
 */
vireo_result_t vireo_directory_stat_task_create(vireo_task_metadata_t metadata,
    uint32_t stat_operation, unsigned char const *wire, size_t wire_size,
    vireo_mysql_node_actor_t const *actor, size_t allocation_budget,
    vireo_task_cancel_t *cancel, vireo_task_t **owner);

/**
 * @brief 读取严格VDS1和原完整帧，发布无借用指针的独立输入
 * @param[in] task 必需存活稳定task，借至返回，不移动/消费。
 * @param[in] stat_operation 必需非零预期标签，与可信注册表同源。
 * @param[out] out 必需独立输出，仅成功覆盖，失败整个对象含padding保持。
 * @param[out] issue 必需本地诊断；非NULL入口先置NONE，包括其他NULL路径。
 * @retval VIREO_OK metadata/operation/seq、非零actor/handle、reserved与帧全部通过。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或stat_operation=0。
 * @retval VIREO_RESULT_PROTOCOL 68字节封装、关联、actor/handle形态或原帧非法。
 * @return 原公开task查询错误透传；不证明当前绑定、身份来源或DB授权。
 * @note 保持errno，无申请/I/O/采时；地址独立、不重叠、不指errno；独立对象可并发。
 */
vireo_result_t vireo_directory_stat_task_read(vireo_task_t const *task,
    uint32_t stat_operation, vireo_directory_stat_input_t *out, vireo_node_stat_issue_t *issue);

/**
 * @brief 当前OS worker核task、取消和软期限，同步调用至多一次目录STAT service
 * @param[in] task 必需可信上游创建的存活task，短借；每个task caller只执行一次。
 * @param[in] options 必需显式注册表/pool等待配置，短借。
 * @param[in,out] repository 必需当前OS worker存活节点repo，只借，不销毁或接管。
 * @param[in] now_ns caller在此次执行前新取的同域MONOTONIC纳秒；普通数字不证明新鲜。
 * @param[out] out 必需独占输出；地址齐备后先全清当前结果，复用前已处理旧资源责任。
 * @retval VIREO_OK service返回FOUND且完整清理；不证明读后权限仍有效。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL（out保持）或配置/opaque依赖拒绝。
 * @retval VIREO_RESULT_RANGE pool等待>60000或原service范围拒绝。
 * @retval VIREO_RESULT_PROTOCOL VDS1/原帧/关联非法，未执行service。
 * @retval VIREO_RESULT_CANCELLED 执行前观察取消，或service原pool关闭。
 * @retval VIREO_RESULT_TIMEOUT now_ns>=deadline时未调用service，或service原等待到期。
 * @retval VIREO_RESULT_NOT_FOUND service完整UNAUTHORIZED/NOT_FOUND，须读outcome区分。
 * @return 其他service错误原样返回；地址齐备后保存原报告，result等于本次返回。
 * @note 本层无申请/自有owner/随机源/UTC/网络/发布；下层repo可申请资源并采UTC，保持errno。
 *     取消后期限前置只各观察一次，进入service后不抢断/重放，不因晚取消抹掉真实结果。
 *     任一cleanup_pending都由原worker保留repo并清理；数值结果不是资源owner。
 *     输入借至返回，out独立；同repo串行、独立repo可并发，POSIX取消禁用，不支持longjmp。
 */
vireo_result_t vireo_directory_stat_task_execute(vireo_task_t const *task,
    vireo_directory_stat_task_options_t const *options, vireo_mysql_node_repository_t *repository,
    uint64_t now_ns, vireo_directory_stat_task_result_t *out);
#endif
