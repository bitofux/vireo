/* PROJECT : VIREO; FILE : directory_root_task.h;
 * AUTHOR : bitofux; DATE : 2026-10-22; BRIEF : 可信根查询输入副本与一次同步执行。 */
#ifndef VIREO_SERVICE_DIRECTORY_ROOT_TASK_H
#define VIREO_SERVICE_DIRECTORY_ROOT_TASK_H
#include <vireo/protocol/node_root.h>
#include <vireo/service/directory_root.h>
#include <vireo/thread/task.h>

/** @brief VRT1内部封装恰56字节，不是客户端wire或sizeof(C结构)。 */
#define VIREO_DIRECTORY_ROOT_TASK_PAYLOAD_SIZE ((size_t)56)

/** @brief 独立值快照；结构体/magic本身不证明可信来源。 */
typedef struct vireo_directory_root_input {
    vireo_task_metadata_t metadata; /**< 原route/实例/operation/deadline全部逻辑字段。 */
    vireo_node_root_request_t request; /**< 原32字节请求的独立值；此层要求handle非零。 */
    vireo_mysql_node_actor_t actor; /**< 服务端绑定生产的非零user/session，禁止来自客户端。 */
} vireo_directory_root_input_t;

/** @brief 与提交端同源的显式配置，复制为值。 */
typedef struct vireo_directory_root_task_options {
    uint32_t root_operation; /**< 非零内部标签；装配保证所有命令间不冲突，不等于wire命令。 */
    uint32_t pool_timeout_ms; /**< 0..60000，只限制pool等待，不是SQL硬期限。 */
} vireo_directory_root_task_options_t;

/** @brief 执行最后阶段；SERVICE只在实际调用服务时记录。 */
typedef enum vireo_directory_root_task_stage {
    VIREO_DIRECTORY_ROOT_TASK_NONE = 0,    /**< 必需地址不齐，out保持。 */
    VIREO_DIRECTORY_ROOT_TASK_CONTEXT = 1, /**< 配置或worker资源前置失败。 */
    VIREO_DIRECTORY_ROOT_TASK_DECODE = 2,  /**< 严格读取VRT1/完整请求。 */
    VIREO_DIRECTORY_ROOT_TASK_MATCH = 3, /**< 内部封装、身份或operation/sequence关联失败。 */
    VIREO_DIRECTORY_ROOT_TASK_CANCEL = 4,   /**< 执行前一次取消观察。 */
    VIREO_DIRECTORY_ROOT_TASK_DEADLINE = 5, /**< 执行前一次软期限判断。 */
    VIREO_DIRECTORY_ROOT_TASK_SERVICE = 6   /**< 已进入root服务，不提供重放许可。 */
} vireo_directory_root_task_stage_t;

/** @brief caller独占结果，不保活task/连接，不是资源owner。 */
typedef struct vireo_directory_root_task_result {
    vireo_directory_root_task_stage_t stage; /**< 实际最后阶段。 */
    vireo_result_t result; /**< execute原返回，独立于业务类别/资源清理。 */
    vireo_directory_root_input_t input;    /**< read成功后有效的独立值。 */
    vireo_node_root_issue_t request_issue; /**< 原请求本地去敏诊断，不发到wire。 */
    vireo_directory_root_result_t service; /**< 原service事实，未调用时零。 */
    vireo_mysql_node_error_t error;        /**< 原service诊断，未调用时零。 */
} vireo_directory_root_task_result_t;

/**
 * @brief 可信提交端复制原NODE_ROOT帧与绑定身份，创建拥有型task
 * @param[in] metadata
 *     正常完整route、非零实例/operation，同域有限deadline，seq与帧相同。
 * @param[in] root_operation
 *     非零且等于metadata.operation，来源与可信注册表一致。
 * @param[in] wire
 *     必需稳定只读完整32字节请求，借至返回。
 * @param[in] wire_size
 *     必须32，经既有NODE_ROOT decoder完整校验。
 * @param[in] actor
 *     必需服务端生产的非零持久身份，短借，不接受客户端身份。
 * @param[in] allocation_budget
 *     正且不超task硬限，包含控制块及56字节副本。
 * @param[in] cancel
 *     可NULL；非NULL由task沿公开引用合同retain，caller保活至retain成功。
 * @param[out] owner
 *     必需独占空owner，成功caller owns，须destroy或真实交接一次。
 *
 * @retval VIREO_OK
 *     独立副本已发布，原wire/actor随后可失效。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 * 必需NULL/非空owner、零身份/handle/operation/预算或metadata形态错误。
 * @retval VIREO_RESULT_PROTOCOL
 *     原完整帧非法或sequence不匹配。
 * @return 原task预算/分配/取消引用等依赖错误透传，失败owner保持空。
 *
 * @note VRT1=magic4/reserved4零/user u64/session u64/原32字节wire，整数显式大端。
 *     不认证来源、不登记/提交、不含node_id/连接指针/fd；0 handle需上游先拒绝。
 *     保持errno，无DB/网络I/O；有公开task分配/引用，非硬实时；独立owner可并发。
 *     所有地址有效对齐、互不重叠、不指errno，输入稳定至返回。
 */
vireo_result_t vireo_directory_root_task_create(vireo_task_metadata_t metadata,
                                                uint32_t root_operation, const unsigned char *wire,
                                                size_t wire_size,
                                                const vireo_mysql_node_actor_t *actor,
                                                size_t allocation_budget,
                                                vireo_task_cancel_t *cancel, vireo_task_t **owner);

/**
 * @brief 严格读取VRT1并发布无借用指针的输入
 * @param[in] task
 *     必需存活稳定task，短借，不移动/消费。
 * @param[in] root_operation
 *     必需非零可信预期标签。
 * @param[out] out
 *     必需独立值，只在成功覆盖，失败整个对象含padding保持。
 * @param[out] issue
 *     必需独立诊断，非NULL入口先NONE；内部关联错ENVELOPE，帧错沿原分类。
 *
 * @retval VIREO_OK
 *     恰56字节、magic/reserved、身份/handle、operation/seq及CRC/schema通过。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL或零operation；非NULL issue仍重置。
 * @retval VIREO_RESULT_PROTOCOL
 *     畸形封装/帧/关联，不发布out。
 * @return 原task查询错误透传，不认证来源或当前绑定。
 *
 * @note 无分配/I/O/采时，保持errno；先核长度后读取，地址独立且不指errno。
 *     独立对象可并发，同task不可并发销毁，稳定至返回。
 */
vireo_result_t vireo_directory_root_task_read(const vireo_task_t *task, uint32_t root_operation,
                                              vireo_directory_root_input_t *out,
                                              vireo_node_root_issue_t *issue);

/**
 * @brief 原OS worker核task、取消及软期限，然后至多一次根service
 * @param[in] task
 *     必需可信上游创建的稳定task，caller保证每task只execute一次。
 * @param[in] options
 *     必需显式operation/pool等待配置，短借。
 * @param[in,out] repository
 *     必需创建于当前worker的存活repo，借用，不销毁或接管。
 * @param[in] now_ns
 *     caller执行前新采同域MONOTONIC纳秒，普通值不证明新鲜。
 * @param[out] out
 *     必需独占结果；必要地址齐备后先全清，覆盖前已履行旧资源义务。
 *
 * @retval VIREO_OK
 *     service完整FOUND，仍不证明读后授权持续有效。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL时out保持；配置/原依赖拒绝沿原码。
 * @retval VIREO_RESULT_RANGE
 *     pool等待>60000，无service调用，或原依赖范围错误。
 * @retval VIREO_RESULT_PROTOCOL
 *     内部封装/原帧/关联错误，不调用service。
 * @retval VIREO_RESULT_CANCELLED
 *     执行前观察取消，或原service结果。
 * @retval VIREO_RESULT_TIMEOUT
 *     now_ns>=deadline时不调用service，或原service池等待超时。
 * @retval VIREO_RESULT_NOT_FOUND
 *     只表示service完整UNAUTHORIZED，根查询无普通NOT_FOUND。
 * @return 其他service错误原样返回；地址齐备时out.result等于返回码。
 *
 * @note read→取消一次→期限一次→service一次；取消优先，不在SQL中抢断、重放或改写真实结果。
 *     deadline0/MAX均有限。无本层分配/采时/发布，保持errno；下层可能申请/阻塞/采UTC。
 *     cleanup_pending仍须原worker清理；结果复制不转移owner。同repo串行，独立repo可并发。
 *     POSIX取消禁用，不支持longjmp；所有地址独立有效、不指errno，短借至返回。
 */
vireo_result_t vireo_directory_root_task_execute(const vireo_task_t *task,
                                                 const vireo_directory_root_task_options_t *options,
                                                 vireo_mysql_node_repository_t *repository,
                                                 uint64_t now_ns,
                                                 vireo_directory_root_task_result_t *out);
#endif
