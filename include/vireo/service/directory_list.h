/* PROJECT : VIREO; AUTHOR : bitofux; DATE : 2026-10-22;
 * BRIEF : 044-06已采用的分页token与LIST服务合同。 */
#ifndef VIREO_SERVICE_DIRECTORY_LIST_H
#define VIREO_SERVICE_DIRECTORY_LIST_H
#include <stdbool.h>
#include <stdint.h>
#include <vireo/persistence/mysql_node_repository.h>
#include <vireo/security/page_token.h>
/** @brief 业务类别，非wire状态；只有PAGE提供节点与可能的NEXT。 */
typedef enum vireo_directory_list_outcome {
    VIREO_DIRECTORY_LIST_NONE = 0,
    VIREO_DIRECTORY_LIST_PAGE = 1,
    VIREO_DIRECTORY_LIST_UNAUTHORIZED = 2,
    VIREO_DIRECTORY_LIST_NOT_FOUND = 3,
    VIREO_DIRECTORY_LIST_BAD_TOKEN = 4
} vireo_directory_list_outcome_t;
/** @brief 一次服务使用的独立输入，没有客户端身份、sequence/handle或裸游标。 */
typedef struct vireo_directory_list_query {
    uint64_t directory_id; /**< 非零显式目录，根也须真实ID。 */
    uint16_t page_size;    /**< 显式1..64，绑定token上下文。 */
    bool has_page_token; /**< false为第一页且token字节须全零；true时任意96字节可待验。 */
    vireo_page_token_t page_token; /**< 独立值，只借至返回，不记录日志。 */
} vireo_directory_list_query_t;
/** @brief 是否调用042及用途；不是执行过多少SQL或身份凭证。 */
typedef enum vireo_directory_list_repository_operation {
    VIREO_DIRECTORY_LIST_REPOSITORY_NONE = 0,
    VIREO_DIRECTORY_LIST_REPOSITORY_CHILDREN = 1,
    VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE = 2
} vireo_directory_list_repository_operation_t;
/** @brief caller拥有的独立结果，禁止直接序列化，不拥有repo/key或下层子owner。 */
typedef struct vireo_directory_list_result {
    vireo_directory_list_outcome_t outcome; /**< 仅PAGE发布业务数据。 */
    vireo_mysql_node_page_t page; /**< PAGE是有效前缀，未用槽/名字尾部清零；其余全零。 */
    vireo_page_token_t next_page_token; /**< 仅PAGE且page.has_more有效，其他全零。 */
    vireo_directory_list_repository_operation_t
        repository_operation;         /**< NONE或实际单次调用用途。 */
    vireo_result_t repository_result; /**< 非NONE时原rc，不随清理/服务错误提升改写。 */
    vireo_mysql_node_report_t repository; /**< 非NONE时原报告，非OK也必须读cleanup_pending。 */
    bool token_checked; /**< 是否调用初次verify，不包括后续时间复核/sign。 */
    vireo_result_t token_result; /**< checked时初次verify原rc，后续过期不改写原OK。 */
} vireo_directory_list_result_t;
/** @brief 去敏服务阶段，无wire状态、SQL/名字/token文本。 */
typedef enum vireo_directory_list_stage {
    VIREO_DIRECTORY_LIST_STAGE_NONE = 0,
    VIREO_DIRECTORY_LIST_STAGE_VALIDATE = 1,
    VIREO_DIRECTORY_LIST_STAGE_TOKEN_VERIFY = 2,
    VIREO_DIRECTORY_LIST_STAGE_REPOSITORY = 3,
    VIREO_DIRECTORY_LIST_STAGE_PAGE_VALIDATE = 4,
    VIREO_DIRECTORY_LIST_STAGE_UTC = 5,
    VIREO_DIRECTORY_LIST_STAGE_TOKEN_SIGN = 6,
    VIREO_DIRECTORY_LIST_STAGE_TOKEN_REVALIDATE = 7
} vireo_directory_list_stage_t;
/** @brief 本层首因与下层原始首因/首清理分别保留。 */
typedef struct vireo_directory_list_error {
    vireo_directory_list_stage_t stage; /**< 本层失败阶段，成功为NONE。 */
    int system_errno;                   /**< 仅本层CLOCK_REALTIME返回-1的errno，其他0。 */
    vireo_mysql_node_error_t repository; /**< 实际调用042时原诊断，含原cleanup_result，不改写。 */
} vireo_directory_list_error_t;
/**
 * @brief 同worker每页授权/读列表/签NEXT，坏token用一次空页探测保持身份拒绝优先
 * @param[in,out] repository 必需活的当前OS worker节点repo，guard/pool保活且无残留。
 *     短借不接管/销毁，同repo串行；线程资格由042实际调用检查。
 * @param[in] key 必需存活不变key，caller保活直到所有并发服务借用结束。
 * @param[in] actor 必需可信连接绑定生产的非零持久user/session；客户端不能指定，042重核。
 * @param[in] query 必需稳定只读独立查询，目录非零、page1..64、token存在性满足字段合同。
 * @param[in] timeout_ms 池等待0..60000毫秒，不限制SQL/行锁/整个同步调用。
 * @param[out] result 必需独占独立结果；必需地址齐备后先清零，再保留实际原始调用事实。
 *     复用前caller已处理旧repo残留，清零输出不释放任何owner。
 * @param[out] error 可NULL独立去敏诊断；地址齐备后重置，NULL仍以局部诊断核清理。
 * @retval VIREO_OK 仅PAGE，持久授权/页形状/资源清理/NEXT签发与时间复核完整。
 * @retval VIREO_RESULT_NOT_FOUND 仅UNAUTHORIZED或NOT_FOUND，明确领域issue且回滚/清理完整。
 * @retval VIREO_RESULT_PROTOCOL BAD_TOKEN为明确坏token且probe证明该次身份未拒绝；
 *     下层若返回其他PROTOCOL故障则NONE，不能只看rc推断业务。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL、身份/目录0、无token但残留字节或下层前置拒绝。
 * @retval VIREO_RESULT_RANGE page不在1..64或timeout>60000，或下层原范围错误。
 * @retval VIREO_RESULT_NO_MEMORY 下层页/SQL/crypto分配或首清理失败，NONE。
 * @retval VIREO_RESULT_DATABASE 下层SQL/行形状或首清理失败，NONE。
 * @retval VIREO_RESULT_BUSY 下层pending/池无容量或首清理失败，NONE，不自动重试。
 * @retval VIREO_RESULT_TIMEOUT pool等待/首清理，或第一页新建链在签名后已失效，NONE。
 * @retval VIREO_RESULT_CANCELLED pool关闭或首清理失败，NONE。
 * @retval VIREO_RESULT_IO CLOCK_REALTIME采时或下层I/O/首清理失败，NONE。
 * @retval VIREO_RESULT_OVERFLOW UTC换算/第一页TTL或下层/首清理溢出，NONE。
 * @retval VIREO_RESULT_INTERNAL crypto/报告/页关联矛盾、清理NOT_FOUND等，NONE。
 * @return 其他基础设施/首清理错误原样返回，NONE；非PAGE业务page/NEXT全零。
 * @note 必需地址缺失时保持result/error；齐备后清输出再校值。所有地址有效对齐、
 *     互不重叠且不指向errno，输入借至返回无逸出；保持入口errno。
 * @note 第一页after0，token合法用已验after；verify PROTOCOL则query页1/after UINT64_MAX。
 *     后者只有AUTH_REJECTED变UNAUTHORIZED，完整OK空页或NODE_NOT_FOUND变BAD_TOKEN。
 *     本地crypto/UTC基础设施失败不调用repo，NONE；不声称这些失败时能判数据库身份。
 *     合法值每次至多一次list_children，不额外get_root/STAT，不+1，不自动重试。
 * @note 先保存原rc/report/error，首清理优先（清理NOT_FOUND提升INTERNAL）；pending时原基础设施rc
 *     保持，原OK/NOT_FOUND提升INTERNAL；完整后才核found/issue/rollback与业务投影。
 *     pending仍由原worker按042销毁/恢复，本服务不释放或抛弃下层owner。
 * @note PAGE校owner/parent/ID>after有序/名字/type/hash/时间，MORE要求满页与末项游标一致。
 *     SQL/清理后需NEXT才采UTC、保留续页原issued/expires或新建10分钟链，sign后再采UTC复核。
 *     续页时间窗口不合BAD_TOKEN；第一页新链sign后失效TIMEOUT/NONE；采时故障NONE，不发布半页。
 *     无MORE不要求SQL结束后token仍可用；仅判断点有效，无持续授权/跨页快照/撤销广播。
 * @note 服务仅局部候选页，不新增大页heap；042页暂存与MAC ctx另有分配，worker需足够栈。
 *     repo同创建线程串行，独立repo可并行；只读key可共享，销毁必须等所有借用结束。
 *     同步可能阻塞，无硬期限，不支持POSIX异步取消/longjmp，不编码wire或接fd/Session表。
 */
vireo_result_t vireo_directory_service_list(vireo_mysql_node_repository_t *repository,
                                            const vireo_page_token_key_t *key,
                                            const vireo_mysql_node_actor_t *actor,
                                            const vireo_directory_list_query_t *query,
                                            uint32_t timeout_ms,
                                            vireo_directory_list_result_t *result,
                                            vireo_directory_list_error_t *error);
#endif
