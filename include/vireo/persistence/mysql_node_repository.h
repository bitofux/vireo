/*
 * PROJECT : VIREO
 * FILE    : mysql_node_repository.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-21
 * BRIEF   : 同worker事务授权与owner隔离的节点读取、分页、目录创建、移动与软删除。
 */
#ifndef VIREO_PERSISTENCE_MYSQL_NODE_REPOSITORY_H
#define VIREO_PERSISTENCE_MYSQL_NODE_REPOSITORY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/persistence/mysql_pool.h>

/** @brief 数据库原始节点名最大字节数，不包含任何尾NUL。 */
#define VIREO_MYSQL_NODE_NAME_CAPACITY ((size_t)255)
/** @brief 创建worker独占opaque owner；借guard/pool，不跨线程移动。 */
typedef struct vireo_mysql_node_repository vireo_mysql_node_repository_t;
/** @brief 可信服务生产的调用期身份值，本层仍须事务重核。 */
typedef struct vireo_mysql_node_actor {
    uint64_t user_id; /**< 服务端可信持久身份，非零；不是wire handle。 */
    uint64_t session_id; /**< 绑定的持久Session ID，非零；本层再核owner/状态/时间。 */
} vireo_mysql_node_actor_t;
/** @brief 与既定schema node_type一致，C表示不是wire布局。 */
typedef enum vireo_mysql_node_kind {
    VIREO_MYSQL_NODE_DIRECTORY = 1, /**< 虚拟目录，无对象hash，size为0。 */
    VIREO_MYSQL_NODE_FILE = 2 /**< 活动文件，有对象hash，不证明物理存在。 */
} vireo_mysql_node_kind_t;
/** @brief 仅ACTIVE节点的独立值；读取非OK清零，写入口按commit发布。 */
typedef struct vireo_mysql_node_value {
    uint64_t id; /**< 非零持久节点ID。 */
    uint64_t owner_id; /**< 非零持久属主，等于本次可信actor.user_id。 */
    uint64_t parent_id; /**< 非根的非零持久父ID，根归零。 */
    bool has_parent; /**< 根为false且parent_id=0，非根为true且parent_id非零。 */
    unsigned char name[VIREO_MYSQL_NODE_NAME_CAPACITY]; /**< 独立原始字节，不保证NUL/UTF8。 */
    size_t name_length; /**< 根0、非根1..255，按DDL校验不含NUL/斜杠/点或双点。 */
    vireo_mysql_node_kind_t kind; /**< 目录1或文件2，仅ACTIVE节点可发布。 */
    bool has_object_hash; /**< 目录false、活动文件true；不是CAS物理可用证明。 */
    unsigned char object_hash[32]; /**< false时归零，true时32字节全位模式合法。 */
    uint64_t size; /**< 字节，目录必须0，不保证物理CAS可用。 */
    uint64_t created_at_ms; /**< 持久UTC epoch毫秒。 */
    uint64_t updated_at_ms; /**< 持久UTC epoch毫秒，不早于created。 */
} vireo_mysql_node_value_t;
/** @brief 内部拒绝/形状诊断，不是wire状态或权限凭据。 */
typedef enum vireo_mysql_node_issue {
    VIREO_MYSQL_NODE_ISSUE_NONE = 0, /**< 无领域拒绝。 */
    VIREO_MYSQL_NODE_AUTH_REJECTED, /**< 内部合并身份失效；未来wire统一UNAUTHORIZED。 */
    VIREO_MYSQL_NODE_NOT_FOUND, /**< 本操作所需活动节点/目录未命中；不区分他人ID与不存在。 */
    VIREO_MYSQL_NODE_ROOT_INVARIANT, /**< 合法身份无活动根，DATABASE且不修补。 */
    VIREO_MYSQL_NODE_UNEXPECTED_RESULT, /**< 固定SQL形状/持久行不变量不符。 */
    VIREO_MYSQL_NODE_NAME_CONFLICT, /**< 两个写入口已锁读验证其他上传中/活动同名，DATABASE领域拒绝。 */
    VIREO_MYSQL_NODE_ROOT_IMMOVABLE, /**< 有效身份下本用户活动根不能移动或改名，DATABASE。 */
    VIREO_MYSQL_NODE_MOVE_CYCLE, /**< 目标祖先含源目录，本次移动将成环，DATABASE。 */
    VIREO_MYSQL_NODE_TREE_INVALID, /**< 已有祖先链缺失/非目录/重复，DATABASE，不自动修复。 */
    VIREO_MYSQL_NODE_ANCESTRY_LIMIT, /**< 任一链超过256项仍未到根，RANGE且不提交。 */
    VIREO_MYSQL_NODE_ROOT_UNDELETABLE, /**< 有效身份下本用户活动根不可删除，DATABASE。 */
    VIREO_MYSQL_NODE_DIRECTORY_NOT_EMPTY, /**< 目录含直接ACTIVE/UPLOADING孩子，DATABASE。 */
    VIREO_MYSQL_NODE_OBJECT_REFERENCE_INVALID /**< 对象缺失/大小不符/零引用/DELETING，DATABASE。 */
} vireo_mysql_node_issue_t;
/** @brief 首因或首清理失败阶段，无任意文本。 */
typedef enum vireo_mysql_node_stage {
    VIREO_MYSQL_NODE_STAGE_NONE = 0, /**< 无错误。 */
    VIREO_MYSQL_NODE_STAGE_VALIDATE, /**< 参数/线程/残留门禁。 */
    VIREO_MYSQL_NODE_STAGE_ALLOCATE, /**< 对象或固定页暂存内存。 */
    VIREO_MYSQL_NODE_STAGE_ACQUIRE, /**< 池租借。 */
    VIREO_MYSQL_NODE_STAGE_BORROW, /**< 租期连接借用。 */
    VIREO_MYSQL_NODE_STAGE_BEGIN, /**< 关闭autocommit并开启事务边界。 */
    VIREO_MYSQL_NODE_STAGE_USER, /**< 用户锁读及状态。 */
    VIREO_MYSQL_NODE_STAGE_SESSION, /**< Session锁读或最终时间拒绝。 */
    VIREO_MYSQL_NODE_STAGE_NODE, /**< 精确owner节点锁读及形状。 */
    VIREO_MYSQL_NODE_STAGE_UTC, /**< 锁后可信UTC采样/换算。 */
    VIREO_MYSQL_NODE_STAGE_ROLLBACK, /**< 结束读取或撤销尚未提交的写事务。 */
    VIREO_MYSQL_NODE_STAGE_STATEMENT_CLOSE, /**< 消费子语句owner。 */
    VIREO_MYSQL_NODE_STAGE_RELEASE, /**< 归还或丢弃连接租约。 */
    VIREO_MYSQL_NODE_STAGE_NAME_CHECK, /**< mkdir完整名字占用锁读。 */
    VIREO_MYSQL_NODE_STAGE_INSERT, /**< 创建活动空目录。 */
    VIREO_MYSQL_NODE_STAGE_AUDIT, /**< 同事务成功审计。 */
    VIREO_MYSQL_NODE_STAGE_COMMIT, /**< 提交响应确认，与close/release分开。 */
    VIREO_MYSQL_NODE_STAGE_SOURCE, /**< 移动/软删除源活动节点锁读或根拒绝。 */
    VIREO_MYSQL_NODE_STAGE_TARGET_PARENT, /**< 移动目标活动父目录锁读。 */
    VIREO_MYSQL_NODE_STAGE_ANCESTOR, /**< 移动两链或软删除源旧父链检查、成环或预算拒绝。 */
    VIREO_MYSQL_NODE_STAGE_UPDATE, /**< 移动源的一行位置/名称/时间修改。 */
    VIREO_MYSQL_NODE_STAGE_CHILDREN, /**< 删除目录前查一个活动/上传中孩子见证。 */
    VIREO_MYSQL_NODE_STAGE_SOFT_DELETE, /**< 源节点ACTIVE转DELETED并记录时间。 */
    VIREO_MYSQL_NODE_STAGE_OBJECT, /**< 文件所指对象的完整行排他锁读。 */
    VIREO_MYSQL_NODE_STAGE_OBJECT_UPDATE /**< 同事务对象活动引用数减一。 */
} vireo_mysql_node_stage_t;
/** @brief 业务命中与资源清理事实，返回非OK仍须检查。 */
typedef struct vireo_mysql_node_report {
    bool found; /**< 只在整个调用OK时true；列表空页亦成功，非OK不发布。 */
    vireo_mysql_node_issue_t issue; /**< 内部领域结果，不直接发送客户端。 */
    bool rollback_confirmed; /**< 收到ROLLBACK成功事实，后续清理失败不覆盖。 */
    bool cleanup_pending; /**< repo仍有子owner，业务BUSY，须同worker destroy。 */
} vireo_mysql_node_report_t;
/** @brief 去敏首因与首清理错误，独立值且不含SQL/输入文本。 */
typedef struct vireo_mysql_node_error {
    vireo_mysql_node_stage_t stage; /**< 首因；无原始SQL/输入文本或凭据。 */
    int system_errno; /**< 原生UTC返回-1的errno，其余0。 */
    vireo_mysql_error_t database; /**< 首因statement数值诊断。 */
    vireo_mysql_pool_error_t pool; /**< 首因pool数值诊断。 */
    vireo_result_t cleanup_result; /**< 首清理错误，无则OK。 */
    vireo_mysql_node_stage_t cleanup_stage; /**< 首清理阶段，无则NONE。 */
    vireo_mysql_error_t cleanup_database; /**< 首清理statement数值诊断。 */
    vireo_mysql_pool_error_t cleanup_pool; /**< 首清理pool数值诊断。 */
} vireo_mysql_node_error_t;

/** @brief 一次列表最多发布64个直接子节点；不是wire默认页大小。 */
#define VIREO_MYSQL_NODE_PAGE_CAPACITY ((size_t)64)
/** @brief 一次页查询的借用值；游标为内部位置，不证明身份或授权。 */
typedef struct vireo_mysql_node_list_query {
    uint64_t directory_id; /**< 必需非零持久父目录ID；根须先get_root取得ID。 */
    uint64_t after_id; /**< 仅取id严格大于此值的行；0从头，UINT64_MAX合法且无候选行。 */
    size_t page_size; /**< 1..64；不提供隐式默认值，不使用OFFSET。 */
} vireo_mysql_node_list_query_t;
/** @brief 完整清理成功才发布的独立页；非OK整对象清零，未用槽亦为零。 */
typedef struct vireo_mysql_node_page {
    vireo_mysql_node_value_t nodes[VIREO_MYSQL_NODE_PAGE_CAPACITY]; /**< caller拥有，前count项有效。 */
    size_t count; /**< 0..请求page_size；合法空目录/已越过末项也可成功为0。 */
    bool has_more; /**< 本次多读一条发现后续；不是未来续页仍有数据的保证。 */
    uint64_t next_after_id; /**< has_more时等于最后交付项ID且非零，否则0；不取额外项ID。 */
} vireo_mysql_node_page_t;

/**
 * @brief 建立同worker独占节点repository，不借连接或执行SQL
 * @param[in] thread 当前OS线程有效guard，与pool同runtime，借用至destroy完全成功。
 * @param[in] pool 存活共享pool，借用，不接管。
 * @param[out] out 必需NULL唯一owner地址，失败保持。
 * @param[out] error 可NULL独立数值诊断，每次重置。
 *
 * @retval VIREO_OK 成功发布owner。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址或非空owner错误。
 * @retval VIREO_RESULT_NO_MEMORY 对象申请失败。
 *
 * @note 全部入口保持errno，地址独立有效不重叠；同repo仅创建线程串行访问。
 *     create不解引用opaque guard；有效guard/同runtime是caller前置，首次acquire由pool核验。
 */
vireo_result_t vireo_mysql_node_repository_create(vireo_mysql_thread_t *thread,
    vireo_mysql_pool_t *pool, vireo_mysql_node_repository_t **out, vireo_mysql_node_error_t *error);

/**
 * @brief 事务内重核可信身份并读取该owner唯一活动根，清理成功才发布
 * @param[in,out] repository 同创建worker存活owner，无残留statement/lease。
 * @param[in] actor 必需非零可信user/session值，只借至返回，不接客户端直接指定身份。
 * @param[in] timeout_ms 池等待0..60000ms；不约束SQL/行锁/整次调用。
 * @param[out] out 必需独立节点值，入口全清零，仅完整OK发布。
 * @param[out] report 必需独立报告，入口重置，非OK也读取cleanup_pending。
 * @param[out] error 可NULL独立去敏诊断，首因与首清理分别保存。
 *
 * @retval VIREO_OK 锁读user/session/root有效，锁后UTC有效，回滚及资源归还完成。
 * @retval VIREO_RESULT_NOT_FOUND 身份无效，issue=AUTH_REJECTED。
 * @retval VIREO_RESULT_DATABASE SQL/行形状/缺根或清理错误，不发布节点。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址/guard/身份错误。
 * @retval VIREO_RESULT_RANGE 池等待越界。
 * @retval VIREO_RESULT_IO UTC采样失败。
 * @retval VIREO_RESULT_OVERFLOW UTC毫秒转换不可表示。
 * @retval VIREO_RESULT_INTERNAL UTC形状异常或底层同步错误。
 * @retval VIREO_RESULT_BUSY repo残留清理或池无可用连接。
 * @retval VIREO_RESULT_TIMEOUT 池等待到期。
 * @retval VIREO_RESULT_CANCELLED pool已关闭。
 * @retval VIREO_RESULT_NO_MEMORY 底层分配失败；其他资源错误沿底层。
 *
 * @note worker同步阻塞；user→session→node共享锁，最后采可信REALTIME判断issued<=now<expires。
 *     显式ROLLBACK释放锁，不写业务/审计/last_seen；无重试、续期或硬墙钟保证。
 *     只按该次授权判断点读取，不阻止后续撤销/过期，也不提供客户端权限票据。
 *     清理失败的子owner保留原repo；schema已迁移且无不受控trigger/DDL。
 */
vireo_result_t vireo_mysql_node_repository_get_root(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint32_t timeout_ms, vireo_mysql_node_value_t *out,
    vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *error);

/**
 * @brief 事务内重核可信身份并按owner+ID读取一个活动节点
 * @param[in,out] repository 同创建worker存活owner，无残留子owner。
 * @param[in] actor 必需可信非零user/session，短借；普通结构体不证明可信来源。
 * @param[in] node_id 必需非零节点ID，0不表示根目录。
 * @param[in] timeout_ms 池等待0..60000ms，不是SQL/整次调用期限。
 * @param[out] out 必需独立节点值，入口清零，仅完整OK发布。
 * @param[out] report 必需独立报告，每次重置，非OK也读清理责任。
 * @param[out] error 可NULL独立诊断，首因/首清理分开，不含原始输入或SQL。
 *
 * @retval VIREO_OK 已发布本owner活动节点的独立值并完成全部清理。
 * @retval VIREO_RESULT_NOT_FOUND 身份失效AUTH_REJECTED，或节点不可见NODE_NOT_FOUND。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址/guard/零身份或零node_id。
 * @retval VIREO_RESULT_RANGE 池等待越界。
 * @retval VIREO_RESULT_DATABASE SQL/固定行形状或清理失败，不发布节点。
 * @retval VIREO_RESULT_IO UTC采样失败。
 * @retval VIREO_RESULT_OVERFLOW UTC毫秒转换不可表示。
 * @retval VIREO_RESULT_INTERNAL UTC形状异常或资源同步错误。
 * @retval VIREO_RESULT_BUSY 原owner有残留清理或池无容量。
 * @retval VIREO_RESULT_TIMEOUT 池等待到期。
 * @retval VIREO_RESULT_CANCELLED 池已关闭。
 * @retval VIREO_RESULT_NO_MEMORY 底层分配失败；其他资源错误沿底层。
 *
 * @note 全部入口保持errno；同repo创建worker串行。固定owner谓词，不探测其他owner；
 *     隐藏上传中/软删除节点。其余锁序、最终UTC、失败清零、ROLLBACK与清理责任同get_root；
 *     不检查祖先可达性、ACL、CAS存在性或提供wire响应，读后状态可变化。
 */
vireo_result_t vireo_mysql_node_repository_stat(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint64_t node_id, uint32_t timeout_ms,
    vireo_mysql_node_value_t *out, vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *error);

/**
 * @brief 同worker关闭残留statement、DISCARD残留lease，完全消费后清owner
 * @param[in,out] owner 必需唯一owner地址，空owner幂等；失败保留未消费对象。
 * @param[out] error 可NULL独立诊断，每次重置；不执行业务重放。
 *
 * @retval VIREO_OK 全部消费，owner清NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址/线程/guard错误，owner保持。
 * @retval VIREO_RESULT_BUSY 残留资源暂不能消费，保留owner。
 * @retval VIREO_RESULT_DATABASE 数据库清理故障，非OK也须核owner是否已消费。
 * @retval VIREO_RESULT_INTERNAL 底层同步等故障，保留真实剩余责任。
 *
 * @note 排除所有并发访问；guard/pool必须仍存活，完全destroy后才detach/join及销毁pool。
 *     保持errno，不强行抛弃未消费owner，不提供POSIX取消或一般资源故障恢复保证。
 */
vireo_result_t vireo_mysql_node_repository_destroy(vireo_mysql_node_repository_t **owner,
    vireo_mysql_node_error_t *error);
/**
 * @brief 同事务重核身份并按节点ID升序返回本用户目录的一页直接子节点
 *
 * 仅返回ACTIVE节点，不递归、不统计总数。
 *
 * @param[in,out] repository
 *     同创建OS worker串行持有的存活repo，无未消费statement/lease。
 * @param[in] actor
 *     必需可信非零持久user/session；借至返回，本层仍事务重核。
 * @param[in] query
 *     必需有效独立查询值，directory_id非零，page_size为1..64，借至返回。
 * @param[in] timeout_ms
 *     池等待0..60000毫秒；不约束SQL、锁等待或整次调用墙钟时间。
 * @param[out] out
 *     必需caller拥有的独立页，入口整对象清零，仅完整OK时发布。
 * @param[out] report
 *     必需独立报告，每次重置；成功时found=true，包括空页，非OK也读cleanup_pending。
 * @param[out] error
 *     可NULL独立去敏诊断，每次重置，首因与首清理分别保存。
 *
 * @retval VIREO_OK
 *     身份与目标目录有效、页完整且ROLLBACK/全部资源归还成功，包括空页。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址、OS线程、零user/session/directory_id错误。
 * @retval VIREO_RESULT_RANGE
 *     page_size或池等待越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     AUTH_REJECTED为身份失效；NODE_NOT_FOUND为本用户可见活动目录不存在，含目标为文件。
 * @retval VIREO_RESULT_DATABASE
 *     SQL/行形状/错误owner或parent/非严格升序/超LIMIT结果/清理错误，无部分页。
 * @retval VIREO_RESULT_NO_MEMORY
 *     固定页暂存申请或依赖分配失败，无业务输出。
 * @retval VIREO_RESULT_BUSY
 *     repo仍有清理责任，或池无可用连接。
 * @retval VIREO_RESULT_TIMEOUT
 *     池等待到期。
 * @retval VIREO_RESULT_CANCELLED
 *     pool已关闭。
 * @retval VIREO_RESULT_IO
 *     原生UTC采样失败。
 * @retval VIREO_RESULT_OVERFLOW
 *     UTC换算不可表示。
 * @retval VIREO_RESULT_INTERNAL
 *     UTC形状异常或依赖同步错误，保留真实诊断。
 *
 * @note 输出保持：非OK页全零，不返回部分数据；report/error保留清理事实。
 * @note 所有权：不保存actor/query/out地址；固定页暂存调用内申请并在所有路径释放。
 * @note 生命周期：输出独立值，不借SQL视图；guard/pool保活至repo完全销毁。
 * @note 线程安全：同repo仅创建worker串行调用，所有SQL在worker，可同步阻塞。
 * @note errno：全部路径保持入口errno，UTC原生错误单列system_errno。
 * @note 锁序：user→session→parent→children固定语句顺序；范围查询可能取得next-key/gap锁。
 *     关闭全部查询后才采最终UTC，issued<=now<expires；事务锁保留至ROLLBACK。
 * @note 分页：每页独立事务并重新授权；按ID续页，无跨页快照、持锁游标或总数。
 *     页间新增/移动/删除可使后页变化；after_id可任意定位，不能绕过owner/Session检查。
 * @note 范围边界：无wire PAGE_TOKEN/NODE_LIST编码、ACL/祖先/CAS保证、重试、续期或写审计。
 *     LIMIT只约束返回候选行，不承诺扫描量、实际锁数、驱动内存或墙钟硬上限。
 */
vireo_result_t vireo_mysql_node_repository_list_children(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_list_query_t *query,
    uint32_t timeout_ms, vireo_mysql_node_page_t *out, vireo_mysql_node_report_t *report,
    vireo_mysql_node_error_t *error);
/** @brief mkdir提交事实；不由函数rc或后续资源清理推断。 */
typedef enum vireo_mysql_node_mkdir_commit {
    VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED = 0, /**< COMMIT原生execute未开始，不等于已确认回滚。 */
    VIREO_MYSQL_NODE_MKDIR_COMMITTED, /**< 已获完整COMMIT成功响应，清理非OK仍保持。 */
    VIREO_MYSQL_NODE_MKDIR_UNKNOWN /**< COMMIT原生execute已开始却无完整成功确认；不重放。 */
} vireo_mysql_node_mkdir_commit_t;
/** @brief 可信worker借用的单段规范化名字与全局执行事件ID；不是路径或业务幂等回执。 */
typedef struct vireo_mysql_node_mkdir_input {
    uint64_t parent_id; /**< 非零本owner活动父目录；0不表示根。 */
    const unsigned char *name; /**< 必需存活只读字节区，借至返回，不要求尾NUL。 */
    size_t name_length; /**< 1..255；caller负责产品UTF-8/控制字符/规范化，本层复核DDL。 */
    unsigned char request_id[16]; /**< 至少一字节非零；可信执行事件身份，不是sequence。 */
} vireo_mysql_node_mkdir_input_t;
/** @brief 独立报告；COMMITTED字段即使非OK仍保留，不套用旧读取的失败全零语义。 */
typedef struct vireo_mysql_node_mkdir_report {
    vireo_mysql_node_mkdir_commit_t commit; /**< 默认NOT_COMMITTED；UNKNOWN不推定结果。 */
    vireo_mysql_node_issue_t issue; /**< AUTH_REJECTED/NODE_NOT_FOUND/NAME_CONFLICT或固定形状异常。 */
    vireo_mysql_node_value_t node; /**< 仅COMMITTED发布已创建目录，之后清理失败仍保持；其他状态全零。 */
    uint64_t audit_id; /**< 仅COMMITTED非零；目录与该成功审计同事务。 */
    bool rollback_confirmed; /**< 确定未提交分支中收到ROLLBACK成功响应；后续close失败不抹去。 */
    bool cleanup_pending; /**< repo仍有statement/lease；后续业务BUSY，同worker destroy。 */
} vireo_mysql_node_mkdir_report_t;
/**
 * @brief 事务重核可信身份，创建一个活动空目录并原子记录成功审计
 *
 * 不创建物理路径，不递归，不复用已有目录；同父写操作直接取排他锁串行。
 *
 * @param[in,out] repository
 *     必需同创建OS worker串行持有的存活repo；guard/pool保活，无残留owner。
 * @param[in] actor
 *     必需可信非零user/session，借至返回；本层再核状态/属主/时效。
 * @param[in] input
 *     必需独立只读值，name借用且调用期不变；parent非零，request非全零。
 * @param[in] timeout_ms
 *     池等待0..60000ms，不是SQL/锁/COMMIT或整次调用的硬期限。
 * @param[out] report
 *     必需独占独立值，入口重置；非OK也须检查commit与cleanup_pending。
 * @param[out] error
 *     可NULL独立数值诊断，首因与首清理独立，不含SQL/名字/路径。
 *
 * @retval VIREO_OK
 *     COMMIT确认且全部清理完成，report为COMMITTED、node/audit_id有效。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/线程/零身份/零parent/全零request错误。
 * @retval VIREO_RESULT_RANGE
 *     name_length不在1..255或池等待越界。
 * @retval VIREO_RESULT_PROTOCOL
 *     单段名字含NUL/斜杠或为单点/双点，不执行SQL。
 * @retval VIREO_RESULT_NOT_FOUND
 *     AUTH_REJECTED为身份失效，NODE_NOT_FOUND为本owner活动父目录不可用（含文件）。
 * @retval VIREO_RESULT_DATABASE
 *     NAME_CONFLICT为验证的占名；否则SQL/DML/COMMIT形状/审计失败，提交事实另读report。
 * @retval VIREO_RESULT_BUSY
 *     repo有残留资源或池无空闲连接。
 * @retval VIREO_RESULT_TIMEOUT
 *     池等待到期。
 * @retval VIREO_RESULT_CANCELLED
 *     pool关闭。
 * @retval VIREO_RESULT_NO_MEMORY
 *     依赖分配失败；本入口不新增私有页或可变长堆分配。
 * @retval VIREO_RESULT_IO
 *     原生UTC采样失败。
 * @retval VIREO_RESULT_OVERFLOW
 *     UTC毫秒不可表示。
 * @retval VIREO_RESULT_INTERNAL
 *     UTC形状或底层同步故障。
 *
 * @note 输出：NOT_COMMITTED/UNKNOWN的node/audit_id全零；COMMITTED后任何清理失败均保持它们。
 * @note 所有权：全部地址独立有效不重叠，不保存actor/input/name/report/error指针；输出按值独立。
 * @note 生命周期：同repo创建worker串行；无新线程/fd，worker同步阻塞，无POSIX取消合同。
 * @note 锁序：user/session共享锁→owner父节点排他锁→live_name排他锁读，范围/隐式锁可等待或死锁。
 * @note 时间：锁读后第一次UTC核窗并写节点/审计时间；两INSERT成功关闭后第二次UTC再核窗才COMMIT。
 *     两次均issued<=now<expires；不保证COMMIT响应/客户端收到时仍未到期，不保证UTC单调。
 * @note 名字：仅复核DDL字节约束，逐字节/大小写敏感唯一；上游负责规范化UTF-8与控制字符规则。
 *     UPLOADING/ACTIVE占名，DELETED释放；不修改父/用户/Session时间，不提供mkdir-p。
 * @note 审计：NODE_MKDIR=5/NODE=3/status=0，latency=0未测量，detail空；与新节点同事务。
 * @note 清理：公开execution_started=false可回滚；原生COMMIT已开始未确认为UNKNOWN，DISCARD不能消除此未知；不重试业务。
 *     残留owner保留repo，后续业务BUSY直至同worker destroy；首因/首清理分列，保持入口errno。
 * @note 边界：request唯一不是原请求结果恢复；无wire/规范化库/ACL/祖先可达性/CAS/目录移动删除或失败审计。
 */
vireo_result_t vireo_mysql_node_repository_mkdir(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_mkdir_input_t *input,
    uint32_t timeout_ms, vireo_mysql_node_mkdir_report_t *report, vireo_mysql_node_error_t *error);

/** @brief move逐链检查预算，含根；不是整个产品的目录深度上限。 */
#define VIREO_MYSQL_NODE_MOVE_ANCESTOR_CAPACITY ((size_t)256)
/** @brief move提交事实，与mkdir语义一致但类型独立，不由rc/清理结果推断。 */
typedef enum vireo_mysql_node_move_commit {
    VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED = 0, /**< 原生COMMIT未开始，不代表ROLLBACK已确认。 */
    VIREO_MYSQL_NODE_MOVE_COMMITTED, /**< 完整COMMIT响应确认，清理非OK仍保持提交值。 */
    VIREO_MYSQL_NODE_MOVE_UNKNOWN /**< 原生COMMIT已开始未确认，丢弃连接且不重放。 */
} vireo_mysql_node_move_commit_t;
/** @brief 同owner活动非根节点的最终位置和名字，输入只借用至返回。 */
typedef struct vireo_mysql_node_move_input {
    uint64_t node_id; /**< 非零可信owner下源节点ID；同一ID在移动后保持。 */
    uint64_t new_parent_id; /**< 非零最终活动父目录ID；0不是根，根由get_root取得。 */
    const unsigned char *name; /**< 必需只读独立存活字节区，不要求尾NUL。 */
    size_t name_length; /**< 1..255字节；本层DDL约束，上游负责产品UTF8/控制字符/规范化。 */
    unsigned char request_id[16]; /**< 全局执行事件ID，至少一字节非零；不是安全重试凭据。 */
} vireo_mysql_node_move_input_t;
/** @brief move提交与资源独立报告，非OK也必须检查commit/cleanup_pending。 */
typedef struct vireo_mysql_node_move_report {
    vireo_mysql_node_move_commit_t commit; /**< 默认NOT_COMMITTED，UNKNOWN不推定结果。 */
    vireo_mysql_node_issue_t issue; /**< 固定领域拒绝/形状诊断，不直接上wire。 */
    vireo_mysql_node_value_t node; /**< COMMITTED才为源提交后独立值，其余全零。 */
    uint64_t audit_id; /**< COMMITTED才非零；不变操作也有一次成功审计。 */
    bool changed; /**< COMMITTED且实际执行位置/名字UPDATE才true；其他状态false。 */
    bool rollback_confirmed; /**< 确定未提交分支已收到ROLLBACK成功，不被后续close抹去。 */
    bool cleanup_pending; /**< repo仍有子owner，后续业务BUSY，同worker destroy。 */
} vireo_mysql_node_move_report_t;
/**
 * @brief 在同用户事务协调锁下移动或改名一个活动非根节点，原子写成功审计
 *
 * 保持源ID/后代父ID/对象内容；同位置同名成功写审计但不UPDATE、不刷新节点时间。
 *
 * @param[in,out] repository
 *     必需创建OS worker串行持有的存活repo，guard/pool保活，无残留statement/lease。
 * @param[in] actor
 *     必需可信非零user/session，短借至返回，本层再核状态/owner/UTC时效。
 * @param[in] input
 *     必需最终位置/名字与非零执行事件ID，name借用且调用期间不变。
 * @param[in] timeout_ms
 *     池等待0..60000ms，不是SQL/行锁/整次调用的硬期限。
 * @param[out] report
 *     必需独立独占值，入口重置；COMMITTED值不因清理非OK丢失。
 * @param[out] error
 *     可NULL独立数值诊断，首因和首清理分开，不含名字/SQL/路径。
 *
 * @retval VIREO_OK
 *     COMMIT确认且全部资源清理完成，包括changed=false的不变操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/线程/零身份/零源或父/全零request错误。
 * @retval VIREO_RESULT_RANGE
 *     名字长度或池等待越界；或issue=ANCESTRY_LIMIT，任一祖先链超过256项仍未到根。
 * @retval VIREO_RESULT_PROTOCOL
 *     单段名字含NUL/斜杠或为点/双点，不执行SQL。
 * @retval VIREO_RESULT_NOT_FOUND
 *     AUTH_REJECTED为身份失效；NODE_NOT_FOUND为源或目标父不可用，目标文件同样隐藏。
 * @retval VIREO_RESULT_DATABASE
 *     ROOT_IMMOVABLE/MOVE_CYCLE/TREE_INVALID/NAME_CONFLICT，或SQL/行形状/DML/提交/清理错误。
 * @retval VIREO_RESULT_BUSY
 *     repo残留子owner或池无可用连接。
 * @retval VIREO_RESULT_TIMEOUT
 *     池等待到期。
 * @retval VIREO_RESULT_CANCELLED
 *     pool关闭。
 * @retval VIREO_RESULT_NO_MEMORY
 *     依赖分配失败；祖先visited为固定调用期数组，无新私有可变长分配。
 * @retval VIREO_RESULT_IO
 *     原生UTC采样失败。
 * @retval VIREO_RESULT_OVERFLOW
 *     UTC毫秒不可表示。
 * @retval VIREO_RESULT_INTERNAL
 *     UTC形状或依赖同步错误。
 *
 * @note 输出：仅COMMITTED发布node/audit_id/changed，后续资源错误保持；其余全零/false。
 * @note 所有权：全部地址独立有效不重叠，不保存actor/input/name/report/error；输出按值。
 * @note 生命周期：repo创建worker独占，guard/pool活到完全destroy，无跨worker清理。
 * @note 线程安全：同步阻塞；user直接X→session S→源X→目标父X→两条祖先S→名字X。
 *     同用户所有遵守user先锁的读/写可能等待；未来树writer必须遵守此协调协议。
 * @note 祖先：源旧父和目标父分别到活动根，每条含根最多256项；超限拒绝，不扫描后代。
 *     已有链重复/缺失/非目录为TREE_INVALID；目标链遇源目录为MOVE_CYCLE，不自动修树。
 * @note 时间：所有必要锁读后UTC核窗，UPDATE/审计后第二次UTC再核窗才COMMIT。
 *     真正变化updated=max(第一次UTC,旧updated)，审计occurred=第一次UTC；不变操作不改节点时间。
 * @note 审计：NODE_MOVE=6/NODE=3/status=0/detail空/latency=0未测量，与变化同事务。
 * @note 清理：保持errno，UNKNOWN一律DISCARD且不重放；残留保repo/BUSY，须同worker destroy。
 * @note 边界：无覆盖/路径解析/递归修改/CAS移动/ACL/wire/幂等恢复或硬墙钟保证。
 */
vireo_result_t vireo_mysql_node_repository_move(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_move_input_t *input,
    uint32_t timeout_ms, vireo_mysql_node_move_report_t *report, vireo_mysql_node_error_t *error);
/** @brief 软删除提交事实，独立于函数rc和资源清理。 */
typedef enum vireo_mysql_node_soft_delete_commit {
    VIREO_MYSQL_NODE_SOFT_DELETE_NOT_COMMITTED = 0, /**< 原生COMMIT未开始，不代表已确认回滚。 */
    VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED, /**< 完整COMMIT响应确认，后续清理失败仍保持。 */
    VIREO_MYSQL_NODE_SOFT_DELETE_UNKNOWN /**< 原生COMMIT已开始却未确认，DISCARD、不重放。 */
} vireo_mysql_node_soft_delete_commit_t;
/** @brief 按ID删除一个活动非根节点，非递归、不取消上传。 */
typedef struct vireo_mysql_node_soft_delete_input {
    uint64_t node_id; /**< 非零本owner活动节点ID；文件或目录，0不表示根。 */
    unsigned char request_id[16]; /**< 至少一字节非零，可信全局执行事件ID，非重试凭据。 */
} vireo_mysql_node_soft_delete_input_t;
/** @brief 不用仅ACTIVE的node_value承载已删除节点，提交事实按值发布。 */
typedef struct vireo_mysql_node_soft_delete_report {
    vireo_mysql_node_soft_delete_commit_t commit; /**< 默认NOT_COMMITTED，UNKNOWN不推定成功/失败。 */
    vireo_mysql_node_issue_t issue; /**< 固定领域拒绝/形状诊断，不直接上wire。 */
    uint64_t node_id; /**< 仅COMMITTED非零，仍是原ID，后续清理失败保持。 */
    uint64_t audit_id; /**< 仅COMMITTED非零，与删除/引用数变化同事务。 */
    uint64_t deleted_at_ms; /**< 仅COMMITTED有效，max(第一次UTC,源旧updated)；合法值可为0。 */
    bool rollback_confirmed; /**< 确定未提交分支收到ROLLBACK成功，之后close失败保持。 */
    bool cleanup_pending; /**< repo仍有子owner，同worker destroy消费；业务入口BUSY。 */
} vireo_mysql_node_soft_delete_report_t;
/**
 * @brief 同事务软删除一个活动非根文件或空目录、更新文件引用数并写成功审计
 * @param[in,out] repository 创建worker串行持有的存活repo，无残留子owner，guard/pool保活。
 * @param[in] actor 必需可信非零user/session，借至返回，本层重核身份/UTC窗口。
 * @param[in] input 必需非零节点及非全零事件ID，借至返回；不接受递归或强制标志。
 * @param[in] timeout_ms 池等待0..60000毫秒，不约束SQL/行锁/整次调用。
 * @param[out] report 必需独立值，入口重置；非OK也检查commit与cleanup_pending。
 * @param[out] error 可NULL独立去敏首因/首清理数值诊断，不保存原SQL/名字/hash。
 * @retval VIREO_OK COMMIT确认且全部资源清理成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址/线程/零身份/零节点/全零事件错误。
 * @retval VIREO_RESULT_RANGE 池等待越界，或源旧父祖先链含根超过256项。
 * @retval VIREO_RESULT_NOT_FOUND AUTH_REJECTED身份失效；NODE_NOT_FOUND源非本owner活动节点。
 * @retval VIREO_RESULT_DATABASE 根/非空目录/坏祖先/无效对象引用，或SQL/行形状/DML/提交/清理错误。
 * @retval VIREO_RESULT_BUSY repo残留子owner或池无容量。
 * @retval VIREO_RESULT_TIMEOUT 池等待到期。
 * @retval VIREO_RESULT_CANCELLED pool关闭。
 * @retval VIREO_RESULT_NO_MEMORY 依赖分配失败，无新私有可变长堆分配。
 * @retval VIREO_RESULT_IO UTC原生采样失败，原生errno单列。
 * @retval VIREO_RESULT_OVERFLOW UTC换算不可表示。
 * @retval VIREO_RESULT_INTERNAL UTC形状/依赖同步错误。
 * @note 输出：仅COMMITTED发布node_id/audit_id/deleted_at_ms，其他状态清零；提交后清理非OK仍保持。
 * @note 所有权/生命周期：所有地址独立有效不重叠，不保存输入地址；输出独立值，repo同worker销毁。
 * @note 锁序：user直接X→session S→源X→源旧父祖先S→目录孩子见证X或文件object X。
 *     同用户读写/认证DB操作可能等待；不同用户共享hash可能在object X相互等待。
 * @note 树：含根最多256祖先，不扫描后代；根拒绝，仅无直接ACTIVE/UPLOADING孩子的目录可删。
 * @note 时间：必要锁后第一次UTC、节点/对象/审计写后第二次UTC，都核issued<=now<expires才提交。
 *     节点deleted=updated=max(第一次UTC,源旧updated)，对象updated=max(第一次UTC,对象旧updated)。
 * @note 原子性：文件ref_count须>0且state为PENDING/VERIFIED/QUARANTINED，锁后减一；不证明CAS可用。
 *     保留节点hash/size/parent/name及对象state/verified时间；重复审计失败回滚全部变化。
 * @note 审计：NODE_SOFT_DELETE=7/NODE=3/status0/detail空/latency0未采集；occurred为实际第一次UTC。
 * @note 清理：保持errno，UNKNOWN只DISCARD不重放；残留归repo/BUSY，同worker destroy。
 * @note 边界：已删除源返回不存在，不再减引用；无恢复/递归/GC job/物理删除/ACL/wire/安全重试。
 *     ref_count=0并非物理回收许可，保留的节点外键及任务/读lease需后续GC协议处理。
 */
vireo_result_t vireo_mysql_node_repository_soft_delete(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_soft_delete_input_t *input,
    uint32_t timeout_ms, vireo_mysql_node_soft_delete_report_t *report, vireo_mysql_node_error_t *error);
#endif
