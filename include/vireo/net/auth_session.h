/* PROJECT: VIREO; FILE: auth_session.h; AUTHOR: bitofux; DATE: 2026-10-20.
 * Reactor固定Session映射；不保存bearer，不修改旧connection布局。 */
#ifndef VIREO_NET_AUTH_SESSION_H
#define VIREO_NET_AUTH_SESSION_H
#include <vireo/net/tcp_server.h>
#define VIREO_AUTH_SESSION_MEMORY_MAX ((size_t)67108864)
typedef struct vireo_auth_sessions vireo_auth_sessions_t;
/** 来自可信已提交认证的纯身份，不是数据库当前性证明。 */
typedef struct vireo_auth_session_identity {
    uint64_t user_id; /**< 非零。 */
    uint64_t session_id; /**< 非零SQL身份，不是短handle。 */
    uint64_t issued_at_ms; /**< UTC epoch毫秒，0合法。 */
    uint64_t expires_at_ms; /**< 严格大于issued。 */
    bool revoked; /**< 本地失效标志；caller仍负责DB撤销同步。 */
} vireo_auth_session_identity_t;
/** 同表唯一保留票据；复制不增加权限/寿命，caller不得篡改/重放。 */
typedef struct vireo_auth_session_ticket {
    vireo_connection_pool_lease_t client; /**< 完整owner/slot/generation。 */
    uint64_t serial; /**< 本表非零且不回绕的候选实例。 */
    uint32_t handle; /**< 非零随机且与表内active/pending均不碰撞。 */
} vireo_auth_session_ticket_t;
/** 显式预算，表容量采用server.connection_capacity；不含server/allocator开销。 */
typedef struct vireo_auth_sessions_options { size_t max_memory_bytes; } vireo_auth_sessions_options_t;
/**
 * @brief 为存活server建立固定表；成功才发布空owner，借用server直到destroy
 * @return OK；NULL/非空owner/零预算INVALID_ARGUMENT；预算超64MiB/不足RANGE；
 *         checked算术OVERFLOW；分配NO_MEMORY；原server错误透传。
 * @note options短借，out独立；create/destroy须排除全部访问。表全API Reactor-only、
 *       保持errno，无锁，无数据库/网络I/O，不拥有server；server须比表活得久。
 */
vireo_result_t vireo_auth_sessions_create(vireo_tcp_server_t *server,
    vireo_auth_sessions_options_t const *options, vireo_auth_sessions_t **out);
/**
 * @brief 保留一个候选handle，保持旧active；同连接最多一个pending
 * @param[in,out] table 必需存活表，串行访问，不能并发销毁。
 * @param[in] client 当前server的完整租约；仅数值关联，不是用户凭据。
 * @param[in] identity 必需可信已提交且未revoked身份，只短借。
 * @param[out] out 必需独立票据，失败保持；成功后必须commit或abort/forget。
 * @return OK；非法值INVALID_ARGUMENT；旧客户NOT_FOUND；槽范围RANGE；
 *         已有pending、随机0或表内碰撞BUSY；RAND失败IO；serial耗尽OVERFLOW。
 * @note 一次RAND_priv_bytes4，不重试；可能初始化/阻塞，不承诺硬实时。
 *       新代当前客户可替换本槽旧代记录，旧票据随后失效。O(capacity)碰撞扫描。
 *       失败保持表/out；运行无申请，不证明TLS/数据库撤销或UTC新鲜度。
 */
vireo_result_t vireo_auth_session_reserve(vireo_auth_sessions_t *table,
    vireo_connection_pool_lease_t client, vireo_auth_session_identity_t const *identity,
    vireo_auth_session_ticket_t *out);
/**
 * @brief 同一Reactor在响应整帧入队后提交候选，替换原active，无分配/采样/I/O
 * @return OK；NULL/畸形票据INVALID_ARGUMENT；候选已失效NOT_FOUND。
 * @note caller保证reserve至commit间不forget/abort/替换本候选；合法串行执行无失败点。
 *       不查server/当前时间；consumer须在入队前核当前性。已过期/本地撤销者lookup拒绝。
 */
vireo_result_t vireo_auth_session_commit(vireo_auth_sessions_t *table, vireo_auth_session_ticket_t ticket);
/** 清唯一匹配pending、保旧active。返回同commit；无I/O/采样，失败保持。 */
vireo_result_t vireo_auth_session_abort(vireo_auth_sessions_t *table, vireo_auth_session_ticket_t ticket);
/**
 * @brief 核当前server完整租约、active handle、显式可信UTC和本地撤销后发布身份
 * @return OK；NULL/handle0/畸形租约INVALID_ARGUMENT；客户/绑定/handle缺失NOT_FOUND；
 *         过期TIMEOUT；本地revoked CANCELLED；原inspect错误透传。失败保持out。
 * @note 不证明DB后来未撤销、不检查业务权限；未来受保护命令还须接撤销/用户状态政策。
 *       不保存out，无token，无申请；所有输入/输出/errno独立。不是仅凭handle跨连接查找。
 */
vireo_result_t vireo_auth_session_lookup(vireo_auth_sessions_t const *table,
    vireo_connection_pool_lease_t client, uint32_t handle, uint64_t now_utc_ms,
    vireo_auth_session_identity_t *out);
/** 将此SQL Session所有active/pending本地标revoked；非零ID，未命中NOT_FOUND，不改DB。 */
vireo_result_t vireo_auth_session_revoke(vireo_auth_sessions_t *table, uint64_t session_id);
/** 释放连接时清精确代次的active/pending；旧票据不能清新客户。无匹配NOT_FOUND。 */
vireo_result_t vireo_auth_session_forget(vireo_auth_sessions_t *table, vireo_connection_pool_lease_t client);
/** 无pending才擦全表并free/清owner；有pending BUSY；空owner重复OK；NULL地址非法。 */
vireo_result_t vireo_auth_sessions_destroy(vireo_auth_sessions_t **owner);
/** Reactor-only，必需表与非零可信实例号；严格大于last才OK并更新，否则INVALID_ARGUMENT。
 * 在worker可执行前调用一次，登记失败也不退水位；无分配/I/O，保持errno。 */
vireo_result_t vireo_auth_session_note_resume(vireo_auth_sessions_t *sessions,
    uint64_t request_instance_id);
/** Reactor-only：非零id；cutoff<id<=last为OK；<=cutoff为BUSY，>last为NOT_FOUND。
 * NULL/0为INVALID_ARGUMENT；不认证客户端或冻结未来状态，无副作用，保持errno。 */
vireo_result_t vireo_auth_session_check_resume(vireo_auth_sessions_t const *sessions,
    uint64_t request_instance_id);
/** Reactor-only，必需表和非零SQL Session ID；推进cutoff到last并撤销匹配active/pending。
 * 无命中仍OK；NULL/0为INVALID_ARGUMENT。只供可信COMMITTED/UNKNOWN结果，一次效果receipt
 * 防重复推进；函数本身不认证来源、不跨调用防重或修改DB。无分配/I/O，保持errno。 */
vireo_result_t vireo_auth_session_apply_logout(vireo_auth_sessions_t *sessions,
    uint64_t session_id);

#endif
