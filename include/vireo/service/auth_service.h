/*
 * PROJECT : VIREO
 * FILE    : auth_service.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 注册/登录服务编排与拥有型秘密输出。
 */
#ifndef VIREO_SERVICE_AUTH_SERVICE_H
#define VIREO_SERVICE_AUTH_SERVICE_H

#include <stddef.h>
#include <stdint.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <vireo/service/auth_login_verifier.h>
#include <vireo/service/auth_password.h>

/** @brief 单次注册的只读短借输入；metadata必须由可信服务装配。 */
typedef struct vireo_auth_registration_request {
    const char *username; /**< 借用原始显示名，3..32字节ASCII字母/数字/下划线。 */
    size_t username_length; /**< 精确字节数，无尾NUL要求，不trim或截断。 */
    const void *password; /**< 借用原密码，8..64字节ASCII 0x21..0x7e；caller负责清理。 */
    size_t password_length; /**< 精确字节数，无组合要求，不转换。 */
    unsigned char request_id[16]; /**< 可信非全零事件ID；不是客户端声明或业务幂等key。 */
    uint64_t occurred_at_ms; /**< 可信UTC epoch毫秒，允许0；不读取隐式时钟。 */
    uint64_t latency_us; /**< 可信调用前请求耗时快照，微秒；不含本次KDF/DB。 */
} vireo_auth_registration_request_t;

/** @brief 单次已获LOGIN尝试准入的输入；本类型本身不证明准入或TLS。 */
typedef struct vireo_auth_login_request {
    const char *username; /**< 借用原始账号；必须与Reactor准入使用的请求相同。 */
    size_t username_length; /**< 统一3..32字节规则，不从客户端接收独立username_key。 */
    const void *password; /**< 借用原密码，统一8..64字节规则；caller负责清理。 */
    size_t password_length; /**< 精确字节数，无尾NUL要求。 */
    unsigned char request_id[16]; /**< 可信非全零LOGIN事件ID；不是可重放的事务回执key。 */
    uint64_t issued_at_ms; /**< 可信UTC epoch毫秒；也是登录成功审计的事件时间。 */
    uint64_t expires_at_ms; /**< 可信绝对UTC到期时间，严格大于issued；无隐式默认TTL。 */
    uint64_t latency_us; /**< 调用service前耗时快照，微秒；不含本次查库/KDF/事务。 */
} vireo_auth_login_request_t;

/**
 * @brief caller拥有的登录结果；包含秘密，禁止日志、直接序列化或当作wire结构。
 * @note 唯一token有效条件是transaction.commit==COMMITTED，不能检查返回码或全零字节。
 *       未提交/UNKNOWN时user/time/token为零；COMMITTED即使清理失败仍发布完整拥有型值。
 *       lookup和transaction只供内部使用，清理义务取两者cleanup_pending的或。
 */
typedef struct vireo_auth_login_result {
    vireo_mysql_credentials_report_t lookup; /**< 凭据查询事实；未查询全零，错误不得当作缺失。 */
    vireo_mysql_login_report_t transaction; /**< 登录事务原始事实；未调用时NOT_COMMITTED。 */
    uint64_t user_id; /**< 仅确认提交时非零；来自所验凭据快照。 */
    uint64_t issued_at_ms; /**< 仅确认提交时发布请求中的时间；0也可为合法时间。 */
    uint64_t expires_at_ms; /**< 仅确认提交时发布；不保证返回时尚未到期。 */
    vireo_session_token_t token; /**< 确认提交后唯一对外候选bearer副本，复制后各owner均须清理。 */
} vireo_auth_login_result_t;

/**
 * @brief 统一校验输入，在事务外生成PHC，再调用现有注册事务并清理自有临时值。
 *
 * @param[in,out] repository
 *     必需当前OS worker创建且无残留清理责任的R，短借且同对象串行，不转移owner。
 * @param[in,out] gate
 *     必需全服务共享的存活KDF gate，只借至返回。
 * @param[in] request
 *     必需完整只读输入；全部span有效至返回，服务不保存或清除caller密码。
 * @param[in] timeout_ms
 *     每次pool等待0..60000毫秒，不能解释为KDF/SQL/整次操作的硬期限。
 * @param[out] report
 *     必需独占输出；复用注册报告，非OK也必须检查commit与cleanup_pending。
 * @param[out] error
 *     可NULL，保存repository无文本诊断；尚未调用DB时为零。
 *
 * @retval VIREO_OK
 *     账户/根目录/成功审计确认提交且repository本次清理完成；不自动登录。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针为空、事件ID全零，或repository拒绝线程/guard等参数。
 * @retval VIREO_RESULT_RANGE
 *     用户名/密码长度或timeout越界。
 * @retval VIREO_RESULT_PROTOCOL
 *     用户名或密码含不允许的字节，或底层PHC格式不获准。
 * @retval VIREO_RESULT_BUSY
 *     KDF gate无额度、repository有残留责任或pool无容量。
 * @retval VIREO_RESULT_CANCELLED
 *     gate或pool已关闭。
 * @retval VIREO_RESULT_NO_MEMORY
 *     KDF或repository分配失败。
 * @retval VIREO_RESULT_IO
 *     密码salt安全随机源失败。
 * @retval VIREO_RESULT_TIMEOUT
 *     pool等待到期。
 * @retval VIREO_RESULT_DATABASE
 *     注册SQL/唯一冲突/清理失败；按report判定持久结果。
 * @retval VIREO_RESULT_INTERNAL
 *     密码或数据库依赖内部失败。
 *
 * @note 任一必需地址NULL时不改输出；地址齐备后先重置report/error，再验证内容。
 *       顺序为基础参数/timeout/事件ID、用户名、密码政策、KDF、一次register、统一清理。
 *       COMMITTED后清理失败不改写提交事实；UNKNOWN不自动重放，无隐式事务补偿。
 * @note 同步worker入口，可能阻塞；保持errno。不接fd、connection、wire或TLS对象。
 *       所有输入/输出/R/gate/errno互不重叠，输入调用期间不可变。不内部destroy或替换R。
 *       PHC及本次repository输入临时存储在所有正常返回路径安全擦除；不支持异步取消/longjmp。
 *       R线程/guard与可用性由caller保证，不能承诺register之前已核R的opaque内部状态。
 */
vireo_result_t vireo_auth_service_register(vireo_mysql_user_repository_t *repository,
    vireo_auth_password_gate_t *gate, const vireo_auth_registration_request_t *request,
    uint32_t timeout_ms, vireo_mysql_registration_report_t *report,
    vireo_mysql_user_repository_error_t *error);

/**
 * @brief 查凭据并释放连接后统一验密，生成token并提交登录，按提交事实交付独立结果。
 *
 * @param[in,out] repository
 *     必需当前OS worker独占的存活R，无残留责任；不接管或销毁。
 * @param[in,out] gate
 *     必需与其他认证KDF相同的共享gate，只借至返回。
 * @param[in] verifier
 *     必需已发布只读验证器，借至返回；不逐请求创建dummy PHC。
 * @param[in] request
 *     必需已完成TLS/schema/统一输入合法性与一次LOGIN准入的不可变请求。
 *     这些网络前置由可信装配层保证；此函数仍复验用户名/密码政策，不复扣准入。
 * @param[in] timeout_ms
 *     每次pool等待0..60000毫秒；查询和写事务各一次，非合计硬期限。
 * @param[in,out] result
 *     必需独占拥有型输出；必需地址齐备后先擦旧内容，再按已发生阶段填写事实。
 *     caller在调用前须已处理旧结果的交付/清理责任，不能靠覆盖来撤销旧Session。
 * @param[out] error
 *     可NULL，每次重置；查询或事务的无文本首因/首清理诊断，不含账号或秘密。
 *
 * @retval VIREO_OK
 *     已确认COMMIT且清理完成，result含完整token与持久身份。
 * @retval VIREO_RESULT_NOT_FOUND
 *     完整缺失/错密/禁用，或事务重核账户消失/禁用/PHC变化；统一认证拒绝。
 *     若查询或重核拒绝后的清理出错，返回首清理错误而不是强行返回NOT_FOUND。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/事件ID错误，或repository拒绝线程/guard。
 * @retval VIREO_RESULT_RANGE
 *     统一长度/timeout/时间关系越界、PHC成本超限，或签发早于用户创建。
 * @retval VIREO_RESULT_PROTOCOL
 *     输入字符或存储PHC非法；不伪装成错密。
 * @retval VIREO_RESULT_BUSY
 *     gate、pool或repository暂不可用；不退款、不等待KDF容量。
 * @retval VIREO_RESULT_CANCELLED
 *     gate或pool关闭；在途执行遵循下层合同。
 * @retval VIREO_RESULT_TIMEOUT
 *     某次pool等待到期。
 * @retval VIREO_RESULT_NO_MEMORY
 *     验密、token摘要或数据库资源分配失败。
 * @retval VIREO_RESULT_IO
 *     token安全随机源失败，不降级或重试。
 * @retval VIREO_RESULT_DATABASE
 *     查库/事务/清理失败，不能当作账号缺失；提交事实独立有效。
 * @retval VIREO_RESULT_INTERNAL
 *     下层计算或同步设施内部失败。
 *
 * @note 任一必需地址NULL时保持输出。地址齐备后擦result/清error，先校验全部输入和metadata。
 *       查询仅完整NOT_FOUND且无清理错误/残留时传NULL做dummy验密；其他错误停止，不生成token。
 *       统一验密false直接拒绝；true才生成一次token/digest并调用一次登录事务。
 *       凭据查询连接须已归还再执行KDF，写事务内再核active/同PHC。
 * @note COMMITTED即使函数非OK也交付token/身份；caller同时履行清理责任，不能按返回码抹去成功。
 *       NOT_COMMITTED/UNKNOWN无token；UNKNOWN不自动重放，不生成第二个token假设失败。
 *       lookup或transaction的cleanup_pending为true时，保留R并同worker destroy后才能继续业务。
 * @note 保持errno；所有地址有效、对齐、互不重叠且不指向errno，密码/凭据调用期间不可变。
 *       worker同步阻塞，同R串行，独立R可共享gate/verifier；不支持异步取消/longjmp。
 *       本次credentials/PHC引用DTO/token/digest在返回前统一擦除，成功result归caller清理。
 *       不持fd、不绑定connection、不编码响应、不发失败审计；不保证端到端恒时。
 */
vireo_result_t vireo_auth_service_login(vireo_mysql_user_repository_t *repository,
    vireo_auth_password_gate_t *gate, const vireo_auth_login_verifier_t *verifier,
    const vireo_auth_login_request_t *request, uint32_t timeout_ms,
    vireo_auth_login_result_t *result, vireo_mysql_user_repository_error_t *error);

/**
 * @brief 在交付与诊断读取结束后安全清除当前登录结果全部存储，允许重复调用。
 * @param[in,out] result
 *     必需独占存活值；擦除前已保存必要事实并处理两阶段cleanup_pending。
 * @retval VIREO_OK
 *     当前整个值清零；不释放内存、不处理副本、不撤销数据库Session。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     result为NULL。
 * @note 保持errno，无分配/I/O；独立值thread-safe，共享值须外部同步。
 *       结果清零不是事务回滚或logout，不能丢弃repository仍持有的owner。
 */
vireo_result_t vireo_auth_login_result_clear(vireo_auth_login_result_t *result);

/**
 * 同OS worker同步短借repository/token，timeout0..60000，now为可信UTC毫秒。
 * 必需R/token/identity/report；error可NULL。必需地址齐全后先清输出；
 * 仅OK且report.valid/无cleanup_pending发布身份，其他路径全零。
 * 摘要失败可NO_MEMORY/INTERNAL，其他沿repo原返回；本地digest/token临时区擦除。
 * 不调用KDF/生成token/续期/审计；输入输出/R/errno不重叠，保持errno。
 */
vireo_result_t vireo_auth_service_resume(vireo_mysql_user_repository_t *repository,
    vireo_session_token_t const *token, uint64_t now_utc_ms, uint32_t timeout_ms,
    vireo_mysql_session_identity_t *identity, vireo_mysql_session_report_t *report,
    vireo_mysql_user_repository_error_t *error);

/**
 * 同OS worker短借可信input及R，timeout0..60000；必需R/input/report，error可NULL。
 * 输入/报告/返回/重置及cleanup_pending完全沿repo logout，原commit不可按rc改写。
 * COMMITTED清理错仍提交；UNKNOWN无重放。无网络状态，保持errno，不管理R。
 */
vireo_result_t vireo_auth_service_logout(vireo_mysql_user_repository_t *repository,
    vireo_mysql_logout_input_t const *input, uint32_t timeout_ms,
    vireo_mysql_logout_report_t *report, vireo_mysql_user_repository_error_t *error);


#endif
