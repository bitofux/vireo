/*
 * PROJECT : VIREO
 * FILE    : auth_login_verifier.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 统一登录验密结果，并为不存在的账户执行受限真实替代验密。
 */
#ifndef VIREO_SERVICE_AUTH_LOGIN_VERIFIER_H
#define VIREO_SERVICE_AUTH_LOGIN_VERIFIER_H

#include <stdbool.h>
#include <stddef.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <vireo/service/auth_password.h>

/** @brief 发布后只读的替代PHC唯一owner；不持有密码、gate、repository或连接。 */
typedef struct vireo_auth_login_verifier vireo_auth_login_verifier_t;

/**
 * @brief 用共享gate生成一次真实替代PHC，完成后发布只读验证器。
 *
 * @param[in,out] gate
 *     必需存活的共享KDF gate，短借至返回；不保存或接管其owner。
 * @param[in,out] out
 *     必需独占owner地址且*out为NULL；成功取得对象，最终由destroy清理。
 *
 * @retval VIREO_OK
 *     已生成64MiB/3轮/p1的替代PHC并清除随机临时密码；不保存明文密码。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     gate/out为NULL或*out非NULL，先于分配/随机源/KDF。
 * @retval VIREO_RESULT_NO_MEMORY
 *     对象分配或KDF内存申请失败；已清除并释放本层临时资源。
 * @retval VIREO_RESULT_IO
 *     安全随机源失败；不使用弱随机数降级。
 * @retval VIREO_RESULT_BUSY
 *     共享gate额度不足；不等待容量，不在请求内重复构造。
 * @retval VIREO_RESULT_CANCELLED
 *     共享gate已关闭。
 * @retval VIREO_RESULT_INTERNAL
 *     密码生成依赖错误或生成结果不满足固定格式/成本不变量。
 *
 * @note 非OK保持*out；保持errno。一次分配、32随机字节转64个ASCII十六进制字符，
 *       然后复用041-02生成；随机字节/临时密码及失败对象在返回前显式清除。
 * @note 同步昂贵运算，只在启动/worker执行；成功后外部同步发布，供worker共享只读借用。
 *       不调用数据库/网络，不支持POSIX取消/longjmp/硬期限；失败由装配者处理后再发布服务。
 */
vireo_result_t vireo_auth_login_verifier_create(
    vireo_auth_password_gate_t *gate, vireo_auth_login_verifier_t **out);

/**
 * @brief 对真实或替代PHC完成一次受限验密，仅active账户的匹配结果为true。
 *
 * @param[in] verifier
 *     必需已发布存活对象，只读短借至返回。
 * @param[in,out] gate
 *     必需存活共享KDF gate；所有认证KDF应使用同一gate，本对象不保存指针。
 * @param[in] credentials
 *     可NULL，仅在repository查询明确NOT_FOUND且无残留清理责任时传NULL。
 *     非NULL须是可信查询完整OK产出的拥有型快照，含非零user_id、ACTIVE或DISABLED，
 *     PHC长度1..127；短借至返回，不修改、不清除。不得用NULL掩盖DB/清理错误。
 * @param[in] password
 *     必需只读原始密码，借至返回；保持041-02的ASCII非空格8～64字节规则。
 * @param[in] password_length
 *     精确字节数8～64，不要求尾NUL，不trim/转换/截断。
 * @param[out] authenticated
 *     必需独占布尔输出；OK才写；true只表示当前快照active且密码匹配。
 *
 * @retval VIREO_OK
 *     验密正常完成：不存在/错密/禁用统一false；不存在时即使替代PHC匹配也为false。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为NULL，或非NULL凭据的ID/状态不是完整快照。
 * @retval VIREO_RESULT_RANGE
 *     密码或PHC长度越界，或PHC成本超限。
 * @retval VIREO_RESULT_PROTOCOL
 *     密码字节不符合政策，或PHC格式不合法；不降级为认证false。
 * @retval VIREO_RESULT_BUSY
 *     共享gate无额度或有限竞争耗尽，未执行KDF。
 * @retval VIREO_RESULT_CANCELLED
 *     共享gate关闭，未执行KDF。
 * @retval VIREO_RESULT_NO_MEMORY
 *     KDF内存分配失败，额度已经归还。
 * @retval VIREO_RESULT_INTERNAL
 *     KDF依赖内部错误，额度已经归还。
 *
 * @note 非OK保持authenticated，保持errno；输入/输出/对象/gate/errno互不重叠。
 *       先必需指针、密码政策，再凭据形态，最后复用041-02；合法请求至多一次KDF。
 * @note active/disabled均使用真实PHC，NULL使用固定替代PHC，统一使用传入gate计费。
 *       不逐请求生成替代PHC，不睡眠补时，不保证端到端或不同成本记录的耗时恒定。
 * @note 同对象可并发只读验证，gate遵循其共享合同；输入调用期间不可并发修改。
 *       destroy须等待全部借用退出。同步worker计算；调用者负责清除原密码与凭据。
 * @note true不是已登录：后续须在事务内重新核对active/同PHC快照，按确认COMMIT决定发token。
 *       不执行DB/限频/审计/网络编码，不输出内部账户分类或PHC，不作自动重试。
 */
vireo_result_t vireo_auth_login_verifier_verify(vireo_auth_login_verifier_t const *verifier,
    vireo_auth_password_gate_t *gate, vireo_mysql_user_credentials_t const *credentials,
    void const *password, size_t password_length, bool *authenticated);

/**
 * @brief 所有借用退出后排他清除整个验证器并释放唯一owner。
 *
 * @param[in,out] owner
 *     必需独占owner地址，*owner可NULL；成功清NULL，别名随之失效。
 *
 * @retval VIREO_OK
 *     已清理或owner原为空；不操作gate、repository或数据库。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner地址为NULL。
 *
 * @note 保持errno；不可与同对象任何借用并发，不内部等待。先停止新请求并join所有worker，
 *       再销毁本对象；不需要单独close，不接管外部gate生命周期。
 */
vireo_result_t vireo_auth_login_verifier_destroy(vireo_auth_login_verifier_t **owner);

#endif
