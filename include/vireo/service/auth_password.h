/*
 * PROJECT : VIREO
 * FILE    : auth_password.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 统一ASCII密码输入与共享KDF双限额包装合同。
 */
#ifndef VIREO_SERVICE_AUTH_PASSWORD_H
#define VIREO_SERVICE_AUTH_PASSWORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>
#include <vireo/security/password.h>

/** @brief 注册和登录共同最小长度；ASCII字符数等于字节数。 */
#define VIREO_AUTH_PASSWORD_MIN_BYTES ((size_t)8)
/** @brief 注册和登录共同最大长度；越界拒绝，不截断。 */
#define VIREO_AUTH_PASSWORD_MAX_BYTES ((size_t)64)
/** @brief 可配置同时执行数量硬上限。 */
#define VIREO_AUTH_PASSWORD_MAX_PARALLEL UINT32_C(256)
/** @brief 总矩阵参数预算下限，能容纳一个最大允许历史记录。 */
#define VIREO_AUTH_PASSWORD_MIN_BUDGET_KIB UINT32_C(262144)
/** @brief 总矩阵参数预算硬上限；不是RSS上限。 */
#define VIREO_AUTH_PASSWORD_MAX_BUDGET_KIB UINT32_C(1048576)

/** @brief 创建时复制的不可变额度，两字段均不等于worker配置。 */
typedef struct vireo_auth_password_gate_options {
    uint32_t max_parallel; /**< 同gate活动KDF数，1～256。 */
    uint32_t memory_budget_kib; /**< 活动KDF的m参数之和，262144～1048576KiB。 */
} vireo_auth_password_gate_options_t;

/** @brief 默认2个并发/256MiB矩阵参数合计预算；机器适用性由装配者判断。 */
#define VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT {UINT32_C(2), UINT32_C(262144)}

/** @brief 唯一owner持有、所有认证worker共享借用的有界KDF准入对象。 */
typedef struct vireo_auth_password_gate vireo_auth_password_gate_t;

/**
 * @brief 检查统一长度及ASCII 0x21..0x7e字符集合，不转换输入。
 *
 * @param[in] password
 *     必需非NULL；有效长度时caller保证对应可读原字节，借用至返回。
 * @param[in] password_length
 *     8～64精确字节；不要求尾NUL，不用strlen、不trim或正规化。
 *
 * @retval VIREO_OK
 *     格式政策满足，不表示密码强或认证成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     password为NULL，优先于长度检查。
 * @retval VIREO_RESULT_RANGE
 *     长度不在8～64闭区间。
 * @retval VIREO_RESULT_PROTOCOL
 *     含空格、控制字节、NUL或非ASCII；允许全部可打印非空格符号，无组合要求。
 *
 * @note 不分配、不I/O、不KDF、不锁、不保存指针且不修改errno；独立调用thread-safe。
 * @note 仅在合法长度时扫描至多64字节；不擦caller输入，没有输出。
 */
vireo_result_t vireo_auth_password_validate(void const *password, size_t password_length);

/**
 * @brief 创建并发布一个打开的共享额度对象，复制两个配置值。
 *
 * @param[in] options
 *     必需合法配置，借用至返回；max_parallel为1～256，预算为256MiB～1GiB。
 * @param[in,out] out
 *     必需独占owner地址，*out必须为NULL；成功转交对象，最终gate_destroy释放。
 *
 * @retval VIREO_OK
 *     已发布OPEN且零活动的新对象。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针NULL或*out非NULL。
 * @retval VIREO_RESULT_RANGE
 *     任一配置数值越界。
 * @retval VIREO_RESULT_NO_MEMORY
 *     对象分配失败。
 *
 * @note 失败保持*out；不执行KDF，不启动线程；所有路径保持errno。
 * @note 创建/发布由装配者外部同步；各独立输出可并发。输入与out/errno禁止重叠。
 * @note 每对象独立额度；进程总限额要求装配层让所有认证KDF共用一个对象。
 */
vireo_result_t vireo_auth_password_gate_create(
    vireo_auth_password_gate_options_t const *options, vireo_auth_password_gate_t **out);

/**
 * @brief 永久关闭新准入；已准入KDF继续并在返回前归还额度。
 *
 * @param[in,out] gate
 *     必需有效共享对象，只借用至返回。
 *
 * @retval VIREO_OK
 *     已关闭或原已关闭，无需等待在途运算。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     gate为NULL。
 *
 * @note 与准入内部原子排序；预留先发生则允许完成，关闭先发生则新准入CANCELLED。
 * @note 可重复、thread-safe，保持errno；不销毁对象、不支持重新打开或强制取消KDF。
 * @note 不保证原子实现lock-free或硬实时，不支持POSIX线程取消/longjmp跳出。
 */
vireo_result_t vireo_auth_password_gate_close(vireo_auth_password_gate_t *gate);

/**
 * @brief 在所有借用退出后排他销毁已关闭且无活动KDF的对象。
 *
 * @param[in,out] owner
 *     必需独占owner地址；*owner可NULL。成功free并清NULL，任何别名随之失效。
 *
 * @retval VIREO_OK
 *     对象已释放或owner原为空。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner为NULL。
 * @retval VIREO_RESULT_BUSY
 *     对象未关闭或仍有活动KDF；保持owner，不等待。
 *
 * @note 所有借用调用退出、worker join及排他销毁须caller保证，活动数0不能证明无借用。
 * @note 不可与任何同gate操作并发；所有路径保持errno。无秘密输入存储，无KDF。
 */
vireo_result_t vireo_auth_password_gate_destroy(vireo_auth_password_gate_t **owner);

/**
 * @brief 检查新注册密码，再自动占用65536KiB/一槽执行035生成并归还。
 *
 * @param[in,out] gate
 *     必需有效共享对象，只借用至返回；与其他hash/close可并发，不与destroy并发。
 * @param[in] password
 *     必需原始密码，只借用至返回；不修改、不保留，仅接受ASCII 0x21..0x7e。
 * @param[in] password_length
 *     8～64字节，与登录统一。
 * @param[out] encoded
 *     必需独占可写区，成功写完整PHC及尾NUL，由caller拥有和清理。
 * @param[in] capacity
 *     实际容量，至少VIREO_PASSWORD_ENCODED_CAPACITY；仅成功时写所需前缀。
 * @param[out] encoded_length
 *     必需独立可写输出，成功写精确PHC长度，不含尾NUL。
 *
 * @retval VIREO_OK
 *     生成结果已提交且本次额度已全部归还。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针NULL，优先于所有长度和准入检查。
 * @retval VIREO_RESULT_RANGE
 *     密码长度或容量越界；先于准入检查。
 * @retval VIREO_RESULT_PROTOCOL
 *     密码包含不允许的字节；先于准入检查。
 * @retval VIREO_RESULT_CANCELLED
 *     合法调用在准入时发现已关闭。
 * @retval VIREO_RESULT_BUSY
 *     槽/内存不足或至多32次原子竞争尝试耗尽；零KDF/随机源，不等待容量。
 * @retval VIREO_RESULT_NO_MEMORY
 *     035矩阵等计算内存分配失败，额度已归还。
 * @retval VIREO_RESULT_IO
 *     035安全随机源失败，额度已归还。
 * @retval VIREO_RESULT_INTERNAL
 *     035内部计算错误，额度已归还。
 *
 * @note 同步worker计算，固定035生成64MiB/3轮/p1；非OK保持整个encoded及长度。
 * @note 全部输入/输出/gate及errno不得重叠；输入调用期间不可修改；输出须独占。
 * @note 自动归还后才发布输出，所有路径保持errno、清本层临时值，不擦caller原密码。
 * @note 不支持POSIX取消/强杀/硬期限；调用方在安全点协作取消，不得提前退还运行中额度。
 * @note 不持DB/网络资源，不限频率、不统一外部登录错误，不做自动重试或重哈希。
 */
vireo_result_t vireo_auth_password_hash_create(vireo_auth_password_gate_t *gate,
    void const *password, size_t password_length, char *encoded, size_t capacity,
    size_t *encoded_length);

/**
 * @brief 先检查长度和PHC成本，再按记录m自动占用一槽验密并归还。
 *
 * @param[in,out] gate
 *     必需有效共享对象，借用至返回；共享hash/close内部同步，destroy外部排他。
 * @param[in] password
 *     必需可读原字节区，只借用至返回且保持；仅接受ASCII 0x21..0x7e。
 * @param[in] password_length
 *     8～64字节，与注册统一，不保留特殊旧密码规则。
 * @param[in] encoded
 *     必需可读canonical PHC字节区，借用至返回；不要求尾NUL。
 * @param[in] encoded_length
 *     1～127，不含尾NUL；禁止嵌NUL，复用035格式检查。
 * @param[out] matches
 *     必需独占输出，OK才写true或false，不与输入/gate/errno重叠。
 *
 * @retval VIREO_OK
 *     校验已完成，额度已归还；matches=false为正常错密。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针NULL，优先于全部长度、格式和准入检查。
 * @retval VIREO_RESULT_RANGE
 *     密码/PHC长度或单次成本越界；零KDF。
 * @retval VIREO_RESULT_PROTOCOL
 *     密码含非法字节，或PHC非canonical/算法/版本/p等不受035支持；零KDF。
 * @retval VIREO_RESULT_CANCELLED
 *     输入合法但准入发现已关闭。
 * @retval VIREO_RESULT_BUSY
 *     双额度任一不足或至多32次竞争耗尽；零KDF，不等待容量。
 * @retval VIREO_RESULT_NO_MEMORY
 *     035计算分配失败，额度已归还。
 * @retval VIREO_RESULT_INTERNAL
 *     035计算内部错误，额度已归还。
 *
 * @note 先基本指针/全部长度，再密码字符、035格式/成本，再准入；按记录m完整KiB收费。
 * @note 单次固定允许m<=262144KiB/t<=10/p1；弱历史m>=8/t>=1允许，不自动升级。
 * @note 非OK保持matches；全部输入/输出/gate/errno禁止重叠，输入调用期间不可修改。
 *       所有路径保持errno。
 * @note 借用/worker/取消/清理与资源边界同create；不擦caller输入或承诺总RSS/耗时。
 */
vireo_result_t vireo_auth_password_hash_verify(vireo_auth_password_gate_t *gate,
    void const *password, size_t password_length, char const *encoded,
    size_t encoded_length, bool *matches);

#endif
