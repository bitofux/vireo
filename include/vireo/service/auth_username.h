/*
- PROJECT : VIREO
- FILE    : auth_username.h
- AUTHOR  : bitofux
- DATE    : 2026-10-19
- BRIEF   : 此模块负责：
- -- 校验ASCII账号名并生成统一拥有型身份key
 */

#ifndef VIREO_SERVICE_AUTH_USERNAME_H
#define VIREO_SERVICE_AUTH_USERNAME_H

#include <stddef.h>
#include <vireo/base/result.h>

/** @brief 账号名最短长度，单位字节，全ASCII下等于字符数。 */
#define VIREO_AUTH_USERNAME_MIN_LENGTH ((size_t)3)
/** @brief 账号名最长长度，不含任何隐式终止字节。 */
#define VIREO_AUTH_USERNAME_MAX_LENGTH ((size_t)32)

/** @brief 调用者拥有的用户名值；两段有效前缀同长，非C字符串。 */
typedef struct vireo_auth_username {
    char username[VIREO_AUTH_USERNAME_MAX_LENGTH]; /**< 原输入大小写；有效前缀外归零。 */
    unsigned char key[VIREO_AUTH_USERNAME_MAX_LENGTH]; /**< 仅ASCII大写转小写的二进制key，尾部归零。 */
    size_t length; /**< 两数组有效字节数3..32，成功才发布，不含终止字节。 */
} vireo_auth_username_t;

/**
 * @brief 完整验证账号输入，成功才发布原显示名及统一小写key。
 *
 * 只接受ASCII A-Z、a-z、0-9和下划线；首位无额外限制。
 * 拒绝空白/NUL/非ASCII，不trim、不截断、不执行Unicode归一化。
 * 注册和登录须共用此政策，密码不得经过此转换。
 *
 * @param[in] input
 *     必需借用输入；仅合法长度时要求input_length字节可读，借用至返回。
 *     不要求尾NUL；范围外不解引用，不保存指针。
 * @param[in] input_length
 *     精确输入字节数；接受3..32，不调用strlen推导长度。
 * @param[out] out
 *     必需、对齐且存活的独占输出；与输入/errno不重叠。
 *     成功取得独立数组副本，失败整个对象字节保持。
 *
 * @retval VIREO_OK
 *     完整发布username/key/length；未使用数组尾部归零，不承诺padding。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     input或out为NULL；参数NULL检查优先于长度和字节检查。
 * @retval VIREO_RESULT_RANGE
 *     输入长度不足3或超过32，在字节检查之前返回。
 * @retval VIREO_RESULT_PROTOCOL
 *     长度合法但任一输入字节不属于上述ASCII集合。
 *
 * @note 生命周期：输出为调用者拥有的普通值，输入释放后仍有效；无销毁函数。
 * @note 线程安全：无共享可变状态；不同输出可并发，共享输出由调用者同步。
 * @note errno：不读取、保存或修改errno；不调用ctype/tolower/locale相关函数。
 * @note 副作用：无动态分配/I/O/采时/锁/等待/回调，至多处理32输入字节。
 * @note 使用：返回OK才可消费out，失败保持的旧内容不是本次成功产物。
 *       查询/唯一性/认证/限流/密码/线程交接及wire序列化由各真实消费者负责。
 *       数组不保证尾NUL，禁止对其使用strlen或无界字符串输出；不冻结ABI。
 */
vireo_result_t vireo_auth_username_prepare(
    const char *input, size_t input_length, vireo_auth_username_t *out);

#endif
