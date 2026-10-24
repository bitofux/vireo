/* PROJECT : VIREO; FILE : directory_name.h; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : 新节点名单段UTF-8/NAME/NFC校验。 */
#ifndef VIREO_SERVICE_DIRECTORY_NAME_H
#define VIREO_SERVICE_DIRECTORY_NAME_H
#include <stddef.h>
#include <vireo/base/result.h>

/** @brief 名字按原始UTF-8字节计数，不按字符或规范化后的长度计数。 */
#define VIREO_DIRECTORY_NAME_CAPACITY ((size_t)255)

/** @brief 只描述客户端提供的名字，不保存名字或Unicode库错误文本。 */
typedef enum vireo_directory_name_issue {
    VIREO_DIRECTORY_NAME_ISSUE_NONE = 0, /**< 合法或基础设施失败，没有已确认名字拒绝。 */
    VIREO_DIRECTORY_NAME_ISSUE_LENGTH = 1, /**< 原名字不在1..255字节。 */
    VIREO_DIRECTORY_NAME_ISSUE_UTF8 = 2, /**< 不完整或非法UTF-8。 */
    VIREO_DIRECTORY_NAME_ISSUE_SYNTAX = 3, /**< 点/双点、斜杠、NUL或C0/C1控制字符。 */
    VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC = 4 /**< 合法NAME，但规范组合结果与原字节不同。 */
} vireo_directory_name_issue_t;

/**
 * @brief 检查新节点名已经是NFC，不修改、返回或保存规范化后的名字
 *
 * @param[in] name
 *     必需稳定只读name_length字节，无尾NUL要求；仅借至返回。
 * @param[in] name_length
 *     原始字节数，1..255；先检查长度，再读取字节或窄化。
 * @param[out] issue
 *     必需独立独占输出；必需地址齐备后先置NONE，再按确证的名字拒绝填写。
 *
 * @retval VIREO_OK
 *     NAME及NFC均合法，issue=NONE。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     name或issue为NULL；不修改任何输出。
 * @retval VIREO_RESULT_RANGE
 *     长度不在1..255，issue=LENGTH，不读取name。
 * @retval VIREO_RESULT_PROTOCOL
 *     issue=UTF8、SYNTAX或NOT_NFC；不代表数据库或授权结果。
 * @retval VIREO_RESULT_NO_MEMORY
 *     Unicode库分配失败，issue=NONE，不能映射成非法名字。
 * @retval VIREO_RESULT_OVERFLOW
 *     Unicode库受检表示失败，issue=NONE。
 * @retval VIREO_RESULT_INTERNAL
 *     固定配置/依赖返回关系异常，issue=NONE。
 *
 * @note 顺序：长度→借助既有TLV NAME规则检查UTF-8/单段约束→显式长度NFC→字节比较。
 *     先比较规范化长度，再按原长度memcmp；不截断、trim、casefold或NFKC。
 *     未开启拒绝未分配码点/忽略字符等额外政策。
 * @note 所有权：不接管输入；内部暂存最多259字节TLV，并临时拥有Unicode库malloc结果，
 *     在返回前free。库内部仍会分配，不承诺整个调用无分配或固定RSS。
 * @note 全部地址有效、对齐、互不重叠且不指向errno；name仅在有效长度时须可读取。
 *     无fd、SQL、锁、时钟、回调注册或持久缓存；独立输入输出可并发，保持入口errno。
 *     普通worker同步调用，不承诺signal-safe、硬实时或POSIX异步取消安全。
 * @note UTF-8/NAME本身不等于NFC；NFC不折叠大小写、宽度或视觉同形字符。
 */
vireo_result_t vireo_directory_name_validate(const unsigned char *name, size_t name_length,
    vireo_directory_name_issue_t *issue);
#endif
