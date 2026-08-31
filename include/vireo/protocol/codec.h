/*
 * PROJECT : VIREO
 * FILE    : codec.h
 * AUTHOR  : bitofux
 * DATE    : 2026-08-21
 * BRIEF   : 当前模块的主要职责：
 * -- 在宿主语义包头与固定 32 字节 wire header 之间显式编码和解码
 * -- 验证 v1 固定 framing 常量和 body 长度硬上限
 * -- 验证请求与响应包头的基础语义
 * -- 按冻结范围计算并验证每帧 CRC-32C
 */

#ifndef VIREO_PROTOCOL_CODEC_H
#define VIREO_PROTOCOL_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

/**
 * @brief 描述 protocol codec 发现的具体协议问题
 *
 * 本枚举类型只用于 vireo 进程内部的协议诊断和显式错误映射，不是 wire protocol 字段，
 * 不可以直接序列化、持久化或强制转换为 vireo_status_t
 *
 * vireo_result_t 表示函数调用的总体成功或失败分类
 * vireo_protocol_codec_issue_t 表示协议失败时违反的具体规则
 */
typedef enum vireo_protocol_codec_issue {
    VIREO_PROTOCOL_CODEC_ISSUE_NONE = 0,
    /**< 未发现 protocol codec 问题 */

    VIREO_PROTOCOL_CODEC_ISSUE_INVALID_MAGIC = 1,
    /**< wire header 的 magic 不是固定字节序列 VIRE */

    VIREO_PROTOCOL_CODEC_ISSUE_VERSION_MISMATCH = 2,
    /**< wire header 的 version 不是当前 VIREO_PROTOCOL_VERSION */

    VIREO_PROTOCOL_CODEC_ISSUE_INVALID_HEADER_LENGTH = 3,
    /**< wire header 的 header_len 不是固定的 VIREO_PROTOCOL_HEADER_SIZE */

    VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE = 4,
    /**< body_len 超过 VIREO_PROTOCOL_MAX_BODY_SIZE 硬上限 */

    VIREO_PROTOCOL_CODEC_ISSUE_BODY_LENGTH_MISMATCH = 5,
    /**< wire header 中的 body_len 与调用者提供的实际 body_size 不一致 */

    VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_FLAGS = 6,
    /**< flags 至少包含一个 VIREO_PROTOCOL_FLAG_KNOWN_MASK 之外的 bit */

    VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_COMMAND = 7,
    /**< command 既不是当前已知命令，也不属于当前保留命令区间 */

    VIREO_PROTOCOL_CODEC_ISSUE_RESERVED_COMMAND = 8,
    /**< command 位于当前保留区间，但该命令尚未定义为可用命令 */

    VIREO_PROTOCOL_CODEC_ISSUE_INVALID_SEQUENCE = 9,
    /**< sequence 使用了正常请求和响应禁止使用的保留值 0*/

    VIREO_PROTOCOL_CODEC_ISSUE_REQUEST_HAS_RESPONSE_FLAG = 10,
    /**< 请求包错误设置了 VIREO_PROTOCOL_FLAG_RESPONSE */

    VIREO_PROTOCOL_CODEC_ISSUE_REQUEST_HAS_MORE_FLAG = 11,
    /**< 请求包错误设置了只允许响应使用的 VIREO_PROTOCOL_FLAG_MORE */

    VIREO_PROTOCOL_CODEC_ISSUE_INVALID_REQUEST_STATUS = 12,
    /**< 请求包的 status 不是固定 VIREO_PROTOCOL_REQUEST_STATUS */

    VIREO_PROTOCOL_CODEC_ISSUE_RESPONSE_MISSING_RESPONSE_FLAG = 13,
    /**< 响应包没有设置必须存在的 VIREO_PROTOCOL_FLAG_RESPONSE */

    VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_RESPONSE_STATUS = 14,
    /**< 响应包携带了当前 v1 注册表中不存在的 status */

    VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH = 15,
    /**< 重新计算的 CRC-32C 与 wire header 中携带的 crc32c 不相等 */
} vireo_protocol_codec_issue_t;

/**
 * @brief 把宿主语义包头显式编码为固定 32 字节 wire header
 *
 * 本函数将 header 中的多字节整数按照 big-endian 编码到固定 wire offset，并自动写入固定的
 * magic、version 和 header_len 同时，本函数不负责根据 body 重新计算 CRC-32C，只编码 header->crc32c
 * 的当前值。调用者需要先完成请求或响应基础验证 再调用vireo_protocol_frame_crc32c_calculate() 计算
 * CRC，最后再更新 header->crc32c 后再次编码最终 header。
 *
 * @param[in] header
 * 要编码的宿主语义包头；必须非NULL，函数只在调用期间借用该对象，不会修改、不保存且不接管所有权
 * @param[out] wire 接收 wire header 的输出缓冲区；必须是非NULL，且从该地址开始至少有 wire_capacity
 * 字节可写。 调用者始终保留缓冲区所有权。
 * @param[in] wire_capacity wire 输出缓冲区的可写容量，单位是字节；必须至少为
 * VIREO_PROTOCOL_HEADER_SIZE。当前函数 只写入前 VIREO_PROTOCOL_HEADER_SIZE 字节。
 *
 * @retval VIREO_OK 编码成功，wire 的前 32 字节包含完整 v1 wire header。
 * @retval VIREO_RESULT_INVALID_ARGUMENT header 或者 wire 为 NULL
 * @retval VIREO_RESULT_RANGE wire_capacity 小于 VIREO_PROTOCOL_HEADER_SIZE
 *         或者 header->body_len 大于 VIREO_PROTOCOL_MAX_BODY_SIZE
 *
 * @note 输出保持：函数失败时不会修改 wire 的任何字节
 * @note 所有权：函数不接管 header 或者 wire 的所有权，也不保存其地址
 * @note 生命周期：函数返回后不持有任何输入或输出对象的引用
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 * @warning 本函数完成字节编码不等于 header 已通过请求或者响应基础验证
 * @warning 禁止使用 memcpy 直接复制 vireo_protocol_header_t 作为 wire header
 */
vireo_result_t vireo_protocol_header_encode(vireo_protocol_header_t const *header, uint8_t *wire,
                                            size_t wire_capacity);

/**
 * @brief 验证固定 framing 并把 32 字节 wire header 解码为宿主语义包头
 *
 * 本函数验证 magic、version、header_len 和 body_len 硬上限，随后按照固定 wire offset 读取各个字段
 * 并将 big-endian 多字节整数转换为宿主语义值。解码成功之后，out_header->body_len 可供未来的上层
 * connection/framing 层计算完整 frame 所需字节数；只需要完整的 32 字节 header，不需要 body。
 * 不验证 CRC-32C，不验证请求或响应基础语义。
 *
 * @param[in] wire 包含 wire header 的只读字节区域；必须是非 NULL。
 *
 * @param[in] wire_size 从 wire 开始当前至少可读取的字节数；必须不小于
 * VIREO_PROTOCOL_HEADER_SIZE。大于 32 时 函数只读取前 32 个字节。
 *
 * @param[out] out_header 接收宿主语义包头的非空指针；调用者始终保留所有权。只有函数返回 VIREO_OK
 * 时才写入完整结果
 *
 * @param[out] out_issue 接收具体 codec 问题 的非空指针；调用者始终保留所有权，成功时写入
 * VIREO_PROTOCOL_CODEC_ISSUE_NONE wire 违反固定 framing 时写入对应问题
 *
 * @retval VIREO_OK 固定 framing 合法，全部可变字段已经转换为宿主语义值并写入 *out_header
 *         *out_issue 的值为 VIREO_PROTOCOL_CODEC_ISSUE_NONE
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT wire、out_header 或者 out_issue 为 NULL
 *
 * @retval VIREO_RESULT_RANGE wire_size 小于 VIREO_PROTOCOL_HEADER_SIZE
 *
 * @retval VIREO_RESULT_PROTOCOL 违反 vireo v1 协议规则，magic、version、header_len 或者 body_len
 * 硬上限违反 v1 协议 具体的协议错误写入到 *out_issue
 *
 * @note 输出保持：除了 out_issue 之外，函数失败时不修改 *out_header
 * @note out_issue：只要 out_issue 本身非 NULL，函数会在检查其他参数前先写入
 * VIREO_PROTOCOL_CODEC_ISSUE_NONE 若发现固定 framing 问题，再写入具体问题
 * @note 所有权：函数不接管 wire、out_header、out_issue 的所有权
 * @note 生命周期：函数返回后不持有任何输入或者输出对象的引用
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 * @warning VIREO_OK 只表示固定 framing 可解释，不表示 CRC 或者完整 frame 已经通过验证
 */
vireo_result_t vireo_protocol_header_decode(uint8_t const *wire, size_t wire_size,
                                            vireo_protocol_header_t *out_header,
                                            vireo_protocol_codec_issue_t *out_issue);

/**
 * @brief 验证宿主语义包头是否满足 v1 请求的基础规则
 *
 * - body_len 不超过 VIREO_PROTOCOL_MAX_BODY_SIZE
 * - flags 不包含 v1 未知 bit
 * - command 是当前已知命令，且不属于保留区间
 * - sequence 不是保留值 0
 * - 请求没有设置 VIREO_PROTOCOL_FLAG_RESPONSE
 * - 请求没有设置 VIREO_PROTOCOL_FLAG_MORE
 * - status 等于 VIREO_PROTOCOL_REQUEST_STATUS
 *
 * @param[in] header 要验证的宿主语义包头；必须是非 NULL
 *
 * @param[out] out_issue 接收具体问题的非空指针；成功时写入 VIREO_PROTOCOL_CODEC_ISSUE_NONE
 *             失败时写入检测到的具体协议问题
 *
 * @retval VIREO_OK header 满足全部 v1 请求基础规则，*out_issue 为 VIREO_PROTOCOL_CODEC_ISSUE_NONE
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT header 或者 out_issue 为 NULL
 *
 * @retval VIREO_RESULT_PROTOCOL header 违反至少一项请求基础规则，*out_issue 指明一个检测到的问题
 *
 * @note 范围边界：本函数不验证 command-specific flags 组合、session_handle、
 *                 task_handle、body schema、TLV 或 chunk 内容。
 * @note out_issue：只要 out_issue 本身非 NULL，函数会在检查其他参数前先写入
 *                  VIREO_PROTOCOL_CODEC_ISSUE_NONE
 * @note 多错输入：多个字段同时非法时，只保证报告其中一个已检测问题；
 * @note 所有权：函数不接管 header 或者 out_issue 的所有权
 * @note 生命周期：函数返回后不持有任何输入或者输出对象的引用
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
vireo_result_t vireo_protocol_request_header_validate(vireo_protocol_header_t const *header,
                                                      vireo_protocol_codec_issue_t *out_issue);

/**
 * @brief 验证宿主语义包头是否满足 v1 响应的基础规则
 *
 * - body_len 不超过 VIREO_PROTOCOL_MAX_BODY_SIZE
 * - flags 不包含 v1 未知 bit
 * - command 是当前已知命令，且不属于保留区间
 * - sequence 不是保留值 0
 * - 响应设置了 VIREO_PROTOCOL_FLAG_RESPONSE
 * - 响应允许设置 VIREO_PROTOCOL_FLAG_MORE
 * - status 是当前 v1 注册表中的已知状态
 *
 * @param[in] header 要验证的宿主语义包头；必须是非 NULL
 *
 * @param[out] out_issue 接收具体响应问题的非空指针；调用者始终保留所有权；
 *            成功时写入 VIREO_PROTOCOL_CODEC_ISSUE_NONE；失败时写入检测到的具体协议问题
 *
 * @retval VIREO_OK header 满足全部 v1 响应基础规则，*out_issue 为 VIREO_PROTOCOL_CODEC_ISSUE_NONE
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT header 或者 out_issue 为 NULL
 *
 * @retval VIREO_RESULT_PROTOCOL header 违反至少一项响应基础规则，*out_issue 指明一个检测到的问题
 *
 * @note 范围边界：本函数不验证 command-specific response mode、flags 组合、
 *                 session_handle、task_handle、body schema、TLV 或 chunk 内容。
 * @note out_issue：只要 out_issue 本身非 NULL，函数会在检查其他参数前先写入
 * VIREO_PROTOCOL_CODEC_ISSUE_NONE
 * @note 多错输入：多个字段同时非法时，只保证报告其中一个已检测问题
 * @note 严格 v1：拒绝当前 v1 注册表中不存在的响应 status
 * @note 所有权：函数不接管 header 或者 out_issue 的所有权
 * @note 生命周期：函数返回后不持有任何输入或者输出对象的引用
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
vireo_result_t vireo_protocol_response_header_validate(vireo_protocol_header_t const *header,
                                                       vireo_protocol_codec_issue_t *out_issue);

/**
 * @brief 按 v1 覆盖范围计算当前 frame 的 CRC-32C
 *
 * CRC 输入严格依次为：
 *  1. wire header 中的 [0,VIREO_PROTOCOL_CRC32C_OFFSET)
 *  2. body 中的 [0,body_size)
 * 不会计算 wire header 中位于 [VIREO_PROTOCOL_CRC32C_OFFSET,VIREO_PROTOCOL_HEADER_SIZE) 的 crc32c
 * 字段本身 每个 frame 独立计算，不跨 frame 计算 本函数返回的是 *out_crc32c 是宿主语义 uint32_t
 * 数值。调用者必须通过 vireo_protocol_header_encode() 把该数值以 big-endian 写入 wire header 的
 * crc32c 字段
 *
 * 使用标准 CRC-32C/Castagnoli 参数：
 *
 * -- 初始寄存器：0xFFFFFFFF
 * -- reflected polynomial：0x82F63B78
 * -- 最终结果：按位取反
 * -- 标准检查字符串 "123456789" 的结果：0xE3069283
 *
 * @param[in] wire
 *      完整 32 字节 wire header 的起始地址；必须是非 NULL；
 *      wire 应该来自 vireo_protocol_header_encode()
 *      或者已经通过 vireo_protocol_header_decode()的固定 framing 校验
 *
 * @param[in] wire_size
 *      从 wire 开始当前至少可读取的字节数；必须不小于 VIREO_PROTOCOL_HEADER_SIZE
 *      函数只读取前 32 字节中的[0, VIREO_PROTOCOL_CRC32C_OFFSET) 和编码的 body_len。
 *
 * @param[in] body
 *     当前 frame 的完整只读 body。
 *     body_size 为 0 时允许为 NULL；
 *     body_size 大于 0 时必须指向至少 body_size 个可读字节。
 *
 * @param[in] body_size
 *     body 的实际字节数；必须不超过 VIREO_PROTOCOL_MAX_BODY_SIZE，
 *     并且必须等于 wire header 中以 big-endian 编码的 body_len。
 *
 * @param[out] out_crc32c
 *     接收宿主字节序 CRC-32C 数值的非空指针；调用者始终保留所有权。
 *     只有函数返回 VIREO_OK 时才写入结果。
 *
 * @retval VIREO_OK
 *     CRC-32C 计算成功，*out_crc32c 已写入宿主语义数值。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     wire 或 out_crc32c 为 NULL，或者 body_size 大于 0 但 body 为 NULL。
 *
 * @retval VIREO_RESULT_RANGE
 *     wire_size 小于 VIREO_PROTOCOL_HEADER_SIZE，body_size 超过协议硬上限，
 *     或者 wire header 中的 body_len 与 body_size 不一致。
 *
 * @note 输出保持：函数失败时不修改 *out_crc32c。
 * @note 所有权：函数不接管 wire、body 或 out_crc32c 的所有权。
 * @note 生命周期：函数返回后不持有任何输入或输出对象的引用。
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 安全边界：CRC-32C 用于发现意外数据损坏，不提供密码学认证，
 *       不能替代 TLS 或消息认证机制。
 */
vireo_result_t vireo_protocol_frame_crc32c_calculate(uint8_t const *wire, size_t wire_size,
                                                     uint8_t const *body, size_t body_size,
                                                     uint32_t *out_crc32c);

/**
 * @brief 验证 wire header 中携带的 crc32c 是否与当前 frame 内容一致
 *
 * 本函数从 wire header 的 VIREO_PROTOCOL_CRC32C_OFFSET 读取
 * big-endian CRC-32C 数值，再按照 v1 冻结覆盖范围重新计算并比较。
 *
 * 调用本函数前，wire header 应已经通过
 * vireo_protocol_header_decode() 的固定 framing 校验，并且完整 body
 * 已经到达。本函数不重复验证 magic、version、header_len、请求或响应
 * 基础语义。
 *
 * @param[in] wire
 *     完整 32 字节 wire header 的起始地址；必须非 NULL。
 *     函数只在调用期间借用，不修改、不保存且不接管所有权。
 *
 * @param[in] wire_size
 *     从 wire 开始当前至少可读取的字节数；必须不小于
 *     VIREO_PROTOCOL_HEADER_SIZE。
 *
 * @param[in] body
 *     当前 frame 的完整只读 body。
 *     body_size 为 0 时允许为 NULL；
 *     body_size 大于 0 时必须指向至少 body_size 个可读字节。
 *
 * @param[in] body_size
 *     body 的实际字节数；必须不超过 VIREO_PROTOCOL_MAX_BODY_SIZE，
 *     并且必须等于 wire header 中以 big-endian 编码的 body_len。
 *
 * @param[out] out_issue
 *     接收具体 CRC 或长度问题的非空指针；调用者始终保留所有权。
 *     验证成功时写入 VIREO_PROTOCOL_CODEC_ISSUE_NONE。
 *
 * @retval VIREO_OK
 *     重新计算的 CRC-32C 与 wire header 中携带的数值相等，
 *     *out_issue 为 VIREO_PROTOCOL_CODEC_ISSUE_NONE。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     wire 或 out_issue 为 NULL，或者 body_size 大于 0 但 body 为 NULL。
 *
 * @retval VIREO_RESULT_RANGE
 *     wire_size 小于 VIREO_PROTOCOL_HEADER_SIZE，body_size 超过协议硬上限，
 *     或者 wire header 中的 body_len 与 body_size 不一致。
 *     body 长度不一致时 *out_issue 为
 *     VIREO_PROTOCOL_CODEC_ISSUE_BODY_LENGTH_MISMATCH。
 *
 * @retval VIREO_RESULT_PROTOCOL
 *     重新计算的 CRC-32C 与 wire header 中携带的数值不相等，
 *     *out_issue 为 VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH。
 *
 * @note out_issue：只要 out_issue 本身非 NULL，函数会在检查其他参数前先
 *       写入 VIREO_PROTOCOL_CODEC_ISSUE_NONE。
 * @note 所有权：函数不接管 wire、body 或 out_issue 的所有权。
 * @note 生命周期：函数返回后不持有任何输入或输出对象的引用。
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 安全边界：CRC-32C 只检测意外损坏，不证明发送方身份或抵抗主动篡改。
 */
vireo_result_t vireo_protocol_frame_crc32c_verify(uint8_t const *wire, size_t wire_size,
                                                  uint8_t const *body, size_t body_size,
                                                  vireo_protocol_codec_issue_t *out_issue);

#endif /* VIREO_PROTOCOL_CODEC_H */
