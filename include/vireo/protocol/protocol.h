/*
 * PROJECT : VIREO
 * FILE    : protocol.h
 * AUTHOR  : bitofux
 * DATE    : 2026-08-18
 * BRIEF   : 定义 vireo v1 线协议(wire protocol)
 * -- 定义 32 字节固定包头的常量、offset 和字段长度
 * -- 定义协议 flags、command、status 注册表
 * -- 定义已经通过 framing 校验后的宿主语义包头
 * -- 提供 command、status、flags 纯查询函数
 */

#ifndef VIREO_PROTOCOL_PROTOCOL_H
#define VIREO_PROTOCOL_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>

/*
 * vireo 的 magic 固定常量值
 *
 * 'V' = 0x56
 * 'I' = 0x49
 * 'R' = 0x52
 * 'E' = 0x45
 *
 * 它是一个多字节整数常量，在后续的 codec 按照网络字节序将其编码为0x56 0x49 0x52 0x45
 * 不可以直接复制该整数在宿主机中的内存表示
 */
#define VIREO_PROTOCOL_MAGIC_VALUE UINT32_C(0x56495245)

/* vireo 当前线协议版本 */
#define VIREO_PROTOCOL_VERSION UINT8_C(1)

/* vireo v1 版本的固定包头长度 */
#define VIREO_PROTOCOL_HEADER_SIZE UINT8_C(32)

/*
 * vireo v1 允许的最大包体长度 单位：字节 16 * 1024 * 1024 BYTE
 *
 * 所有命令共同遵守的硬上限
 * 具体的命令可以设置更小的 body 上限，但是不可以超过这个值
 */
#define VIREO_PROTOCOL_MAX_BODY_SIZE UINT32_C(16777216)

/*
 * sequence 0 是保留值，不用于正常请求关联
 *
 * 客户端发送正常请求时必须分配非零 sequence
 */
#define VIREO_PROTOCOL_SEQUENCE_NONE UINT32_C(0)

/*
 * 请求包的 status 字段必须是 0，它不会携带任何 status 值
 */
#define VIREO_PROTOCOL_REQUEST_STATUS UINT16_C(0)

/* 未绑定 session 时使用的 session_handle */
#define VIREO_PROTOCOL_NO_SESSION_HANDLE UINT32_C(0)

/* 当前帧不属于任务时使用的 task_handle */
#define VIREO_PROTOCOL_NO_TASK_HANDLE UINT32_C(0)

/*
 * vireo v1 固定包头中每个字段的 wire offset
 *
 * 这些偏移量 offset 描述的是线协议字节数组，不是描述 vireo_protocol_header_t 的宿主结构体成员
 * offset
 *
 * wire layout 与 C 结构体 ABI 完全分离。无论宿主结构体是否存在 padding，都必须由 codec 按照这些固定
 * offset 逐字段编码和解码(很重要)
 */
#define VIREO_PROTOCOL_MAGIC_OFFSET UINT8_C(0)
#define VIREO_PROTOCOL_VERSION_OFFSET UINT8_C(4)
#define VIREO_PROTOCOL_HEADER_LENGTH_OFFSET UINT8_C(5)
#define VIREO_PROTOCOL_COMMAND_OFFSET UINT8_C(6)
#define VIREO_PROTOCOL_FLAGS_OFFSET UINT8_C(8)
#define VIREO_PROTOCOL_STATUS_OFFSET UINT8_C(10)
#define VIREO_PROTOCOL_BODY_LENGTH_OFFSET UINT8_C(12)
#define VIREO_PROTOCOL_SEQUENCE_OFFSET UINT8_C(16)
#define VIREO_PROTOCOL_SESSION_HANDLE_OFFSET UINT8_C(20)
#define VIREO_PROTOCOL_TASK_HANDLE_OFFSET UINT8_C(24)
#define VIREO_PROTOCOL_CRC32C_OFFSET UINT8_C(28)

/*
 * vireo v1 固定包头中每个字段的 wire 长度
 *
 * 单位：字节 BYTE
 */
#define VIREO_PROTOCOL_MAGIC_SIZE UINT8_C(4)
#define VIREO_PROTOCOL_VERSION_SIZE UINT8_C(1)
#define VIREO_PROTOCOL_HEADER_LENGTH_SIZE UINT8_C(1)
#define VIREO_PROTOCOL_COMMAND_SIZE UINT8_C(2)
#define VIREO_PROTOCOL_FLAGS_SIZE UINT8_C(2)
#define VIREO_PROTOCOL_STATUS_SIZE UINT8_C(2)
#define VIREO_PROTOCOL_BODY_LENGTH_SIZE UINT8_C(4)
#define VIREO_PROTOCOL_SEQUENCE_SIZE UINT8_C(4)
#define VIREO_PROTOCOL_SESSION_HANDLE_SIZE UINT8_C(4)
#define VIREO_PROTOCOL_TASK_HANDLE_SIZE UINT8_C(4)
#define VIREO_PROTOCOL_CRC32C_SIZE UINT8_C(4)

/*
 * flag 在线协议中固定占 2个字节，也就是 16 bit
 * 不使用枚举的原因是，因为在 C 中，enum 的底层宽度由具体实现决定，不保证一定是16 bit
 *
 * 将 uint16_t 重定义为 vireo_protocol_flags_t 类型
 */
typedef uint16_t vireo_protocol_flags_t;

/*
 * bit 0：当前帧是响应
 *
 * 客户端请求不能设置该位
 * 服务端响应必须设置该位
 */
#define VIREO_PROTOCOL_FLAG_RESPONSE UINT16_C(0x0001)

/*
 * bit 1：当前命令属于长任务命令
 */
#define VIREO_PROTOCOL_FLAG_LONG_COMMAND UINT16_C(0x0002)

/*
 * bit 2：当前 body 使用 chunk frame 格式
 */
#define VIREO_PROTOCOL_FLAG_CHUNK UINT16_C(0x0004)

/*
 * bit 3：当前帧是该流的最后一帧或结束确认
 *
 * 注意：它只代表该传输结束，不代表业务一定成功完成
 */
#define VIREO_PROTOCOL_FLAG_END UINT16_C(0x0008)

/*
 * bit 4：发送方要求接收方返回帧级确认
 */
#define VIREO_PROTOCOL_FLAG_NEED_ACK UINT16_C(0x0010)

/*
 * bit 5：分页或者多响应序列中仍然存在后续内容
 */
#define VIREO_PROTOCOL_FLAG_MORE UINT16_C(0x0020)

/*
 * 表示 vireo v1 定义的全部 flag 位，也就是已经使用的 bit 位
 *
 * 总共 6 个 bit 位置，其余 6-15 位 是保留位，v1 中必须是 0
 */
#define VIREO_PROTOCOL_FLAG_KNOWN_MASK UINT16_C(0x003F)

/*
 * command 在线协议中固定占16 bit
 *
 * 使用固定宽度整数可以完整保存远端传入的未知 command
 * 再由 vireo_command_is_known() 显式判断是否认识
 *
 * 将 uint16_t 重定义为 vireo_command_t 类型
 */
typedef uint16_t vireo_command_t;

/* 基础诊断命令 */

#define VIREO_COMMAND_PING UINT16_C(0x0001)
#define VIREO_COMMAND_SERVER_INFO UINT16_C(0x0002)

/* 用户与 session 命令 */
#define VIREO_COMMAND_REGISTER UINT16_C(0x0100)
#define VIREO_COMMAND_LOGIN UINT16_C(0x0101)
#define VIREO_COMMAND_LOGOUT UINT16_C(0x0102)
#define VIREO_COMMAND_SESSION_RESUME UINT16_C(0x0103)

/* 上传命令 */
#define VIREO_COMMAND_UPLOAD_INIT UINT16_C(0x0201)
#define VIREO_COMMAND_UPLOAD_CHUNK UINT16_C(0x0202)
#define VIREO_COMMAND_UPLOAD_COMMIT UINT16_C(0x0203)
#define VIREO_COMMAND_UPLOAD_ABORT UINT16_C(0x0204)
#define VIREO_COMMAND_UPLOAD_STATUS UINT16_C(0x0205)

/* 下载命令 */
#define VIREO_COMMAND_DOWNLOAD_INIT UINT16_C(0x0301)
#define VIREO_COMMAND_DOWNLOAD_CHUNK UINT16_C(0x0302)
#define VIREO_COMMAND_DOWNLOAD_ACK UINT16_C(0x0303)
#define VIREO_COMMAND_DOWNLOAD_FINISH UINT16_C(0x0304)
#define VIREO_COMMAND_DOWNLOAD_ABORT UINT16_C(0x0305)
#define VIREO_COMMAND_DOWNLOAD_SOURCES UINT16_C(0x0306)

/* 虚拟目录树命令 */
#define VIREO_COMMAND_NODE_LIST UINT16_C(0x0401)
#define VIREO_COMMAND_NODE_STAT UINT16_C(0x0402)
#define VIREO_COMMAND_NODE_MKDIR UINT16_C(0x0403)
#define VIREO_COMMAND_NODE_REMOVE UINT16_C(0x0404)
#define VIREO_COMMAND_NODE_MOVE UINT16_C(0x0405)

/* 任务管理命令 */
#define VIREO_COMMAND_TASK_LIST UINT16_C(0x0501)
#define VIREO_COMMAND_TASK_STATUS UINT16_C(0x0502)
#define VIREO_COMMAND_TASK_CANCEL UINT16_C(0x0503)

/* storage node 控制命令 */
#define VIREO_COMMAND_STORAGE_REGISTER UINT16_C(0x0601)
#define VIREO_COMMAND_STORAGE_HEARTBEAT UINT16_C(0x0602)

/* storage 保留命令 0x0610 - 0x0614 */
#define VIREO_COMMAND_STORAGE_PUT_RESERVED_FIRST UINT16_C(0x0610)
#define VIREO_COMMAND_STORAGE_PUT_RESERVED_LAST UINT16_C(0x0614)

/* storage node 数据命令 */
#define VIREO_COMMAND_STORAGE_GET_CHUNK UINT16_C(0x0620)
#define VIREO_COMMAND_STORAGE_DELETE_CHUNK UINT16_C(0x0630)

/*
 * status 在线协议中固定占 16 bit
 *
 * 协议对端可见的稳定线协议状态
 *
 * 将 uint16_t 重定义为 vireo_status_t 类型
 */
typedef uint16_t vireo_status_t;

/* 通用成功状态 */
#define VIREO_STATUS_OK UINT16_C(0)
#define VIREO_STATUS_ACCEPTED UINT16_C(1)

/* 通用协议错误 */
#define VIREO_STATUS_BAD_REQUEST UINT16_C(1001)
#define VIREO_STATUS_UNSUPPORTED UINT16_C(1002)
#define VIREO_STATUS_VERSION_MISMATCH UINT16_C(1003)
#define VIREO_STATUS_CRC_MISMATCH UINT16_C(1004)
#define VIREO_STATUS_BODY_TOO_LARGE UINT16_C(1005)
#define VIREO_STATUS_INVALID_FLAGS UINT16_C(1006)
#define VIREO_STATUS_DUPLICATE_REQUEST UINT16_C(1007)
#define VIREO_STATUS_RATE_LIMITED UINT16_C(1008)

/* 认证与 session 状态 */
#define VIREO_STATUS_UNAUTHORIZED UINT16_C(1101)
#define VIREO_STATUS_FORBIDDEN UINT16_C(1102)
#define VIREO_STATUS_INVALID_TOKEN UINT16_C(1103)
#define VIREO_STATUS_AUTHENTICATION_FAILED UINT16_C(1104)
#define VIREO_STATUS_SESSION_EXPIRED UINT16_C(1105)
#define VIREO_STATUS_USER_EXISTS UINT16_C(1106)
#define VIREO_STATUS_USER_DISABLED UINT16_C(1107)
#define VIREO_STATUS_WEAK_CREDENTIAL UINT16_C(1108)

/* 虚拟目录树状态 */
#define VIREO_STATUS_NOT_FOUND UINT16_C(1201)
#define VIREO_STATUS_ALREADY_EXISTS UINT16_C(1202)
#define VIREO_STATUS_INVALID_PATH UINT16_C(1203)
#define VIREO_STATUS_NOT_DIRECTORY UINT16_C(1204)
#define VIREO_STATUS_DIRECTORY_NOT_EMPTY UINT16_C(1205)
#define VIREO_STATUS_CONFLICT UINT16_C(1206)

/* 上传、下载和任务状态 */
#define VIREO_STATUS_UPLOAD_REJECTED UINT16_C(1301)
#define VIREO_STATUS_TASK_NOT_FOUND UINT16_C(1302)
#define VIREO_STATUS_CHUNK_MISMATCH UINT16_C(1303)
#define VIREO_STATUS_HASH_MISMATCH UINT16_C(1304)
#define VIREO_STATUS_INVALID_TASK_STATE UINT16_C(1305)
#define VIREO_STATUS_TASK_EXPIRED UINT16_C(1306)
#define VIREO_STATUS_RANGE_INVALID UINT16_C(1307)
#define VIREO_STATUS_CHUNK_WINDOW_EXCEEDED UINT16_C(1308)
#define VIREO_STATUS_TASK_CANCELLED UINT16_C(1309)
#define VIREO_STATUS_SOURCE_UNAVAILABLE UINT16_C(1310)

/* 传输流程的正常非终态或者特殊成功状态 */
#define VIREO_STATUS_RESUME UINT16_C(1390)
#define VIREO_STATUS_FAST_UPLOAD UINT16_C(1391)
#define VIREO_STATUS_PARTIAL UINT16_C(1392)
#define VIREO_STATUS_CHUNK_ALREADY_RECEIVED UINT16_C(1393)

/* 服务端失败 */
#define VIREO_STATUS_BUSY UINT16_C(1901)
#define VIREO_STATUS_INTERNAL_ERROR UINT16_C(1902)
#define VIREO_STATUS_STORAGE_NO_SPACE UINT16_C(1903)
#define VIREO_STATUS_DB_ERROR UINT16_C(1904)
#define VIREO_STATUS_IO_ERROR UINT16_C(1905)
#define VIREO_STATUS_TIMEOUT UINT16_C(1906)
#define VIREO_STATUS_OVERLOADED UINT16_C(1907)
#define VIREO_STATUS_UNAVAILABLE UINT16_C(1908)

/*
 * 通过 framing 校验的宿主语义包头，其保存每一帧会发生变化的语义字段
 *
 * 在编码之前，会将该结构体作为普通 C
 * 对象创建、初始化和读取；该结构体中的多字节整数始终使用宿主字节序
 *
 * 编码时，codec 只读取本结构体，随后按照固定的 wire offset 将字段编码到独立的 32 字节 大端字节序的
 * wire buffer 中
 *
 * 解码时，codec 从 32 字节 wire buffer 中读取大端字节序字段，转换为宿主语义值后写入本结构体。
 *
 * magic、version、header_len 不保存在本结构体中，因为任何数据包的包头都必须满足
 * -- magic == VIREO_PROTOCOL_MAGIC_VALUE
 * -- version == VIREO_PROTOCOL_VERSION
 * -- header_len == VIREO_PROTOCOL_HEADER_SIZE
 */
typedef struct vireo_protocol_header {
    // 当前帧对应的命令编号，请求与响应必须是相同的command
    vireo_command_t command;

    // 当前帧的协议 flags
    vireo_protocol_flags_t flags;

    /*
     * 请求必须是 VIREO_PROTOCOL_REQUEST_STATUS
     * 响应保存客户端可见的 vireo_status_t
     */
    vireo_status_t status;

    // 当前帧 body 的字节数，不包含包头，不得超过 VIREO_PROTOCOL_MAX_BODY_SIZE
    uint32_t body_len;

    // 单个连接的请求关联号 客户端与服务端保持一致，且客户端正常请求必须非 0
    uint32_t sequence;

    /* 当前连接绑定的短 session_handle
     * 若未认证时，它的值为 VIREO_PROTOCOL_NO_SESSION_HANDLE
     * 它不是长期的 session token，不能作为安全凭据
     */
    uint32_t session_handle;

    /*
     * 当前进程内的任务 handle
     *
     * 非任务命令它的值为 VIREO_PROTOCOL_NO_TASK_HANDLE
     * 更不是跨服务重启持久化的任务 UUID
     */
    uint32_t task_handle;

    /*
     * 当前帧的 CRC-32C 校验值
     *
     * 非常重要，要明确计算 crc32 到底计算哪些字节
     *
     * CRC 输入依次为：
     *  32 字节 wire header 中位于 [0,VIREO_PROTOCOL_CRC32C_OFFSET) 的字节
     *  当前帧的全部 body 字节
     *
     * CRC 输入不包含 wire header 中的 crc32c 字段本身
     * 每一帧独立计算 CRC，不跨多个 frame 累计
     *
     * codec 将最终的 32 bit CRC 数值以大端字节序编码到 wire buffer 的 VIREO_PROTOCOL_CRC32C_OFFSET
     * 位置 本结构体中的 crc32c 始终保存宿主字节序的语义值
     */
    uint32_t crc32c;

} vireo_protocol_header_t;

/**
 * @brief 判断 flags 是否包含 vireo v1 未定义的位
 *
 * @param[in] flags 要检查的 16 bit flags位集合
 *
 * @retval true flags 至少包含一个 vireo v1 未定义的位
 * @retval false flags 只包含 VIREO_PROTOCOL_FLAG_KNOWN_MASK 中的位
 *
 * @note 所有权：flags 按值传入，不涉及对象所有权
 * @note 生命周期：无返回对象
 * @note 线程安全：thread-safe；函数不访问共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
bool vireo_protocol_flags_have_unknown_bits(vireo_protocol_flags_t flags);

/**
 * @brief 判断当前 command 是否是当前已经冻结名称的命令
 *
 * @param[in] command 要查询的 16 bit 命令编号；并且允许传入未知值
 *
 * @retval true command 是当前注册表中的已知命令
 * @retval false command 未知或者处于保留编号范围
 *
 * @note 所有权：command 按值传入，不涉及对象所有权
 * @note 生命周期：无返回对象
 * @note 线程安全：thread-safe；函数不访问共享可变状态
 * @note errno：本函数不读取、不保存且不修改errno
 */
bool vireo_command_is_known(vireo_command_t command);

/**
 * @brief 判断 command 是否位于当前保留的 STORAGE_PUT 编号范围
 *
 * @param[in] command 要查询的 16 bit 命令编号；允许传入任意值
 *
 * @retval true command 位于 0x0610-0x0614
 * @retval false command 不位于该保留范围
 *
 * @note 返回 true 不代表该命令已经实现，目前还在保留
 * @note 所有权：command 按值传入，不涉及对象所有权
 * @note 线程安全：thread-safe；函数不访问共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
bool vireo_command_is_reserved(vireo_command_t command);

/**
 * @brief 获取 command 的名称
 *
 * 已知命令返回固定的小写名称
 * STORAGE_PUT 保留范围返回 "reserved_storage_put"；其他未知值返回 "unknown"
 *
 * @param[in] command 要查询的 16 bit 命令编号；允许传入未知值
 *
 * @return 指向静态只读字符串的非空指针
 *
 * @note 所有权：返回只读字符串属于本模块内容，调用者不得修改或者释放
 * @note 生命周期：返回的只读字符串在整个进程生命周期内有效
 * @note 本函数用于日志、测试和诊断，不能代替数值协议判断
 * @note 线程安全：thread-safe；函数不访问共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
char const *vireo_command_name(vireo_command_t command);

/**
 * @brief 判断 status 是否属于当前的 vireo v1 注册表
 *
 * @param[in] status 要查询的 16 bit 线协议状态；允许传入未知值
 *
 * @retval true status 当前注册表中已知状态
 * @retval false status 是未知状态
 *
 * @note 所有权：status 按值传入，不涉及对象所有权
 * @note 生命周期：无返回对象
 * @note 线程安全：thread-safe；函数不访问共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
bool vireo_status_is_known(vireo_status_t status);

/**
 * @brief 获取 status 的名称
 *
 * 已知状态返回固定的小写名称，未知状态返回 "unknown"
 *
 * @param[in] status 要查询的 16 bit 线协议状态；允许传入未知值
 *
 * @return 指向静态只读字符串的非空指针
 *
 * @note 所有权：返回字符串属于本模块，调用者不得修改或者释放
 * @note 生命周期：返回字符串在整个进程生命周期内有效
 * @note 客户端业务逻辑必须依据数值状态
 * @note 线程安全：thread-safe；函数不访问共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
char const *vireo_status_name(vireo_status_t status);

#endif /* VIREO_PROTOCOL_PROTOCOL_H */
