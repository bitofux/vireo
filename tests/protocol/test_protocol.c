/*
 * PROJECT : VIREO
 * FILE    : test_protocol.c
 * AUTHOR  : bitofux
 * DATE    : 2026-08-20
 * BRIEF   : 测试 vireo v1 协议注册表与固定公共合同
 * -- 固定 wire header 的常量、offset 和字段长度
 * -- 固定 flags、command 和 status 的稳定数值
 * -- 验证 flags 位判断
 * -- 验证全部已知 command、保留 command 和未知 command
 * -- 验证全部已知 status 和未知 status
 * -- 验证所有公共查询函数保持 errno
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vireo/protocol/protocol.h>

/* 静态断言 */
#define s_assert(CONSTANT, STRING) _Static_assert(CONSTANT, STRING)
/* 数组长度 */
#define VIREO_TEST_ARRAY_COUNT(array) (sizeof(array) / sizeof(array[0]))
/*
 * vireo v1 protocol 以 8 bit byte 为基础
 */
s_assert(CHAR_BIT == 8, "vireo requires 8-bit bytes");

/* 固定三个公共协议整数类型的宽度 */
s_assert(sizeof(vireo_protocol_flags_t) == sizeof(uint16_t),
         "vireo_protocol_flags_t must match uint16_t");

s_assert(sizeof(vireo_command_t) == sizeof(uint16_t), "vireo_command_t must match uint16_t");

s_assert(sizeof(vireo_status_t) == sizeof(uint16_t), "vireo_status_t must match uint16_t");

/* 固定 vireo v1 基础协议常量 */
s_assert(VIREO_PROTOCOL_MAGIC_VALUE == UINT32_C(0x56495245), "unexpected protocol magic");

s_assert(VIREO_PROTOCOL_VERSION == UINT8_C(1), "unexpected protocol version");

s_assert(VIREO_PROTOCOL_HEADER_SIZE == UINT8_C(32), "unexpected header size");

s_assert(VIREO_PROTOCOL_MAX_BODY_SIZE == UINT32_C(16777216), "unexpected maximum body size");

s_assert(VIREO_PROTOCOL_SEQUENCE_NONE == UINT32_C(0), "unexpected reserved sequence");

s_assert(VIREO_PROTOCOL_REQUEST_STATUS == UINT16_C(0), "unexpected request status");

s_assert(VIREO_PROTOCOL_NO_SESSION_HANDLE == UINT32_C(0), "unexpected empty session handle");

s_assert(VIREO_PROTOCOL_NO_TASK_HANDLE == UINT32_C(0), "unexpected empty task handle");

/* 固定 32 字节 wire header 中所有字段的起始 offset */
s_assert(VIREO_PROTOCOL_MAGIC_OFFSET == UINT8_C(0), "unexpected magic offset");

s_assert(VIREO_PROTOCOL_VERSION_OFFSET == UINT8_C(4), "unexpected version offset");

s_assert(VIREO_PROTOCOL_HEADER_LENGTH_OFFSET == UINT8_C(5), "unexpected header length offset");

s_assert(VIREO_PROTOCOL_COMMAND_OFFSET == UINT8_C(6), "unexpected command offset");

s_assert(VIREO_PROTOCOL_FLAGS_OFFSET == UINT8_C(8), "unexpected flags offset");

s_assert(VIREO_PROTOCOL_STATUS_OFFSET == UINT8_C(10), "unexpected status offset");

s_assert(VIREO_PROTOCOL_BODY_LENGTH_OFFSET == UINT8_C(12), "unexpected body length offset");

s_assert(VIREO_PROTOCOL_SEQUENCE_OFFSET == UINT8_C(16), "unexpected sequence offset");

s_assert(VIREO_PROTOCOL_SESSION_HANDLE_OFFSET == UINT8_C(20), "unexpected session handle offset");

s_assert(VIREO_PROTOCOL_TASK_HANDLE_OFFSET == UINT8_C(24), "unexpected task handle offset");

s_assert(VIREO_PROTOCOL_CRC32C_OFFSET == UINT8_C(28), "unexpected CRC32C offset");

/* 固定 wire header 中所有字段的长度 */
s_assert(VIREO_PROTOCOL_MAGIC_SIZE == UINT8_C(4), "unexpected magic size");

s_assert(VIREO_PROTOCOL_VERSION_SIZE == UINT8_C(1), "unexpected version size");

s_assert(VIREO_PROTOCOL_HEADER_LENGTH_SIZE == UINT8_C(1), "unexpected header length size");

s_assert(VIREO_PROTOCOL_COMMAND_SIZE == UINT8_C(2), "unexpected command size");

s_assert(VIREO_PROTOCOL_FLAGS_SIZE == UINT8_C(2), "unexpected flags size");

s_assert(VIREO_PROTOCOL_STATUS_SIZE == UINT8_C(2), "unexpected status size");

s_assert(VIREO_PROTOCOL_BODY_LENGTH_SIZE == UINT8_C(4), "unexpected body length size");

s_assert(VIREO_PROTOCOL_SEQUENCE_SIZE == UINT8_C(4), "unexpected sequence size");

s_assert(VIREO_PROTOCOL_SESSION_HANDLE_SIZE == UINT8_C(4), "unexpected session handle size");

s_assert(VIREO_PROTOCOL_TASK_HANDLE_SIZE == UINT8_C(4), "unexpected task handle size");

s_assert(VIREO_PROTOCOL_CRC32C_SIZE == UINT8_C(4), "unexpected CRC32C size");

/* 验证 wire layout 连续，没有重叠和空洞 */
s_assert(VIREO_PROTOCOL_MAGIC_OFFSET + VIREO_PROTOCOL_MAGIC_SIZE == VIREO_PROTOCOL_VERSION_OFFSET,
         "magic must end at version");

s_assert(VIREO_PROTOCOL_VERSION_OFFSET + VIREO_PROTOCOL_VERSION_SIZE ==
             VIREO_PROTOCOL_HEADER_LENGTH_OFFSET,
         "version must end at header length");

s_assert(VIREO_PROTOCOL_HEADER_LENGTH_OFFSET + VIREO_PROTOCOL_HEADER_LENGTH_SIZE ==
             VIREO_PROTOCOL_COMMAND_OFFSET,
         "header length must end at command");

s_assert(VIREO_PROTOCOL_COMMAND_OFFSET + VIREO_PROTOCOL_COMMAND_SIZE == VIREO_PROTOCOL_FLAGS_OFFSET,
         "command must end at flags");

s_assert(VIREO_PROTOCOL_FLAGS_OFFSET + VIREO_PROTOCOL_FLAGS_SIZE == VIREO_PROTOCOL_STATUS_OFFSET,
         "flags must end at status");

s_assert(VIREO_PROTOCOL_STATUS_OFFSET + VIREO_PROTOCOL_STATUS_SIZE ==
             VIREO_PROTOCOL_BODY_LENGTH_OFFSET,
         "status must end at body length");

s_assert(VIREO_PROTOCOL_BODY_LENGTH_OFFSET + VIREO_PROTOCOL_BODY_LENGTH_SIZE ==
             VIREO_PROTOCOL_SEQUENCE_OFFSET,
         "body length must end at sequence");

s_assert(VIREO_PROTOCOL_SEQUENCE_OFFSET + VIREO_PROTOCOL_SEQUENCE_SIZE ==
             VIREO_PROTOCOL_SESSION_HANDLE_OFFSET,
         "sequence must end at session handle");

s_assert(VIREO_PROTOCOL_SESSION_HANDLE_OFFSET + VIREO_PROTOCOL_SESSION_HANDLE_SIZE ==
             VIREO_PROTOCOL_TASK_HANDLE_OFFSET,
         "session handle must end at task handle");

s_assert(VIREO_PROTOCOL_TASK_HANDLE_OFFSET + VIREO_PROTOCOL_TASK_HANDLE_SIZE ==
             VIREO_PROTOCOL_CRC32C_OFFSET,
         "task handle must end at CRC32C");

s_assert(VIREO_PROTOCOL_CRC32C_OFFSET + VIREO_PROTOCOL_CRC32C_SIZE == VIREO_PROTOCOL_HEADER_SIZE,
         "CRC32C must end the fixed header boundary");

/* 固定全部 vireo v1 flags 数值 */
s_assert(VIREO_PROTOCOL_FLAG_RESPONSE == UINT16_C(0x0001), "unexpected RESPONSE flag");

s_assert(VIREO_PROTOCOL_FLAG_LONG_COMMAND == UINT16_C(0x0002), "unexpected LONG_COMMAND flag");

s_assert(VIREO_PROTOCOL_FLAG_CHUNK == UINT16_C(0x0004), "unexpected CHUNK flag");

s_assert(VIREO_PROTOCOL_FLAG_END == UINT16_C(0x0008), "unexpected END flag");

s_assert(VIREO_PROTOCOL_FLAG_NEED_ACK == UINT16_C(0x0010), "unexpected NEED_ACK flag");

s_assert(VIREO_PROTOCOL_FLAG_MORE == UINT16_C(0x0020), "unexpected MORE flag");

s_assert(VIREO_PROTOCOL_FLAG_KNOWN_MASK == UINT16_C(0x003F), "unexpected known flags mask");

s_assert(VIREO_PROTOCOL_FLAG_KNOWN_MASK ==
             (VIREO_PROTOCOL_FLAG_RESPONSE | VIREO_PROTOCOL_FLAG_LONG_COMMAND |
              VIREO_PROTOCOL_FLAG_CHUNK | VIREO_PROTOCOL_FLAG_END | VIREO_PROTOCOL_FLAG_NEED_ACK |
              VIREO_PROTOCOL_FLAG_MORE),
         "known flags mask must contain every v1 flag");

/* 固定全部已命名 command 的 wire 数值 */
s_assert(VIREO_COMMAND_PING == UINT16_C(0x0001), "unexpected PING");

s_assert(VIREO_COMMAND_SERVER_INFO == UINT16_C(0x0002), "unexpected SERVER_INFO");

s_assert(VIREO_COMMAND_REGISTER == UINT16_C(0x0100), "unexpected REGISTER");

s_assert(VIREO_COMMAND_LOGIN == UINT16_C(0x0101), "unexpected LOGIN");

s_assert(VIREO_COMMAND_LOGOUT == UINT16_C(0x0102), "unexpected LOGOUT");

s_assert(VIREO_COMMAND_SESSION_RESUME == UINT16_C(0x0103), "unexpected SESSION_RESUME");

s_assert(VIREO_COMMAND_UPLOAD_INIT == UINT16_C(0x0201), "unexpected UPLOAD_INIT");

s_assert(VIREO_COMMAND_UPLOAD_CHUNK == UINT16_C(0x0202), "unexpected UPLOAD_CHUNK");

s_assert(VIREO_COMMAND_UPLOAD_COMMIT == UINT16_C(0x0203), "unexpected UPLOAD_COMMIT");

s_assert(VIREO_COMMAND_UPLOAD_ABORT == UINT16_C(0x0204), "unexpected UPLOAD_ABORT");

s_assert(VIREO_COMMAND_UPLOAD_STATUS == UINT16_C(0x0205), "unexpected UPLOAD_STATUS");

s_assert(VIREO_COMMAND_DOWNLOAD_INIT == UINT16_C(0x0301), "unexpected DOWNLOAD_INIT");

s_assert(VIREO_COMMAND_DOWNLOAD_CHUNK == UINT16_C(0x0302), "unexpected DOWNLOAD_CHUNK");

s_assert(VIREO_COMMAND_DOWNLOAD_ACK == UINT16_C(0x0303), "unexpected DOWNLOAD_ACK");

s_assert(VIREO_COMMAND_DOWNLOAD_FINISH == UINT16_C(0x0304), "unexpected DOWNLOAD_FINISH");

s_assert(VIREO_COMMAND_DOWNLOAD_ABORT == UINT16_C(0x0305), "unexpected DOWNLOAD_ABORT");

s_assert(VIREO_COMMAND_DOWNLOAD_SOURCES == UINT16_C(0x0306), "unexpected DOWNLOAD_SOURCES");

s_assert(VIREO_COMMAND_NODE_LIST == UINT16_C(0x0401), "unexpected NODE_LIST");

s_assert(VIREO_COMMAND_NODE_STAT == UINT16_C(0x0402), "unexpected NODE_STAT");

s_assert(VIREO_COMMAND_NODE_MKDIR == UINT16_C(0x0403), "unexpected NODE_MKDIR");

s_assert(VIREO_COMMAND_NODE_REMOVE == UINT16_C(0x0404), "unexpected NODE_REMOVE");

s_assert(VIREO_COMMAND_NODE_MOVE == UINT16_C(0x0405), "unexpected NODE_MOVE");

s_assert(VIREO_COMMAND_TASK_LIST == UINT16_C(0x0501), "unexpected TASK_LIST");

s_assert(VIREO_COMMAND_TASK_STATUS == UINT16_C(0x0502), "unexpected TASK_STATUS");

s_assert(VIREO_COMMAND_TASK_CANCEL == UINT16_C(0x0503), "unexpected TASK_CANCEL");

s_assert(VIREO_COMMAND_STORAGE_REGISTER == UINT16_C(0x0601), "unexpected STORAGE_REGISTER");

s_assert(VIREO_COMMAND_STORAGE_HEARTBEAT == UINT16_C(0x0602), "unexpected STORAGE_HEARTBEAT");

s_assert(VIREO_COMMAND_STORAGE_PUT_RESERVED_FIRST == UINT16_C(0x0610),
         "unexpected STORAGE_PUT reserved first");

s_assert(VIREO_COMMAND_STORAGE_PUT_RESERVED_LAST == UINT16_C(0x0614),
         "unexpected STORAGE_PUT reserved last");

s_assert(VIREO_COMMAND_STORAGE_GET_CHUNK == UINT16_C(0x0620), "unexpected STORAGE_GET_CHUNK");

s_assert(VIREO_COMMAND_STORAGE_DELETE_CHUNK == UINT16_C(0x0630), "unexpected STORAGE_DELETE_CHUNK");

/* 固定全部 vireo v1 status wire 数值 */
s_assert(VIREO_STATUS_OK == UINT16_C(0), "unexpected OK");

s_assert(VIREO_STATUS_ACCEPTED == UINT16_C(1), "unexpected ACCEPTED");

s_assert(VIREO_STATUS_BAD_REQUEST == UINT16_C(1001), "unexpected BAD_REQUEST");

s_assert(VIREO_STATUS_UNSUPPORTED == UINT16_C(1002), "unexpected UNSUPPORTED");

s_assert(VIREO_STATUS_VERSION_MISMATCH == UINT16_C(1003), "unexpected VERSION_MISMATCH");

s_assert(VIREO_STATUS_CRC_MISMATCH == UINT16_C(1004), "unexpected CRC_MISMATCH");

s_assert(VIREO_STATUS_BODY_TOO_LARGE == UINT16_C(1005), "unexpected BODY_TOO_LARGE");

s_assert(VIREO_STATUS_INVALID_FLAGS == UINT16_C(1006), "unexpected INVALID_FLAGS");

s_assert(VIREO_STATUS_DUPLICATE_REQUEST == UINT16_C(1007), "unexpected DUPLICATE_REQUEST");

s_assert(VIREO_STATUS_RATE_LIMITED == UINT16_C(1008), "unexpected RATE_LIMITED");

s_assert(VIREO_STATUS_UNAUTHORIZED == UINT16_C(1101), "unexpected UNAUTHORIZED");

s_assert(VIREO_STATUS_FORBIDDEN == UINT16_C(1102), "unexpected FORBIDDEN");

s_assert(VIREO_STATUS_INVALID_TOKEN == UINT16_C(1103), "unexpected INVALID_TOKEN");

s_assert(VIREO_STATUS_AUTHENTICATION_FAILED == UINT16_C(1104), "unexpected AUTHENTICATION_FAILED");

s_assert(VIREO_STATUS_SESSION_EXPIRED == UINT16_C(1105), "unexpected SESSION_EXPIRED");

s_assert(VIREO_STATUS_USER_EXISTS == UINT16_C(1106), "unexpected USER_EXISTS");

s_assert(VIREO_STATUS_USER_DISABLED == UINT16_C(1107), "unexpected USER_DISABLED");

s_assert(VIREO_STATUS_WEAK_CREDENTIAL == UINT16_C(1108), "unexpected WEAK_CREDENTIAL");

s_assert(VIREO_STATUS_NOT_FOUND == UINT16_C(1201), "unexpected NOT_FOUND");

s_assert(VIREO_STATUS_ALREADY_EXISTS == UINT16_C(1202), "unexpected ALREADY_EXISTS");

s_assert(VIREO_STATUS_INVALID_PATH == UINT16_C(1203), "unexpected INVALID_PATH");

s_assert(VIREO_STATUS_NOT_DIRECTORY == UINT16_C(1204), "unexpected NOT_DIRECTORY");

s_assert(VIREO_STATUS_DIRECTORY_NOT_EMPTY == UINT16_C(1205), "unexpected DIRECTORY_NOT_EMPTY");

s_assert(VIREO_STATUS_CONFLICT == UINT16_C(1206), "unexpected CONFLICT");

s_assert(VIREO_STATUS_UPLOAD_REJECTED == UINT16_C(1301), "unexpected UPLOAD_REJECTED");

s_assert(VIREO_STATUS_TASK_NOT_FOUND == UINT16_C(1302), "unexpected TASK_NOT_FOUND");

s_assert(VIREO_STATUS_CHUNK_MISMATCH == UINT16_C(1303), "unexpected CHUNK_MISMATCH");

s_assert(VIREO_STATUS_HASH_MISMATCH == UINT16_C(1304), "unexpected HASH_MISMATCH");

s_assert(VIREO_STATUS_INVALID_TASK_STATE == UINT16_C(1305), "unexpected INVALID_TASK_STATE");

s_assert(VIREO_STATUS_TASK_EXPIRED == UINT16_C(1306), "unexpected TASK_EXPIRED");

s_assert(VIREO_STATUS_RANGE_INVALID == UINT16_C(1307), "unexpected RANGE INVALID");

s_assert(VIREO_STATUS_CHUNK_WINDOW_EXCEEDED == UINT16_C(1308), "unexpected CHUNK_WINDOW_EXCEEDED");

s_assert(VIREO_STATUS_TASK_CANCELLED == UINT16_C(1309), "unexpected TASK_CANCELLED");

s_assert(VIREO_STATUS_SOURCE_UNAVAILABLE == UINT16_C(1310), "unexpected SOURCE_UNAVAILABLE");

s_assert(VIREO_STATUS_RESUME == UINT16_C(1390), "unexpected RESUME");

s_assert(VIREO_STATUS_FAST_UPLOAD == UINT16_C(1391), "unexpected FAST_UPLOAD");

s_assert(VIREO_STATUS_PARTIAL == UINT16_C(1392), "unexpected PARTIAL");

s_assert(VIREO_STATUS_CHUNK_ALREADY_RECEIVED == UINT16_C(1393),
         "unexpected CHUNK_ALREADY_RECEIVED");

s_assert(VIREO_STATUS_BUSY == UINT16_C(1901), "unexpected BUSY");

s_assert(VIREO_STATUS_INTERNAL_ERROR == UINT16_C(1902), "unexpected INTERNAL_ERROR");

s_assert(VIREO_STATUS_STORAGE_NO_SPACE == UINT16_C(1903), "unexpected STORAGE_NO_SPACE");

s_assert(VIREO_STATUS_DB_ERROR == UINT16_C(1904), "unexpected DB_ERROR");

s_assert(VIREO_STATUS_IO_ERROR == UINT16_C(1905), "unexpected IO_ERROR");

s_assert(VIREO_STATUS_TIMEOUT == UINT16_C(1906), "unexpected TIMEOUT");

s_assert(VIREO_STATUS_OVERLOADED == UINT16_C(1907), "unexpected OVERLOADED");

s_assert(VIREO_STATUS_UNAVAILABLE == UINT16_C(1908), "unexpected UNAVAILABLE");

/*
 * 封装 command、status、flag
 */
struct command_case {
    vireo_command_t command;
    char const *command_name;
};

struct status_case {
    vireo_status_t status;
    char const *status_name;
};

struct flag_case {
    vireo_protocol_flags_t flags;
    char const *flags_name;
    bool expected_unknown;
};

/* 已知 command 的命令编号和字符串名称 */
static struct command_case const known_command_cases[] = {
    {VIREO_COMMAND_PING, "ping"},
    {VIREO_COMMAND_SERVER_INFO, "server_info"},

    {VIREO_COMMAND_REGISTER, "register"},
    {VIREO_COMMAND_LOGIN, "login"},
    {VIREO_COMMAND_LOGOUT, "logout"},
    {VIREO_COMMAND_SESSION_RESUME, "session_resume"},

    {VIREO_COMMAND_UPLOAD_INIT, "upload_init"},
    {VIREO_COMMAND_UPLOAD_CHUNK, "upload_chunk"},
    {VIREO_COMMAND_UPLOAD_COMMIT, "upload_commit"},
    {VIREO_COMMAND_UPLOAD_ABORT, "upload_abort"},
    {VIREO_COMMAND_UPLOAD_STATUS, "upload_status"},

    {VIREO_COMMAND_DOWNLOAD_INIT, "download_init"},
    {VIREO_COMMAND_DOWNLOAD_CHUNK, "download_chunk"},
    {VIREO_COMMAND_DOWNLOAD_ACK, "download_ack"},
    {VIREO_COMMAND_DOWNLOAD_FINISH, "download_finish"},
    {VIREO_COMMAND_DOWNLOAD_ABORT, "download_abort"},
    {VIREO_COMMAND_DOWNLOAD_SOURCES, "download_sources"},

    {VIREO_COMMAND_NODE_LIST, "node_list"},
    {VIREO_COMMAND_NODE_STAT, "node_stat"},
    {VIREO_COMMAND_NODE_MKDIR, "node_mkdir"},
    {VIREO_COMMAND_NODE_REMOVE, "node_remove"},
    {VIREO_COMMAND_NODE_MOVE, "node_move"},
    {VIREO_COMMAND_TASK_LIST, "task_list"},
    {VIREO_COMMAND_TASK_STATUS, "task_status"},
    {VIREO_COMMAND_TASK_CANCEL, "task_cancel"},

    {VIREO_COMMAND_STORAGE_REGISTER, "storage_register"},
    {VIREO_COMMAND_STORAGE_HEARTBEAT, "storage_heartbeat"},

    {VIREO_COMMAND_STORAGE_GET_CHUNK, "storage_get_chunk"},
    {VIREO_COMMAND_STORAGE_DELETE_CHUNK, "storage_delete_chunk"}};

/* vireo v1 保留的命令编号 */
static vireo_command_t const reserved_command_cases[] = {
    UINT16_C(0x0610), UINT16_C(0x0611), UINT16_C(0x0612), UINT16_C(0x0613), UINT16_C(0x0614)};

/* 用于测试的未知的命令编号 */
static vireo_command_t const unknown_command_cases[] = {
    UINT16_C(0x0000), UINT16_C(0x0003), UINT16_C(0x00FF), UINT16_C(0x0603),
    UINT16_C(0x060F), UINT16_C(0x0615), UINT16_C(0xFFFF),
};

/* 已知 status 的状态编号和字符串名称 */
static struct status_case const known_status_cases[] = {
    {VIREO_STATUS_OK, "ok"},
    {VIREO_STATUS_ACCEPTED, "accepted"},

    {VIREO_STATUS_BAD_REQUEST, "bad_request"},
    {VIREO_STATUS_UNSUPPORTED, "unsupported"},
    {VIREO_STATUS_VERSION_MISMATCH, "version_mismatch"},
    {VIREO_STATUS_CRC_MISMATCH, "crc_mismatch"},
    {VIREO_STATUS_BODY_TOO_LARGE, "body_too_large"},
    {VIREO_STATUS_INVALID_FLAGS, "invalid_flags"},
    {VIREO_STATUS_DUPLICATE_REQUEST, "duplicate_request"},
    {VIREO_STATUS_RATE_LIMITED, "rate_limited"},

    {VIREO_STATUS_UNAUTHORIZED, "unauthorized"},
    {VIREO_STATUS_FORBIDDEN, "forbidden"},
    {VIREO_STATUS_INVALID_TOKEN, "invalid_token"},
    {VIREO_STATUS_AUTHENTICATION_FAILED, "authentication_failed"},
    {VIREO_STATUS_SESSION_EXPIRED, "session_expired"},
    {VIREO_STATUS_USER_EXISTS, "user_exists"},
    {VIREO_STATUS_USER_DISABLED, "user_disabled"},
    {VIREO_STATUS_WEAK_CREDENTIAL, "weak_credential"},

    {VIREO_STATUS_NOT_FOUND, "not_found"},
    {VIREO_STATUS_ALREADY_EXISTS, "already_exists"},
    {VIREO_STATUS_INVALID_PATH, "invalid_path"},
    {VIREO_STATUS_NOT_DIRECTORY, "not_directory"},
    {VIREO_STATUS_DIRECTORY_NOT_EMPTY, "directory_not_empty"},
    {VIREO_STATUS_CONFLICT, "conflict"},

    {VIREO_STATUS_UPLOAD_REJECTED, "upload_rejected"},
    {VIREO_STATUS_TASK_NOT_FOUND, "task_not_found"},
    {VIREO_STATUS_CHUNK_MISMATCH, "chunk_mismatch"},
    {VIREO_STATUS_HASH_MISMATCH, "hash_mismatch"},
    {VIREO_STATUS_INVALID_TASK_STATE, "invalid_task_state"},
    {VIREO_STATUS_TASK_EXPIRED, "task_expired"},
    {VIREO_STATUS_RANGE_INVALID, "range_invalid"},
    {VIREO_STATUS_CHUNK_WINDOW_EXCEEDED, "chunk_window_exceeded"},
    {VIREO_STATUS_TASK_CANCELLED, "task_cancelled"},
    {VIREO_STATUS_SOURCE_UNAVAILABLE, "source_unavailable"},

    {VIREO_STATUS_RESUME, "resume"},
    {VIREO_STATUS_FAST_UPLOAD, "fast_upload"},
    {VIREO_STATUS_PARTIAL, "partial"},
    {VIREO_STATUS_CHUNK_ALREADY_RECEIVED, "chunk_already_received"},

    {VIREO_STATUS_BUSY, "busy"},
    {VIREO_STATUS_INTERNAL_ERROR, "internal_error"},
    {VIREO_STATUS_STORAGE_NO_SPACE, "storage_no_space"},
    {VIREO_STATUS_DB_ERROR, "db_error"},
    {VIREO_STATUS_IO_ERROR, "io_error"},
    {VIREO_STATUS_TIMEOUT, "timeout"},
    {VIREO_STATUS_OVERLOADED, "overloaded"},
    {VIREO_STATUS_UNAVAILABLE, "unavailable"},
};

/* 用于测试的未知的 status 编号 */
static vireo_status_t const unknown_status_cases[] = {
    UINT16_C(2),    UINT16_C(1000), UINT16_C(1009), UINT16_C(1109),   UINT16_C(1207),
    UINT16_C(1311), UINT16_C(1394), UINT16_C(1909), UINT16_C(0xFFFF),
};

/* 比较实际 bool 结果与预期值 */
static int expect_bool(char const *case_name, bool actual, bool expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected %s, got %s\n", case_name, expected ? "true" : "false",
            actual ? "true" : "false");

    return 1;
}

/* 比较实际字符串与预期字符串 */
static int expect_string(char const *case_name, char const *actual, char const *expected) {
    if (actual == NULL) {
        fprintf(stderr, "%s: expected \"%s\", got NULL\n", case_name, expected);
        return 1;
    }
    if (strcmp(actual, expected) == 0) {
        return 0;
    }

    fprintf(stderr, "%s: expected \"%s\", got \"%s\"\n", case_name, expected, actual);

    return 1;
}

/* 比较 error 的实际值和预期值 */
static int expect_errno_value(char const *case_name, int actual, int expected) {
    if (actual == expected) {
        return 0;
    }

    fprintf(stderr, "%s: expected errno %d, got %d\n", case_name, expected, actual);

    return 1;
}

/* 验证全部已知和未知 flags 位组合 */
static int check_protocol_flags(void) {
    static struct flag_case const flag_cases[] = {
        {UINT16_C(0x0000), "flags zero", false},
        {VIREO_PROTOCOL_FLAG_RESPONSE, "flags RESPONSE", false},
        {VIREO_PROTOCOL_FLAG_LONG_COMMAND, "flags LONG_COMMAND", false},
        {VIREO_PROTOCOL_FLAG_CHUNK, "flag CHUNK", false},
        {VIREO_PROTOCOL_FLAG_END, "flags END", false},
        {VIREO_PROTOCOL_FLAG_NEED_ACK, "flags NEED_ACK", false},
        {VIREO_PROTOCOL_FLAG_MORE, "flags MORE", false},
        {VIREO_PROTOCOL_FLAG_KNOWN_MASK, "flags known mask", false},
        {UINT16_C(0x0040), "flags bit 6", true},
        {UINT16_C(0x8000), "flags bit 15", true},
        {VIREO_PROTOCOL_FLAG_RESPONSE | UINT16_C(0x0040), "flags known and unknown", true},
        {UINT16_C(0xFFFF), "flags all bits", true}

    };

    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(flag_cases); ++index) {
        bool actual = vireo_protocol_flags_have_unknown_bits(flag_cases[index].flags);

        failures +=
            expect_bool(flag_cases[index].flags_name, actual, flag_cases[index].expected_unknown);
    }

    return failures;
}

/* 验证全部已命名 command */
static int check_known_commands(void) {
    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(known_command_cases); ++index) {
        // 获取 known_command_cases 数组中 command_case 类型的元素的地址
        struct command_case const *test_case = &known_command_cases[index];

        // 判断当前 command_case 类型的元素中 command 是否已知
        if (!vireo_command_is_known(test_case->command)) {
            fprintf(stderr, "known command %s (%u): is_known returned false\n",
                    test_case->command_name, (unsigned int)test_case->command);

            ++failures;
        }

        // 判断当前 command_case 类型的元素中的 command 是否保留
        if (vireo_command_is_reserved(test_case->command)) {
            fprintf(stderr, "known command %s (%u): is_reserved returned true\n",
                    test_case->command_name, (unsigned int)test_case->command);

            ++failures;
        }

        failures += expect_string(test_case->command_name, vireo_command_name(test_case->command),
                                  test_case->command_name);
    }

    return failures;
}

/* 验证 STORAGE_PUT 保留 command 区间 */
static int check_reserved_commands(void) {
    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(reserved_command_cases); ++index) {
        vireo_command_t command = reserved_command_cases[index];

        if (vireo_command_is_known(command)) {
            fprintf(stderr, "reserved command %u: is_known returned true\n", (unsigned int)command);
            ++failures;
        }

        if (!vireo_command_is_reserved(command)) {
            fprintf(stderr, "reserved command %u: is_reserved returned false\n",
                    (unsigned int)command);
            ++failures;
        }

        failures += expect_string("reserved command name", vireo_command_name(command),
                                  "reserved_storage_put");
    }

    return failures;
}

/* 验证保留范围外的未知 command */
static int check_unknown_commands(void) {
    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(unknown_command_cases); ++index) {
        vireo_command_t command = unknown_command_cases[index];

        if (vireo_command_is_known(command)) {
            fprintf(stderr, "unknown command %u: is_known returned true\n", (unsigned int)command);
            ++failures;
        }

        if (vireo_command_is_reserved(command)) {
            fprintf(stderr, "unknown command %u: is_reserved returned true\n",
                    (unsigned int)command);
            ++failures;
        }

        failures += expect_string("unknown command name", vireo_command_name(command), "unknown");
    }

    return failures;
}

/* 验证全部已知 status */
static int check_known_statuses(void) {
    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(known_status_cases); ++index) {
        struct status_case const *test_case = &known_status_cases[index];

        if (!vireo_status_is_known(test_case->status)) {
            fprintf(stderr, "known status %s (%u): is_known returned false\n",
                    test_case->status_name, (unsigned int)test_case->status);

            ++failures;
        }

        failures += expect_string(test_case->status_name, vireo_status_name(test_case->status),
                                  test_case->status_name);
    }

    return failures;
}

/* 验证注册表间隙和范围外的未知 status */
static int check_unknown_statuses(void) {
    int failures = 0;

    for (size_t index = 0; index < VIREO_TEST_ARRAY_COUNT(unknown_status_cases); ++index) {
        vireo_status_t status = unknown_status_cases[index];

        if (vireo_status_is_known(status)) {
            fprintf(stderr, "unknown status %u: is_known returned true\n", (unsigned int)status);

            ++failures;
        }

        failures += expect_string("unknown status name", vireo_status_name(status), "unknown");
    }

    return failures;
}

/* 验证所有公共查询函数不会修改 errno */
static int check_errno_preservation(void) {
    int failures = 0;

    errno = EACCES;
    (void)vireo_protocol_flags_have_unknown_bits(VIREO_PROTOCOL_FLAG_RESPONSE);
    failures += expect_errno_value("flags known errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_protocol_flags_have_unknown_bits(UINT16_C(0x8000));
    failures += expect_errno_value("flags unknown errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_command_is_known(VIREO_COMMAND_PING);
    failures += expect_errno_value("command known errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_command_is_known(UINT16_C(0xFFFF));
    failures += expect_errno_value("command unknown errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_command_is_reserved(VIREO_COMMAND_STORAGE_PUT_RESERVED_FIRST);
    failures += expect_errno_value("reserved command errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_command_is_reserved(UINT16_C(0x060F));
    failures += expect_errno_value("non-reserved command errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_command_name(VIREO_COMMAND_PING);
    failures += expect_errno_value("known command name errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_command_name(VIREO_COMMAND_STORAGE_PUT_RESERVED_FIRST);
    failures += expect_errno_value("reserved command name errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_command_name(UINT16_C(0xFFFF));
    failures += expect_errno_value("unknown command name errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_status_is_known(VIREO_STATUS_OK);
    failures += expect_errno_value("known status errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_status_is_known(UINT16_C(0xFFFF));
    failures += expect_errno_value("unknown status errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_status_name(VIREO_STATUS_OK);
    failures += expect_errno_value("known status name errno", errno, EACCES);

    errno = EACCES;
    (void)vireo_status_name(UINT16_C(0xFFFF));
    failures += expect_errno_value("unknown status name errno", errno, EACCES);

    return failures;
}
int main(void) {
    int failures = 0;

    failures += check_protocol_flags();
    failures += check_known_commands();
    failures += check_reserved_commands();
    failures += check_unknown_commands();
    failures += check_known_statuses();
    failures += check_unknown_statuses();
    failures += check_errno_preservation();

    if (failures != 0) {
        fprintf(stderr, "test_protocol: %d check(s) failed\n", failures);
        return EXIT_FAILURE;
    }

    puts("test_protocol: all check(s) passed");
    return EXIT_SUCCESS;
}
