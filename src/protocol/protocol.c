/*
 * PROJECT : VIREO
 * FILE    : protocol.c
 * AUTHOR  : bitofux
 * DATE    : 2026-08-19
 * BRIEF   : 实现 vireo v1 协议注册表的纯查询函数
 * -- 判断 flags 是否包含未知位
 * -- 判断 command 是否已知或者处于保留范围
 * -- 返回 command 的名称
 * -- 判断 status 是否已知
 * -- 返回 status 的名称
 */

#include <vireo/protocol/protocol.h>

/* 判断 flags 是否包含未知位 */
bool vireo_protocol_flags_have_unknown_bits(vireo_protocol_flags_t flags) {
    // 获取未知位的集合
    vireo_protocol_flags_t const flags_unknown_mask =
        (vireo_protocol_flags_t)(~VIREO_PROTOCOL_FLAG_KNOWN_MASK);

    /*
     * flags_unknown_mask 的已知位为 0，未知位为 1
     * flags 中的每个 bit 都可能是 0 或者 1
     *
     * flags 与 flags_unknown_mask 执行按位与之后，所有的已知位都会被清除
     * 结果中只可能保留 flags 实际设置的未知位
     *
     * -- 结果为 0：flags 不包含未知位
     * -- 结果非 0：flags 至少包含一个未知位
     */

    return (flags & flags_unknown_mask) != UINT16_C(0);
}

/* 判断 command 是否是当前注册表中的已知命令 */
bool vireo_command_is_known(vireo_command_t command) {
    // 使用 switch 显式匹配当前注册表中的已命名命令
    switch (command) {
        case VIREO_COMMAND_PING:
        case VIREO_COMMAND_SERVER_INFO:

        case VIREO_COMMAND_REGISTER:
        case VIREO_COMMAND_LOGIN:
        case VIREO_COMMAND_LOGOUT:
        case VIREO_COMMAND_SESSION_RESUME:

        case VIREO_COMMAND_UPLOAD_INIT:
        case VIREO_COMMAND_UPLOAD_CHUNK:
        case VIREO_COMMAND_UPLOAD_COMMIT:
        case VIREO_COMMAND_UPLOAD_ABORT:
        case VIREO_COMMAND_UPLOAD_STATUS:

        case VIREO_COMMAND_DOWNLOAD_INIT:
        case VIREO_COMMAND_DOWNLOAD_CHUNK:
        case VIREO_COMMAND_DOWNLOAD_ACK:
        case VIREO_COMMAND_DOWNLOAD_FINISH:
        case VIREO_COMMAND_DOWNLOAD_ABORT:
        case VIREO_COMMAND_DOWNLOAD_SOURCES:

        case VIREO_COMMAND_NODE_LIST:
        case VIREO_COMMAND_NODE_STAT:
        case VIREO_COMMAND_NODE_MKDIR:
        case VIREO_COMMAND_NODE_REMOVE:
        case VIREO_COMMAND_NODE_MOVE:

        case VIREO_COMMAND_TASK_LIST:
        case VIREO_COMMAND_TASK_STATUS:
        case VIREO_COMMAND_TASK_CANCEL:

        case VIREO_COMMAND_STORAGE_REGISTER:
        case VIREO_COMMAND_STORAGE_HEARTBEAT:

        case VIREO_COMMAND_STORAGE_GET_CHUNK:
        case VIREO_COMMAND_STORAGE_DELETE_CHUNK:
            return true;

        default:
            return false;
    }
}

/* 判断 command 是否位于 STORAGE_PUT 保留编号范围 */
bool vireo_command_is_reserved(vireo_command_t command) {
    return command >= VIREO_COMMAND_STORAGE_PUT_RESERVED_FIRST &&
           command <= VIREO_COMMAND_STORAGE_PUT_RESERVED_LAST;
}

/* 返回 command 的字符串常量名称 */
char const *vireo_command_name(vireo_command_t command) {
    switch (command) {
        case VIREO_COMMAND_PING:
            return "ping";

        case VIREO_COMMAND_SERVER_INFO:
            return "server_info";

        case VIREO_COMMAND_REGISTER:
            return "register";

        case VIREO_COMMAND_LOGIN:
            return "login";

        case VIREO_COMMAND_LOGOUT:
            return "logout";

        case VIREO_COMMAND_SESSION_RESUME:
            return "session_resume";

        case VIREO_COMMAND_UPLOAD_INIT:
            return "upload_init";

        case VIREO_COMMAND_UPLOAD_CHUNK:
            return "upload_chunk";

        case VIREO_COMMAND_UPLOAD_COMMIT:
            return "upload_commit";

        case VIREO_COMMAND_UPLOAD_ABORT:
            return "upload_abort";

        case VIREO_COMMAND_UPLOAD_STATUS:
            return "upload_status";

        case VIREO_COMMAND_DOWNLOAD_INIT:
            return "download_init";

        case VIREO_COMMAND_DOWNLOAD_CHUNK:
            return "download_chunk";

        case VIREO_COMMAND_DOWNLOAD_ACK:
            return "download_ack";

        case VIREO_COMMAND_DOWNLOAD_FINISH:
            return "download_finish";

        case VIREO_COMMAND_DOWNLOAD_ABORT:
            return "download_abort";

        case VIREO_COMMAND_DOWNLOAD_SOURCES:
            return "download_sources";

        case VIREO_COMMAND_NODE_LIST:
            return "node_list";

        case VIREO_COMMAND_NODE_STAT:
            return "node_stat";

        case VIREO_COMMAND_NODE_MKDIR:
            return "node_mkdir";

        case VIREO_COMMAND_NODE_REMOVE:
            return "node_remove";

        case VIREO_COMMAND_NODE_MOVE:
            return "node_move";

        case VIREO_COMMAND_TASK_LIST:
            return "task_list";

        case VIREO_COMMAND_TASK_STATUS:
            return "task_status";

        case VIREO_COMMAND_TASK_CANCEL:
            return "task_cancel";

        case VIREO_COMMAND_STORAGE_REGISTER:
            return "storage_register";

        case VIREO_COMMAND_STORAGE_HEARTBEAT:
            return "storage_heartbeat";

        case VIREO_COMMAND_STORAGE_GET_CHUNK:
            return "storage_get_chunk";

        case VIREO_COMMAND_STORAGE_DELETE_CHUNK:
            return "storage_delete_chunk";

        default:
            break;
    }

    // 判断当前命令是否处于保留命令范围
    if (vireo_command_is_reserved(command)) {
        return "reserved_storage_put";
    }

    return "unknown";
}

/* 判断 status 是否属于当前 vireo v1 状态注册表 */
bool vireo_status_is_known(vireo_status_t status) {
    switch (status) {
        case VIREO_STATUS_OK:
        case VIREO_STATUS_ACCEPTED:

        case VIREO_STATUS_BAD_REQUEST:
        case VIREO_STATUS_UNSUPPORTED:
        case VIREO_STATUS_VERSION_MISMATCH:
        case VIREO_STATUS_CRC_MISMATCH:
        case VIREO_STATUS_BODY_TOO_LARGE:
        case VIREO_STATUS_INVALID_FLAGS:
        case VIREO_STATUS_DUPLICATE_REQUEST:
        case VIREO_STATUS_RATE_LIMITED:

        case VIREO_STATUS_UNAUTHORIZED:
        case VIREO_STATUS_FORBIDDEN:
        case VIREO_STATUS_INVALID_TOKEN:
        case VIREO_STATUS_AUTHENTICATION_FAILED:
        case VIREO_STATUS_SESSION_EXPIRED:
        case VIREO_STATUS_USER_EXISTS:
        case VIREO_STATUS_USER_DISABLED:
        case VIREO_STATUS_WEAK_CREDENTIAL:

        case VIREO_STATUS_NOT_FOUND:
        case VIREO_STATUS_ALREADY_EXISTS:
        case VIREO_STATUS_INVALID_PATH:
        case VIREO_STATUS_NOT_DIRECTORY:
        case VIREO_STATUS_DIRECTORY_NOT_EMPTY:
        case VIREO_STATUS_CONFLICT:

        case VIREO_STATUS_UPLOAD_REJECTED:
        case VIREO_STATUS_TASK_NOT_FOUND:
        case VIREO_STATUS_CHUNK_MISMATCH:
        case VIREO_STATUS_HASH_MISMATCH:
        case VIREO_STATUS_INVALID_TASK_STATE:
        case VIREO_STATUS_TASK_EXPIRED:
        case VIREO_STATUS_RANGE_INVALID:
        case VIREO_STATUS_CHUNK_WINDOW_EXCEEDED:
        case VIREO_STATUS_TASK_CANCELLED:
        case VIREO_STATUS_SOURCE_UNAVAILABLE:

        case VIREO_STATUS_RESUME:
        case VIREO_STATUS_FAST_UPLOAD:
        case VIREO_STATUS_PARTIAL:
        case VIREO_STATUS_CHUNK_ALREADY_RECEIVED:

        case VIREO_STATUS_BUSY:
        case VIREO_STATUS_INTERNAL_ERROR:
        case VIREO_STATUS_STORAGE_NO_SPACE:
        case VIREO_STATUS_DB_ERROR:
        case VIREO_STATUS_IO_ERROR:
        case VIREO_STATUS_TIMEOUT:
        case VIREO_STATUS_OVERLOADED:
        case VIREO_STATUS_UNAVAILABLE:
            return true;
        default:
            return false;
    }
}

/* 返回 status 的字符串常量名称 */
char const *vireo_status_name(vireo_status_t status) {
    switch (status) {
        case VIREO_STATUS_OK:
            return "ok";

        case VIREO_STATUS_ACCEPTED:
            return "accepted";

        case VIREO_STATUS_BAD_REQUEST:
            return "bad_request";

        case VIREO_STATUS_UNSUPPORTED:
            return "unsupported";

        case VIREO_STATUS_VERSION_MISMATCH:
            return "version_mismatch";

        case VIREO_STATUS_CRC_MISMATCH:
            return "crc_mismatch";

        case VIREO_STATUS_BODY_TOO_LARGE:
            return "body_too_large";

        case VIREO_STATUS_INVALID_FLAGS:
            return "invalid_flags";

        case VIREO_STATUS_DUPLICATE_REQUEST:
            return "duplicate_request";

        case VIREO_STATUS_RATE_LIMITED:
            return "rate_limited";

        case VIREO_STATUS_UNAUTHORIZED:
            return "unauthorized";

        case VIREO_STATUS_FORBIDDEN:
            return "forbidden";

        case VIREO_STATUS_INVALID_TOKEN:
            return "invalid_token";

        case VIREO_STATUS_AUTHENTICATION_FAILED:
            return "authentication_failed";

        case VIREO_STATUS_SESSION_EXPIRED:
            return "session_expired";

        case VIREO_STATUS_USER_EXISTS:
            return "user_exists";

        case VIREO_STATUS_USER_DISABLED:
            return "user_disabled";

        case VIREO_STATUS_WEAK_CREDENTIAL:
            return "weak_credential";

        case VIREO_STATUS_NOT_FOUND:
            return "not_found";

        case VIREO_STATUS_ALREADY_EXISTS:
            return "already_exists";

        case VIREO_STATUS_INVALID_PATH:
            return "invalid_path";

        case VIREO_STATUS_NOT_DIRECTORY:
            return "not_directory";

        case VIREO_STATUS_DIRECTORY_NOT_EMPTY:
            return "directory_not_empty";

        case VIREO_STATUS_CONFLICT:
            return "conflict";

        case VIREO_STATUS_UPLOAD_REJECTED:
            return "upload_rejected";

        case VIREO_STATUS_TASK_NOT_FOUND:
            return "task_not_found";

        case VIREO_STATUS_CHUNK_MISMATCH:
            return "chunk_mismatch";

        case VIREO_STATUS_HASH_MISMATCH:
            return "hash_mismatch";

        case VIREO_STATUS_INVALID_TASK_STATE:
            return "invalid_task_state";

        case VIREO_STATUS_TASK_EXPIRED:
            return "task_expired";

        case VIREO_STATUS_RANGE_INVALID:
            return "range_invalid";

        case VIREO_STATUS_CHUNK_WINDOW_EXCEEDED:
            return "chunk_window_exceeded";

        case VIREO_STATUS_TASK_CANCELLED:
            return "task_cancelled";

        case VIREO_STATUS_SOURCE_UNAVAILABLE:
            return "source_unavailable";

        case VIREO_STATUS_RESUME:
            return "resume";

        case VIREO_STATUS_FAST_UPLOAD:
            return "fast_upload";

        case VIREO_STATUS_PARTIAL:
            return "partial";

        case VIREO_STATUS_CHUNK_ALREADY_RECEIVED:
            return "chunk_already_received";

        case VIREO_STATUS_BUSY:
            return "busy";

        case VIREO_STATUS_INTERNAL_ERROR:
            return "internal_error";

        case VIREO_STATUS_STORAGE_NO_SPACE:
            return "storage_no_space";

        case VIREO_STATUS_DB_ERROR:
            return "db_error";

        case VIREO_STATUS_IO_ERROR:
            return "io_error";

        case VIREO_STATUS_TIMEOUT:
            return "timeout";

        case VIREO_STATUS_OVERLOADED:
            return "overloaded";

        case VIREO_STATUS_UNAVAILABLE:
            return "unavailable";

        default:
            return "unknown";
    }
}
