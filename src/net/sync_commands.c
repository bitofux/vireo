/*
- PROJECT : VIREO
- FILE    : sync_commands.c
- AUTHOR  : bitofux
- DATE    : 2026-10-07
- BRIEF   : 此模块负责：
- -- 完整构造并发布诊断TLV缓存
- -- 有界验证请求并填响应，业务status与本地错误分开
 */
#include <errno.h>
#include <string.h>
#include <vireo/base/checked.h>
#include <vireo/net/sync_commands.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>

/** 本模块不以 errno 传递协议错误，所有出口恢复调用者现场。 */
static vireo_result_t finish(vireo_result_t result, int saved_errno) {
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_tcp_server_sync_context_init(uint8_t const *version, size_t version_size,
                                                  vireo_tcp_server_sync_context_t *out_context) {
    int const saved_errno = errno;
    if (version == NULL || out_context == NULL || version_size == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    if (version_size > VIREO_SYNC_MAX_VERSION_BYTES)
        return finish(VIREO_RESULT_RANGE, saved_errno);
    for (size_t k = 0; k < version_size; ++k)
        if (version[k] < UINT8_C(0x21) || version[k] > UINT8_C(0x7E))
            return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    size_t required = 0;
    vireo_result_t result = vireo_checked_size_add((size_t)18, version_size, &required);
    if (result != VIREO_OK)
        return finish(result, saved_errno);
    if (required > VIREO_SYNC_MAX_INFO_BODY_BYTES)
        return finish(VIREO_RESULT_INTERNAL, saved_errno);
    vireo_tcp_server_sync_context_t next = {0};
    vireo_tlv_writer_t writer;
    /* uint16命令先取高/低8位，各值可表示为uint8；不调用codec内部helper。 */
    uint8_t const commands[4] = {(uint8_t)(VIREO_COMMAND_PING >> 8),
                                 (uint8_t)(VIREO_COMMAND_PING & UINT16_C(0xFF)),
                                 (uint8_t)(VIREO_COMMAND_SERVER_INFO >> 8),
                                 (uint8_t)(VIREO_COMMAND_SERVER_INFO & UINT16_C(0xFF))};
    result = vireo_tlv_writer_init(&writer, next.server_info_body, sizeof(next.server_info_body));
    if (result == VIREO_OK)
        result = vireo_tlv_writer_put_u16(&writer, VIREO_SYNC_TLV_PROTOCOL_VERSION,
                                          (uint16_t)VIREO_PROTOCOL_VERSION);
    if (result == VIREO_OK)
        result =
            vireo_tlv_writer_put(&writer, VIREO_SYNC_TLV_SERVER_VERSION, version, version_size);
    if (result == VIREO_OK)
        result = vireo_tlv_writer_put(&writer, VIREO_SYNC_TLV_SUPPORTED_COMMANDS, commands,
                                      sizeof(commands));
    if (result != VIREO_OK)
        return finish(result, saved_errno);
    if (writer.used != required)
        return finish(VIREO_RESULT_INTERNAL, saved_errno);
    next.server_info_body_size = writer.used;
    *out_context = next;
    return finish(VIREO_OK, saved_errno);
}

vireo_result_t vireo_tcp_server_handle_sync_command(vireo_connection_frame_view_t const *request,
                                                    uint8_t *body, size_t body_capacity,
                                                    vireo_tcp_server_reply_t *reply,
                                                    void *context) {
    int const saved_errno = errno;
    if (request == NULL || reply == NULL || context == NULL || (body_capacity != 0 && body == NULL))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    vireo_tcp_server_sync_context_t const *cache = context;
    if (cache->server_info_body_size < (size_t)19 ||
        cache->server_info_body_size > VIREO_SYNC_MAX_INFO_BODY_BYTES)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    size_t wire_size = 0;
    vireo_result_t result =
        vireo_checked_size_add((size_t)VIREO_PROTOCOL_HEADER_SIZE, request->body_size, &wire_size);
    if (result != VIREO_OK)
        return finish(result, saved_errno);
    if (wire_size != request->wire_size || request->body_size != request->header.body_len ||
        (request->body_size != 0 && request->body == NULL))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    vireo_protocol_codec_issue_t issue;
    result = vireo_protocol_request_header_validate(&request->header, &issue);
    if (result != VIREO_OK)
        return finish(result, saved_errno);
    vireo_tcp_server_reply_t next = {0};
    bool const info = request->header.command == VIREO_COMMAND_SERVER_INFO;
    if (request->header.command != VIREO_COMMAND_PING && !info)
        next.status = VIREO_STATUS_UNSUPPORTED;
    else if (request->header.flags != 0)
        next.status = VIREO_STATUS_INVALID_FLAGS;
    else if (request->header.session_handle != 0 || request->header.task_handle != 0 ||
             request->body_size != 0)
        next.status = VIREO_STATUS_BAD_REQUEST;
    else if (info) {
        if (body_capacity < cache->server_info_body_size)
            return finish(VIREO_RESULT_RANGE, saved_errno);
        next.body_size = cache->server_info_body_size;
        /* 已验证容量且工作区与cache独立；字节复制完再发布描述。 */
        memcpy(body, cache->server_info_body, next.body_size);
    }
    *reply = next;
    return finish(VIREO_OK, saved_errno);
}
