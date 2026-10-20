/* PROJECT: VIREO — 固定拒绝帧；完整入队事实先保存，刷新失败不可重发。 */
#include "auth_request_rejection_internal.h"
#include <errno.h>

static vireo_result_t enqueue_public(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint8_t const *bytes, size_t size,
    vireo_tcp_server_client_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_write_enqueue(server, client, bytes, size, error);
}
static vireo_result_t refresh_public(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_tls_flow_info_t *info,
    vireo_tcp_server_tls_application_error_t *error) {
    (void)context;
    return vireo_tcp_server_client_tls_flow_refresh(server, client, info, error);
}
static vireo_auth_request_rejection_ops_t const default_ops = {enqueue_public, refresh_public};

/* 只对可信来源的值做边界核验，不把内部result数值序列化。 */
vireo_result_t vireo_auth_request_rejection_classify(vireo_auth_request_head_receipt_t const *head, vireo_status_t *status) {
    if (head->state == VIREO_AUTH_REQUEST_HEAD_EMPTY) return VIREO_RESULT_NOT_FOUND;
    if (head->state != VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME &&
        head->state != VIREO_AUTH_REQUEST_HEAD_CONSUMED) return VIREO_RESULT_INVALID_ARGUMENT;
    if (head->client.pool_id == 0 || head->client.generation == 0 || head->sequence == 0 ||
        head->frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE || head->frame_bytes > VIREO_AUTH_REQUEST_FRAME_MAX ||
        (head->command != VIREO_COMMAND_REGISTER && head->command != VIREO_COMMAND_LOGIN &&
         head->command != VIREO_COMMAND_LOGOUT && head->command != VIREO_COMMAND_SESSION_RESUME) ||
        head->submit_result < VIREO_OK || head->submit_result > VIREO_RESULT_INTERNAL)
        return VIREO_RESULT_INVALID_ARGUMENT;
    if (head->submit_result == VIREO_OK || head->submit_report.submit_report.task_transferred)
        return VIREO_RESULT_NOT_FOUND;
    *status = VIREO_STATUS_INTERNAL_ERROR;
    if (head->submit_report.stage == VIREO_AUTH_REQUEST_SUBMIT_DECODE &&
        head->submit_result == VIREO_RESULT_PROTOCOL) *status = VIREO_STATUS_BAD_REQUEST;
    else if (head->submit_report.stage == VIREO_AUTH_REQUEST_SUBMIT_SESSION) {
        *status=head->submit_result==VIREO_RESULT_TIMEOUT?VIREO_STATUS_SESSION_EXPIRED:
            head->submit_result==VIREO_RESULT_NOT_FOUND || head->submit_result==VIREO_RESULT_CANCELLED?
                VIREO_STATUS_AUTHENTICATION_FAILED:VIREO_STATUS_INTERNAL_ERROR;
    }
    else if (head->submit_report.stage == VIREO_AUTH_REQUEST_SUBMIT_ADMISSION &&
        head->submit_result == VIREO_RESULT_BUSY && head->submit_report.admission_decided) {
        if (head->submit_report.decision.outcome == VIREO_RATE_LIMIT_THROTTLED) *status = VIREO_STATUS_RATE_LIMITED;
        else if (head->submit_report.decision.outcome == VIREO_RATE_LIMIT_CAPACITY) *status = VIREO_STATUS_OVERLOADED;
    } else if (head->submit_report.stage == VIREO_AUTH_REQUEST_SUBMIT_QUEUE &&
        head->submit_result == VIREO_RESULT_BUSY) *status = VIREO_STATUS_OVERLOADED;
    else if (head->submit_result == VIREO_RESULT_CANCELLED) *status = VIREO_STATUS_UNAVAILABLE;
    return VIREO_OK;
}
static bool empty(vireo_auth_request_rejection_receipt_t const *receipt) {
    return receipt->state == VIREO_AUTH_REQUEST_REJECTION_EMPTY && receipt->client.pool_id == 0 &&
        receipt->client.slot_index == 0 && receipt->client.generation == 0 && receipt->command == 0 &&
        receipt->sequence == 0 && receipt->status == 0;
}
static bool matches(vireo_auth_request_head_receipt_t const *head,
    vireo_auth_request_rejection_receipt_t const *receipt, vireo_status_t status) {
    return receipt->state >= VIREO_AUTH_REQUEST_REJECTION_NEEDS_ENQUEUE &&
        receipt->state <= VIREO_AUTH_REQUEST_REJECTION_READY &&
        receipt->client.pool_id == head->client.pool_id && receipt->client.slot_index == head->client.slot_index &&
        receipt->client.generation == head->client.generation && receipt->command == head->command &&
        receipt->sequence == head->sequence && receipt->status == status;
}

/** 发布真实阶段前缀并恢复errno；不回滚已保存凭据或FIFO字节。 */
static vireo_result_t finish(vireo_result_t result, vireo_auth_request_rejection_stage_t stage,
    vireo_auth_request_rejection_report_t value, vireo_auth_request_rejection_report_t *report,
    vireo_auth_request_rejection_receipt_t const *receipt, int saved_errno) {
    value.stage = stage;
    if (receipt != NULL) value.receipt = *receipt;
    if (report != NULL) *report = value;
    errno = saved_errno;
    return result;
}

/** 短借原TLS观察；结束借用后才允许入队/刷新。不把停止当作跨线程屏障。 */
static vireo_result_t ready(vireo_tcp_server_t *server, vireo_connection_pool_lease_t client,
    bool before_enqueue, vireo_auth_request_rejection_report_t *value) {
    vireo_tcp_server_info_t root;
    vireo_result_t result = vireo_tcp_server_inspect(server, &root);
    if (result != VIREO_OK) return result;
    if (root.processing_active || root.driving_active || root.scheduling_active || root.serving_active ||
        root.shutdown_active || root.closing_active) return VIREO_RESULT_BUSY;
    if (before_enqueue && root.stop_requested) return VIREO_RESULT_CANCELLED;
    vireo_tls_connection_t *tls = NULL;
    result = vireo_tcp_server_client_tls_borrow(server, client, &tls, &value->lookup_error);
    if (result != VIREO_OK) return result;
    if (!before_enqueue) return VIREO_OK; /* 已入队后沿原flow API恢复，不重新判断发送政策。 */
    vireo_tls_connection_info_t connection;
    result = vireo_tls_connection_inspect(tls, &connection, &value->error.tls_error);
    if (result != VIREO_OK) return result;
    vireo_tls_io_info_t io;
    result = vireo_tls_connection_io_inspect(tls, &io, &value->error.tls_error);
    if (result != VIREO_OK) return result;
    vireo_tls_close_info_t close;
    result = vireo_tls_connection_close_inspect(tls, &close, &value->error.tls_error);
    if (result != VIREO_OK) return result;
    return connection.handshake_state == VIREO_TLS_HANDSHAKE_ESTABLISHED &&
        io.state == VIREO_TLS_IO_OPEN && close.state == VIREO_TLS_CLOSE_NONE ? VIREO_OK : VIREO_RESULT_BUSY;
}

vireo_result_t vireo_auth_request_rejection_with(vireo_tcp_server_t *server,
    vireo_auth_request_head_receipt_t const *head, vireo_auth_request_rejection_receipt_t *receipt,
    vireo_auth_request_rejection_report_t *report, vireo_auth_request_rejection_ops_t const *ops, void *context) {
    int const saved_errno = errno;
    vireo_auth_request_rejection_report_t value = {0};
#define RETURN(rc, st) return finish((rc), (st), value, report, receipt, saved_errno)
    if (server == NULL || head == NULL || receipt == NULL || report == NULL ||
        ops == NULL || ops->enqueue == NULL || ops->refresh == NULL)
        RETURN(VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_REQUEST_REJECTION_NONE);
    vireo_status_t status = 0;
    vireo_result_t result = vireo_auth_request_rejection_classify(head, &status);
    if (result != VIREO_OK) RETURN(result, VIREO_AUTH_REQUEST_REJECTION_CHECK_HEAD);
    if (head->state == VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME)
        RETURN(VIREO_RESULT_BUSY, VIREO_AUTH_REQUEST_REJECTION_CHECK_HEAD);
    if (!empty(receipt) && !matches(head, receipt, status))
        RETURN(VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_REQUEST_REJECTION_CHECK_RECEIPT);
    if (receipt->state == VIREO_AUTH_REQUEST_REJECTION_READY)
        RETURN(VIREO_RESULT_NOT_FOUND, VIREO_AUTH_REQUEST_REJECTION_CHECK_RECEIPT);
    if (empty(receipt)) *receipt = (vireo_auth_request_rejection_receipt_t){
        VIREO_AUTH_REQUEST_REJECTION_NEEDS_ENQUEUE, head->client, head->command, head->sequence, status};
    result = ready(server, receipt->client, receipt->state == VIREO_AUTH_REQUEST_REJECTION_NEEDS_ENQUEUE, &value);
    if (result != VIREO_OK) RETURN(result, VIREO_AUTH_REQUEST_REJECTION_CHECK_TRANSPORT);
    if (receipt->state == VIREO_AUTH_REQUEST_REJECTION_NEEDS_ENQUEUE) {
        uint8_t wire[VIREO_PROTOCOL_HEADER_SIZE];
        vireo_protocol_header_t header = {.command = receipt->command, .sequence = receipt->sequence,
            .flags = VIREO_PROTOCOL_FLAG_RESPONSE, .status = receipt->status};
        result = vireo_protocol_header_encode(&header, wire, sizeof wire);
        if (result != VIREO_OK) RETURN(result, VIREO_AUTH_REQUEST_REJECTION_ENCODE);
        result = vireo_protocol_frame_crc32c_calculate(wire, sizeof wire, NULL, 0, &header.crc32c);
        if (result != VIREO_OK) RETURN(result, VIREO_AUTH_REQUEST_REJECTION_ENCODE);
        result = vireo_protocol_header_encode(&header, wire, sizeof wire);
        if (result != VIREO_OK) RETURN(result, VIREO_AUTH_REQUEST_REJECTION_ENCODE);
        value.frame_encoded = true;
        value.enqueue_called = true;
        result = ops->enqueue(context, server, receipt->client, wire, sizeof wire, &value.enqueue_error);
        if (result != VIREO_OK) RETURN(result, VIREO_AUTH_REQUEST_REJECTION_ENQUEUE);
        /* enqueue只有完整成功才提交；先保存这个不可重放的事实，再刷新关注。 */
        receipt->state = VIREO_AUTH_REQUEST_REJECTION_NEEDS_REFRESH;
        value.enqueued = true;
    }
    value.refresh_called = true;
    result = ops->refresh(context, server, receipt->client, &value.flow, &value.error);
    if (result != VIREO_OK) RETURN(result, VIREO_AUTH_REQUEST_REJECTION_REFRESH);
    receipt->state = VIREO_AUTH_REQUEST_REJECTION_READY;
    RETURN(VIREO_OK, VIREO_AUTH_REQUEST_REJECTION_NONE);
#undef RETURN
}

vireo_result_t vireo_auth_request_rejection_step(vireo_tcp_server_t *server,
    vireo_auth_request_head_receipt_t const *head, vireo_auth_request_rejection_receipt_t *receipt,
    vireo_auth_request_rejection_report_t *report) {
    return vireo_auth_request_rejection_with(server, head, receipt, report, &default_ops, NULL);
}
vireo_result_t vireo_auth_request_rejection_acknowledge(vireo_auth_request_head_receipt_t *head,
    vireo_auth_request_rejection_receipt_t *receipt) {
    if (head == NULL || receipt == NULL) return VIREO_RESULT_INVALID_ARGUMENT;
    vireo_status_t status = 0;
    vireo_result_t result = vireo_auth_request_rejection_classify(head, &status);
    if (result != VIREO_OK) return result;
    if (head->state == VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME) return VIREO_RESULT_BUSY;
    if (empty(receipt)) return VIREO_RESULT_NOT_FOUND;
    if (!matches(head, receipt, status)) return VIREO_RESULT_INVALID_ARGUMENT;
    if (receipt->state != VIREO_AUTH_REQUEST_REJECTION_READY) return VIREO_RESULT_BUSY;
    result = vireo_auth_request_head_acknowledge(head);
    if (result == VIREO_OK) *receipt = (vireo_auth_request_rejection_receipt_t){0};
    return result;
}
