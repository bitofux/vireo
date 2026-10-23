/* PROJECT : VIREO; FILE : directory_name.c; AUTHOR : bitofux;
 * DATE : 2026-10-24; BRIEF : 复用NAME规则，显式长度NFC只验证不改写。 */
#include "directory_name_internal.h"
#include <vireo/protocol/tlv.h>
#include <utf8proc.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(UTF8PROC_VERSION_MAJOR == 2 && UTF8PROC_VERSION_MINOR == 9 && UTF8PROC_VERSION_PATCH == 0,
    "utf8proc name policy baseline");

static vireo_result_t native_normalize(void *context, const unsigned char *name,
    size_t length, unsigned char **owner, size_t *normalized_length)
{
    (void)context;
    unsigned char *normalized = NULL;
    /* 调用者已核1..255，窄化安全；不启用NULLTERM/兼容折叠。 */
    utf8proc_ssize_t n = utf8proc_map(name, (utf8proc_ssize_t)length, &normalized,
        UTF8PROC_STABLE | UTF8PROC_COMPOSE);
    if (n < 0) {
        if (n == UTF8PROC_ERROR_NOMEM) { return VIREO_RESULT_NO_MEMORY; }
        if (n == UTF8PROC_ERROR_OVERFLOW) { return VIREO_RESULT_OVERFLOW; }
        return VIREO_RESULT_INTERNAL;
    }
    *owner = normalized;
    *normalized_length = (size_t)n;
    return VIREO_OK;
}

static void native_release(void *context, unsigned char *owner)
{
    (void)context;
    free(owner);
}

vireo_result_t vireo_directory_name_validate_with_runtime(const unsigned char *name,
    size_t name_length, vireo_directory_name_issue_t *issue,
    const vireo_directory_name_runtime_t *runtime)
{
    const int saved_errno = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (name == NULL || issue == NULL || runtime == NULL ||
        runtime->normalize == NULL || runtime->release == NULL) { goto done; }
    *issue = VIREO_DIRECTORY_NAME_ISSUE_NONE;
    if (name_length == 0 || name_length > VIREO_DIRECTORY_NAME_CAPACITY) {
        *issue = VIREO_DIRECTORY_NAME_ISSUE_LENGTH;
        rc = VIREO_RESULT_RANGE;
        goto done;
    }
    unsigned char encoded[259], seen[1];
    vireo_tlv_writer_t writer;
    const vireo_tlv_rule_t rule = {1, 1, 255, VIREO_TLV_VALUE_NAME, true, false};
    vireo_tlv_issue_t tlv_issue = VIREO_TLV_ISSUE_NONE;
    rc = VIREO_RESULT_INTERNAL;
    if (vireo_tlv_writer_init(&writer, encoded, sizeof(encoded)) != VIREO_OK ||
        vireo_tlv_writer_put(&writer, 1, name, name_length) != VIREO_OK) { goto done; }
    vireo_result_t validated = vireo_tlv_schema_validate(encoded, writer.used, &rule, 1,
        VIREO_TLV_UNKNOWN_REJECT, seen, sizeof(seen), &tlv_issue);
    if (validated != VIREO_OK) {
        if (validated == VIREO_RESULT_PROTOCOL && tlv_issue == VIREO_TLV_ISSUE_INVALID_UTF8) {
            *issue = VIREO_DIRECTORY_NAME_ISSUE_UTF8; rc = VIREO_RESULT_PROTOCOL;
        } else if (validated == VIREO_RESULT_PROTOCOL && tlv_issue == VIREO_TLV_ISSUE_INVALID_NAME) {
            *issue = VIREO_DIRECTORY_NAME_ISSUE_SYNTAX; rc = VIREO_RESULT_PROTOCOL;
        }
        goto done;
    }
    if (tlv_issue != VIREO_TLV_ISSUE_NONE) { goto done; }
    unsigned char *owner = NULL;
    size_t length = 0;
    rc = runtime->normalize(runtime->context, name, name_length, &owner, &length);
    if (rc != VIREO_OK) {
        /* normalize失败不转移owner；只有分配/表示失败是正常技术返回。 */
        if (rc != VIREO_RESULT_NO_MEMORY && rc != VIREO_RESULT_OVERFLOW) { rc = VIREO_RESULT_INTERNAL; }
        goto done;
    }
    if (owner == NULL) { rc = VIREO_RESULT_INTERNAL; goto done; }
    bool same = length == name_length && memcmp(owner, name, name_length) == 0;
    runtime->release(runtime->context, owner);
    if (!same) { *issue = VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC; rc = VIREO_RESULT_PROTOCOL; }
done:
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_directory_name_validate(const unsigned char *name, size_t name_length,
    vireo_directory_name_issue_t *issue)
{
    const vireo_directory_name_runtime_t runtime = {NULL, native_normalize, native_release};
    return vireo_directory_name_validate_with_runtime(name, name_length, issue, &runtime);
}
