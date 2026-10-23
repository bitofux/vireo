/* PROJECT : VIREO; FILE : fuzz_directory_name.c; AUTHOR : bitofux;
 * DATE : 2026-10-24; BRIEF : 有界名字输入，与TLV及独立固定Unicode样例交叉核验。 */
#include "directory_name_test_vectors.h"
#include <vireo/protocol/tlv.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const unsigned char fallback = 0;
    const unsigned char *name = size == 0 ? &fallback : data;
    vireo_directory_name_issue_t issue; errno=EDOM;
    vireo_result_t rc=vireo_directory_name_validate(name, size, &issue); assert(errno == EDOM);
    if (size == 0 || size > 255) {
        assert(rc == VIREO_RESULT_RANGE && issue == VIREO_DIRECTORY_NAME_ISSUE_LENGTH); return 0;
    }
    unsigned char encoded[259], seen[1]; vireo_tlv_writer_t writer;
    const vireo_tlv_rule_t rule={1, 1, 255, VIREO_TLV_VALUE_NAME, true, false};
    vireo_tlv_issue_t syntax;
    assert(vireo_tlv_writer_init(&writer, encoded, sizeof(encoded)) == VIREO_OK);
    assert(vireo_tlv_writer_put(&writer, 1, data, size) == VIREO_OK);
    vireo_result_t tlv=vireo_tlv_schema_validate(encoded, writer.used, &rule, 1,
        VIREO_TLV_UNKNOWN_REJECT, seen, 1, &syntax);
    if (tlv != VIREO_OK) {
        assert(rc == VIREO_RESULT_PROTOCOL);
        assert(issue == (syntax == VIREO_TLV_ISSUE_INVALID_UTF8 ? VIREO_DIRECTORY_NAME_ISSUE_UTF8 : VIREO_DIRECTORY_NAME_ISSUE_SYNTAX));
    } else {
        assert((rc == VIREO_OK && issue == VIREO_DIRECTORY_NAME_ISSUE_NONE) ||
            (rc == VIREO_RESULT_PROTOCOL && issue == VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC) ||
            ((rc == VIREO_RESULT_NO_MEMORY || rc == VIREO_RESULT_OVERFLOW) && issue == VIREO_DIRECTORY_NAME_ISSUE_NONE));
    }
    for (size_t i=0; i<sizeof(name_vectors)/sizeof(name_vectors[0]); ++i) {
        const struct name_vector *v=&name_vectors[i];
        if (size == v->length && memcmp(data, v->bytes, size) == 0) { assert(issue == v->issue); }
    }
    return 0;
}
