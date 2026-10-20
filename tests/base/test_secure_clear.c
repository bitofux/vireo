/*
 * PROJECT : VIREO
 * FILE    : test_secure_clear.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 精确区间、空值、二进制与重复擦除的公开合同验证
 */
#include <vireo/base/secure_clear.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "line %d: %s\n", __LINE__, #c); exit(1); } } while (0)

int main(void) {
    unsigned char bytes[259];
    errno = EDOM;
    CHECK(vireo_secure_clear(NULL, 1) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
    CHECK(vireo_secure_clear(NULL, SIZE_MAX) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
    CHECK(vireo_secure_clear(NULL, 0) == VIREO_OK && errno == EDOM);
    for (size_t offset = 0; offset <= sizeof(bytes); ++offset) {
        size_t const length = sizeof(bytes) - offset;
        memset(bytes, 0xa5, sizeof(bytes));
        CHECK(vireo_secure_clear(bytes + offset, length) == VIREO_OK && errno == EDOM);
        CHECK(vireo_secure_clear(bytes + offset, length) == VIREO_OK && errno == EDOM);
        for (size_t i = 0; i < sizeof(bytes); ++i) {
            CHECK(bytes[i] == (i < offset ? 0xa5 : 0));
        }
    }
    for (unsigned pattern = 0; pattern < 256; ++pattern) {
        memset(bytes, (int)pattern, sizeof(bytes));
        CHECK(vireo_secure_clear(bytes + 1, sizeof(bytes) - 2) == VIREO_OK && errno == EDOM);
        CHECK(bytes[0] == pattern && bytes[sizeof(bytes) - 1] == pattern);
        for (size_t i = 1; i + 1 < sizeof(bytes); ++i) { CHECK(bytes[i] == 0); }
    }
    puts("secure clear: NULL/zero, 260 exact suffixes, 256 binary patterns, repeat and errno passed");
    return 0;
}
