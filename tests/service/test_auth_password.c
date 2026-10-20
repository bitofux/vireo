/*
 * PROJECT : VIREO
 * FILE    : test_auth_password.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 公共输入政策的独立字符表、端点及拒绝路径。
 */
#include <vireo/service/auth_password.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(VIREO_AUTH_PASSWORD_MIN_BYTES == 8, "minimum");
_Static_assert(VIREO_AUTH_PASSWORD_MAX_BYTES == 64, "maximum");

static char const allowed[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

int main(void)
{
    size_t checks = 0;
    assert(sizeof(allowed) - 1 == 94);
    unsigned char password[65];
    memset(password, 'a', sizeof(password));
    for (size_t length = 0; length <= sizeof(password); ++length) {
        errno = EDOM;
        vireo_result_t const expected = length >= 8 && length <= 64 ? VIREO_OK : VIREO_RESULT_RANGE;
        assert(vireo_auth_password_validate(password, length) == expected && errno == EDOM);
        ++checks;
    }
    /* 一字节对象加越界长度暴露错误地先扫描内容的实现。 */
    unsigned char const one = 0;
    assert(vireo_auth_password_validate(&one, SIZE_MAX) == VIREO_RESULT_RANGE);
    assert(vireo_auth_password_validate(NULL, SIZE_MAX) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_validate(NULL, 8) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(errno == EDOM);
    checks += 3;
    size_t const positions[] = {0, 3, 7, 63};
    for (unsigned int byte = 0; byte <= UINT8_MAX; ++byte) {
        for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
            memset(password, 'a', sizeof(password));
            size_t const length = positions[i] == 63 ? 64 : 8;
            password[positions[i]] = (unsigned char)byte;
            vireo_result_t const expected = memchr(allowed, (int)byte, sizeof(allowed) - 1) != NULL
                ? VIREO_OK : VIREO_RESULT_PROTOCOL;
            errno = ERANGE;
            assert(vireo_auth_password_validate(password, length) == expected && errno == ERANGE);
            assert(password[positions[i]] == byte);
            ++checks;
        }
    }
    char const *valid[] = {"abcdefgh", "12345678", "!!!!!!!!", "ABCDEFGH", "!@#$%^&*()",
        "\"'\\`~[]{}", "Hello!2026"};
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        assert(vireo_auth_password_validate(valid[i], strlen(valid[i])) == VIREO_OK);
        ++checks;
    }
    char const *invalid[] = {" password", "password ", "pass word", "pass\tword",
        "pass\nword", "密码abcdefgh", "abcdefgh😀", "abcdefg\x7f"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        assert(vireo_auth_password_validate(invalid[i], strlen(invalid[i])) == VIREO_RESULT_PROTOCOL);
        ++checks;
    }
    printf("PASS %zu password policy checks; unified ASCII alphabet, lengths, no composition rule, input/errno preserved\n", checks);
    return 0;
}
