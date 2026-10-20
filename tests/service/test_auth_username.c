/*
- PROJECT : VIREO
- FILE    : test_auth_username.c
- AUTHOR  : bitofux
- DATE    : 2026-10-19
- BRIEF   : 此模块负责：
- -- 验证账号完整字节集合、边界、发布、拥有值与locale独立合同
 */

#include <vireo/service/auth_username.h>
#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(VIREO_AUTH_USERNAME_MIN_LENGTH == 3, "minimum");
_Static_assert(VIREO_AUTH_USERNAME_MAX_LENGTH == 32, "maximum");

static size_t checks;
static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
static const char canonical[] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789_";

/* 失败同时验证完整对象字节保持；长度越界用一字节输入暴露错误扫描。 */
static void rejected(const char *input, size_t length, vireo_result_t expected)
{
    vireo_auth_username_t out;
    unsigned char before[sizeof(out)];
    memset(&out, 0xa5, sizeof(out));
    memcpy(before, &out, sizeof(out));
    errno = EDOM;
    assert(vireo_auth_username_prepare(input, length, &out) == expected);
    assert(errno == EDOM && memcmp(before, &out, sizeof(out)) == 0);
    ++checks;
}

/* 独立字符表给出预期，不在测试中复制实现的ASCII区间判断。 */
static void accepted(const char *input, size_t length)
{
    vireo_auth_username_t out, again;
    memset(&out, 0xa5, sizeof(out));
    errno = EDOM;
    assert(vireo_auth_username_prepare(input, length, &out) == VIREO_OK);
    assert(errno == EDOM && out.length == length && !memcmp(out.username, input, length));
    for (size_t i = 0; i < length; ++i) {
        const char *where = memchr(alphabet, (unsigned char)input[i], sizeof(alphabet) - 1);
        assert(where != NULL && out.key[i] == (unsigned char)canonical[where - alphabet]);
    }
    for (size_t i = length; i < VIREO_AUTH_USERNAME_MAX_LENGTH; ++i) {
        assert(out.username[i] == 0 && out.key[i] == 0);
    }
    assert(vireo_auth_username_prepare((const char *)out.key, out.length, &again) == VIREO_OK);
    assert(errno == EDOM && again.length == out.length && !memcmp(again.key, out.key, length));
    ++checks;
}

static void all_bytes(void)
{
    for (unsigned int b = 0; b <= UINT8_MAX; ++b) {
        for (size_t pos = 0; pos < 3; ++pos) {
            char input[3] = {'a', 'a', 'a'};
            unsigned char byte = (unsigned char)b;
            memcpy(input + pos, &byte, 1);
            if (memchr(alphabet, (int)b, sizeof(alphabet) - 1) != NULL) {
                accepted(input, sizeof(input));
            } else {
                rejected(input, sizeof(input), VIREO_RESULT_PROTOCOL);
            }
        }
    }
}

int main(void)
{
    char one = 'a';
    const size_t invalid_lengths[] = {0, 1, 2, 33, SIZE_MAX};
    for (size_t i = 0; i < sizeof(invalid_lengths) / sizeof(invalid_lengths[0]); ++i) {
        rejected(&one, invalid_lengths[i], VIREO_RESULT_RANGE);
    }
    rejected(NULL, 3, VIREO_RESULT_INVALID_ARGUMENT);
    rejected(NULL, SIZE_MAX, VIREO_RESULT_INVALID_ARGUMENT);
    errno = EDOM;
    assert(vireo_auth_username_prepare("abc", SIZE_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_username_prepare(NULL, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(errno == EDOM);
    checks += 2;

    assert(setlocale(LC_CTYPE, "C") != NULL);
    all_bytes();
    /* 同一字节集合在UTF-8 locale仍不接受非ASCII字母。 */
    assert(setlocale(LC_CTYPE, "C.UTF-8") != NULL);
    all_bytes();
    const char *invalid[] = {" Alice_7", "Alice_7 ", "Ali ce", "Al\tice", "Ali\nce",
        "ali.ce", "ali-ce", "ali/ce", "ali\\ce", "用户甲", "café", "cafe\xCC\x81", "Ａlice", "abc😀"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        rejected(invalid[i], strlen(invalid[i]), VIREO_RESULT_PROTOCOL);
    }
    char maximum[32];
    memset(maximum, 'Z', sizeof(maximum));
    accepted(maximum, sizeof(maximum));
    maximum[31] = '!';
    rejected(maximum, sizeof(maximum), VIREO_RESULT_PROTOCOL);
    accepted("Alice_7", 7);
    accepted("_A1", 3);
    accepted("___", 3);
    accepted("123", 3);

    char input[] = "Alice_7";
    vireo_auth_username_t first, second;
    assert(vireo_auth_username_prepare(input, 7, &first) == VIREO_OK);
    memset(input, 'X', sizeof(input));
    assert(!memcmp(first.username, "Alice_7", 7) && !memcmp(first.key, "alice_7", 7));
    assert(vireo_auth_username_prepare("ALICE_7", 7, &second) == VIREO_OK);
    assert(first.length == second.length && !memcmp(first.key, second.key, first.length));
    checks += 2;
    printf("PASS %zu username checks; all 256 bytes at first/middle/last under C and C.UTF-8; lengths, owned values, atomic output, errno\n", checks);
    return 0;
}
