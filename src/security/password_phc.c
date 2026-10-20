/* 严格有界PHC编解码；不分配内存，不调用随机源或KDF。 */
#include "password_internal.h"
#include <inttypes.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

static char const alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool vireo_password_policy_valid(vireo_password_policy_t const *p) {
    return p != NULL && p->create_memory_kib >= 65536 && p->create_memory_kib <= 262144 &&
        p->create_iterations >= 3 && p->create_iterations <= 10 &&
        p->max_verify_memory_kib >= p->create_memory_kib && p->max_verify_memory_kib <= 262144 &&
        p->max_verify_iterations >= p->create_iterations && p->max_verify_iterations <= 10 &&
        p->max_password_bytes >= 1 && p->max_password_bytes <= VIREO_PASSWORD_MAX_BYTES;
}

/* cursor永远位于原长度范围内，失败不越过end。 */
static bool literal(char const **cursor, char const *end, char const *word) {
    size_t const length = strlen(word);
    if ((size_t)(end - *cursor) < length || memcmp(*cursor, word, length) != 0) {
        return false;
    }
    *cursor += length;
    return true;
}

static bool decimal(char const **cursor, char const *end, uint32_t *value) {
    char const *p = *cursor;
    uint32_t number = 0;
    if (p == end || *p < '0' || *p > '9') { return false; }
    bool const zero = *p == '0';
    size_t count = 0;
    while (p != end && *p >= '0' && *p <= '9') {
        uint32_t const digit = (uint32_t)(*p - '0');
        if (number > (UINT32_MAX - digit) / 10 || (zero && count != 0)) { return false; }
        number = number * 10 + digit;
        ++p;
        ++count;
    }
    *cursor = p;
    *value = number;
    return true;
}

static int base64_digit(unsigned char c) {
    if (c >= 'A' && c <= 'Z') { return (int)(c - 'A'); }
    if (c >= 'a' && c <= 'z') { return (int)(c - 'a') + 26; }
    if (c >= '0' && c <= '9') { return (int)(c - '0') + 52; }
    if (c == '+') { return 62; }
    if (c == '/') { return 63; }
    return -1;
}

static bool decode(char const *input, size_t length, unsigned char *out, size_t bytes) {
    uint32_t accumulator = 0;
    unsigned int bits = 0;
    size_t written = 0;
    for (size_t i = 0; i < length; ++i) {
        int const digit = base64_digit((unsigned char)input[i]);
        if (digit < 0) { return false; }
        accumulator = (accumulator << 6) | (uint32_t)digit;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (written == bytes) { return false; }
            out[written++] = (unsigned char)((accumulator >> bits) & UINT32_C(255));
        }
    }
    return written == bytes && (accumulator & ((UINT32_C(1) << bits) - 1)) == 0;
}

vireo_result_t vireo_password_parse(vireo_password_policy_t const *policy,
    char const *encoded, size_t length, vireo_password_record_t *record) {
    char const *cursor = encoded;
    char const *end = encoded + length;
    uint32_t memory = 0;
    uint32_t iterations = 0;
    if (!literal(&cursor, end, "$argon2id$v=19$m=") || !decimal(&cursor, end, &memory) ||
        !literal(&cursor, end, ",t=") || !decimal(&cursor, end, &iterations) ||
        !literal(&cursor, end, ",p=1$") || (size_t)(end - cursor) != 66 || cursor[22] != '$' ||
        !decode(cursor, 22, record->salt, VIREO_PASSWORD_SALT_BYTES) ||
        !decode(cursor + 23, 43, record->tag, VIREO_PASSWORD_TAG_BYTES)) {
        return VIREO_RESULT_PROTOCOL;
    }
    if (memory < 8 || memory > policy->max_verify_memory_kib ||
        iterations < 1 || iterations > policy->max_verify_iterations) {
        return VIREO_RESULT_RANGE;
    }
    record->info = (vireo_password_info_t){19, memory, iterations, 1, length};
    return VIREO_OK;
}

static void encode_base64(unsigned char const *input, size_t bytes, char *out) {
    uint32_t accumulator = 0;
    unsigned int bits = 0;
    size_t written = 0;
    for (size_t i = 0; i < bytes; ++i) {
        accumulator = (accumulator << 8) | input[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out[written++] = alphabet[(accumulator >> bits) & UINT32_C(63)];
        }
    }
    if (bits != 0) { out[written++] = alphabet[(accumulator << (6 - bits)) & UINT32_C(63)]; }
    out[written] = '\0';
}

vireo_result_t vireo_password_encode(uint32_t memory_kib, uint32_t iterations,
    unsigned char const salt[VIREO_PASSWORD_SALT_BYTES],
    unsigned char const tag[VIREO_PASSWORD_TAG_BYTES], char out[VIREO_PASSWORD_ENCODED_CAPACITY],
    size_t *length) {
    char encoded_salt[23];
    char encoded_tag[44];
    encode_base64(salt, VIREO_PASSWORD_SALT_BYTES, encoded_salt);
    encode_base64(tag, VIREO_PASSWORD_TAG_BYTES, encoded_tag);
    int const count = snprintf(out, VIREO_PASSWORD_ENCODED_CAPACITY,
        "$argon2id$v=19$m=%" PRIu32 ",t=%" PRIu32 ",p=1$%s$%s",
        memory_kib, iterations, encoded_salt, encoded_tag);
    OPENSSL_cleanse(encoded_salt, sizeof(encoded_salt));
    OPENSSL_cleanse(encoded_tag, sizeof(encoded_tag));
    if (count < 0 || count >= VIREO_PASSWORD_ENCODED_CAPACITY) { return VIREO_RESULT_INTERNAL; }
    *length = (size_t)count;
    return VIREO_OK;
}
