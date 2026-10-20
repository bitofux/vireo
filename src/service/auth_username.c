/*
- PROJECT : VIREO
- FILE    : auth_username.c
- AUTHOR  : bitofux
- DATE    : 2026-10-19
- BRIEF   : 此模块负责：
- -- 有界校验ASCII账号并在完整成功后发布拥有型身份
 */

#include <vireo/service/auth_username.h>

vireo_result_t vireo_auth_username_prepare(
    const char *input, size_t input_length, vireo_auth_username_t *out)
{
    if (input == NULL || out == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (input_length < VIREO_AUTH_USERNAME_MIN_LENGTH ||
        input_length > VIREO_AUTH_USERNAME_MAX_LENGTH) {
        return VIREO_RESULT_RANGE;
    }

    /* 固定ASCII数值避免locale及负char影响；局部构造保证非法后缀也不半发布。 */
    vireo_auth_username_t prepared = {0};
    for (size_t i = 0; i < input_length; ++i) {
        unsigned char byte = (unsigned char)input[i];
        if (byte >= 0x41U && byte <= 0x5aU) {
            byte = (unsigned char)(byte + 0x20U);
        } else if (!((byte >= 0x61U && byte <= 0x7aU) ||
                     (byte >= 0x30U && byte <= 0x39U) || byte == 0x5fU)) {
            return VIREO_RESULT_PROTOCOL;
        }
        prepared.username[i] = input[i];
        prepared.key[i] = byte;
    }
    prepared.length = input_length;
    *out = prepared;
    return VIREO_OK;
}
