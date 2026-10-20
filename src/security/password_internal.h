#ifndef VIREO_SECURITY_PASSWORD_INTERNAL_H
#define VIREO_SECURITY_PASSWORD_INTERNAL_H

#include <vireo/security/password.h>

enum { VIREO_PASSWORD_SALT_BYTES = 16, VIREO_PASSWORD_TAG_BYTES = 32,
       VIREO_PASSWORD_MAX_BYTES = 4096 };

/* 仅本组件own运行边界；每次调用显式借用，不修改全局操作表。 */
typedef struct vireo_password_runtime {
    void *context;
    int (*random_bytes)(void *context, unsigned char *out, int length);
    vireo_result_t (*derive)(void *context, void const *password, size_t length,
        unsigned char const salt[VIREO_PASSWORD_SALT_BYTES], uint32_t memory_kib,
        uint32_t iterations, unsigned char tag[VIREO_PASSWORD_TAG_BYTES]);
} vireo_password_runtime_t;

typedef struct vireo_password_record {
    vireo_password_info_t info;
    unsigned char salt[VIREO_PASSWORD_SALT_BYTES];
    unsigned char tag[VIREO_PASSWORD_TAG_BYTES];
} vireo_password_record_t;

bool vireo_password_policy_valid(vireo_password_policy_t const *policy);
vireo_result_t vireo_password_parse(vireo_password_policy_t const *policy,
    char const *encoded, size_t length, vireo_password_record_t *record);
vireo_result_t vireo_password_encode(uint32_t memory_kib, uint32_t iterations,
    unsigned char const salt[VIREO_PASSWORD_SALT_BYTES],
    unsigned char const tag[VIREO_PASSWORD_TAG_BYTES], char out[VIREO_PASSWORD_ENCODED_CAPACITY],
    size_t *length);

vireo_result_t vireo_password_create_with_runtime(vireo_password_policy_t const *policy,
    void const *password, size_t length, char *encoded, size_t capacity,
    size_t *encoded_length, vireo_password_runtime_t const *runtime);
vireo_result_t vireo_password_verify_with_runtime(vireo_password_policy_t const *policy,
    void const *password, size_t length, char const *encoded, size_t encoded_length,
    bool *matches, vireo_password_runtime_t const *runtime);

#endif
