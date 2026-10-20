/*
 * PROJECT : VIREO
 * FILE    : test_auth_login_verifier.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 公开接口的真实Argon2、统一拒绝、输入边界与关闭后行为。
 */
#include <vireo/service/auth_login_verifier.h>
#include <assert.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

#define CHECK(call, expected) do { errno = EDOM; assert((call) == (expected)); \
    assert(errno == EDOM); ++observations; } while (0)
static size_t observations;

int main(void)
{
    vireo_auth_password_gate_options_t const options = VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT;
    vireo_auth_password_gate_t *gate = NULL;
    vireo_auth_login_verifier_t *verifier = NULL;
    CHECK(vireo_auth_login_verifier_create(NULL, &verifier), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_login_verifier_create(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_password_gate_create(&options, &gate), VIREO_OK);
    CHECK(vireo_auth_login_verifier_create(gate, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_login_verifier_create(gate, &verifier), VIREO_OK);
    CHECK(vireo_auth_login_verifier_create(gate, &verifier), VIREO_RESULT_INVALID_ARGUMENT);

    vireo_mysql_user_credentials_t credentials = {
        .user_id = 7, .status = VIREO_MYSQL_USER_STATUS_ACTIVE
    };
    char const password[] = "Correct!7";
    CHECK(vireo_auth_password_hash_create(gate, password, sizeof(password) - 1,
        credentials.password_hash, sizeof(credentials.password_hash),
        &credentials.password_hash_length), VIREO_OK);
    vireo_mysql_user_credentials_t const before = credentials;
    bool authenticated = false;
    CHECK(vireo_auth_login_verifier_verify(verifier, gate, &credentials,
        password, sizeof(password) - 1, &authenticated), VIREO_OK);
    assert(authenticated);
    CHECK(vireo_auth_login_verifier_verify(verifier, gate, &credentials,
        "correct!7", 9, &authenticated), VIREO_OK);
    assert(!authenticated);
    authenticated = true;
    CHECK(vireo_auth_login_verifier_verify(verifier, gate, NULL,
        password, sizeof(password) - 1, &authenticated), VIREO_OK);
    assert(!authenticated);
    assert(!memcmp(&credentials, &before, sizeof(before)));
    credentials.status = VIREO_MYSQL_USER_STATUS_DISABLED;
    authenticated = true;
    CHECK(vireo_auth_login_verifier_verify(verifier, gate, &credentials,
        password, sizeof(password) - 1, &authenticated), VIREO_OK);
    assert(!authenticated);
    CHECK(vireo_auth_login_verifier_verify(verifier, gate, &credentials,
        "wrong123", 8, &authenticated), VIREO_OK);
    assert(!authenticated);

    /* 所有非OK路径都保留两种输出初值；包括必需指针、长度、字符和凭据错误。 */
    for (unsigned int initial = 0; initial < 2; ++initial) {
        authenticated = initial != 0;
        CHECK(vireo_auth_login_verifier_verify(NULL, gate, NULL, password, 9,
            &authenticated), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_auth_login_verifier_verify(verifier, NULL, NULL, password, 9,
            &authenticated), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, NULL, NULL, 9,
            &authenticated), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, NULL, password, 9,
            NULL), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, NULL, password, SIZE_MAX,
            &authenticated), VIREO_RESULT_RANGE);
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, NULL, password, 7,
            &authenticated), VIREO_RESULT_RANGE);
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, NULL, "bad pass", 8,
            &authenticated), VIREO_RESULT_PROTOCOL);
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, NULL, "\xe4\xb8\xad\xe6\x96\x87" "12", 8,
            &authenticated), VIREO_RESULT_PROTOCOL);
        credentials.user_id = 0;
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, &credentials, password, 9,
            &authenticated), VIREO_RESULT_INVALID_ARGUMENT);
        credentials.user_id = 7; credentials.status = VIREO_MYSQL_USER_STATUS_NONE;
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, &credentials, password, 9,
            &authenticated), VIREO_RESULT_INVALID_ARGUMENT);
        credentials.status = VIREO_MYSQL_USER_STATUS_ACTIVE;
        size_t const saved = credentials.password_hash_length;
        credentials.password_hash_length = 0;
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, &credentials, password, 9,
            &authenticated), VIREO_RESULT_RANGE);
        credentials.password_hash_length = SIZE_MAX;
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, &credentials, password, 9,
            &authenticated), VIREO_RESULT_RANGE);
        credentials.password_hash_length = saved;
        char const byte = credentials.password_hash[0]; credentials.password_hash[0] = '!';
        CHECK(vireo_auth_login_verifier_verify(verifier, gate, &credentials, password, 9,
            &authenticated), VIREO_RESULT_PROTOCOL);
        credentials.password_hash[0] = byte;
        assert(authenticated == (initial != 0));
    }
    char maximum[64]; memset(maximum, '~', sizeof(maximum));
    CHECK(vireo_auth_login_verifier_verify(verifier, gate, NULL, maximum, sizeof(maximum),
        &authenticated), VIREO_OK); assert(!authenticated);
    CHECK(vireo_auth_password_gate_close(gate), VIREO_OK);
    authenticated = true;
    CHECK(vireo_auth_login_verifier_verify(verifier, gate, NULL, password, 9,
        &authenticated), VIREO_RESULT_CANCELLED); assert(authenticated);
    CHECK(vireo_auth_login_verifier_verify(verifier, gate, &credentials, password, 9,
        &authenticated), VIREO_RESULT_CANCELLED); assert(authenticated);
    vireo_auth_login_verifier_t *failed = NULL;
    CHECK(vireo_auth_login_verifier_create(gate, &failed), VIREO_RESULT_CANCELLED); assert(!failed);
    CHECK(vireo_auth_login_verifier_destroy(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_login_verifier_destroy(&verifier), VIREO_OK); assert(!verifier);
    CHECK(vireo_auth_login_verifier_destroy(&verifier), VIREO_OK);
    CHECK(vireo_auth_password_gate_destroy(&gate), VIREO_OK);
    CHECK(vireo_mysql_user_credentials_clear(&credentials), VIREO_OK);
    OPENSSL_cleanse(maximum, sizeof(maximum));
    printf("PASS %zu public login verification observations; real Argon2, absent/disabled/wrong denied, output preserved\n", observations);
    return 0;
}
