#ifndef VIREO_PASSWORD_TEST_H
#define VIREO_PASSWORD_TEST_H
#include <vireo/security/password.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

/* 固定输入来自既有libsodium Argon2id13路径，独立于本wrapper及其native调用。
 * pwd={a,0,b}，salt={0..15}，m=8KiB/t1/p1，tag32。非生产生成策略。
 */
#define KNOWN_PHC "$argon2id$v=19$m=8,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$" \
    "1h66y+ogiMY1ve8SvI+c8wsgbnh8oiTm5thtBXhNno0"
#define PHC_SALT "AAECAwQFBgcICQoLDA0ODw"
#define PHC_TAG "1h66y+ogiMY1ve8SvI+c8wsgbnh8oiTm5thtBXhNno0"
#endif
