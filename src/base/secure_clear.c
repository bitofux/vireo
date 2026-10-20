/*
 * PROJECT : VIREO
 * FILE    : secure_clear.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : C11 volatile 对象表示写，保留释放前的显式擦除
 */
#include <vireo/base/secure_clear.h>

vireo_result_t vireo_secure_clear(void *data, size_t size) {
    if (size != 0 && data == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    /* unsigned char 可访问任意对象表示；不形成 size 之外的地址或读取原内容。 */
    volatile unsigned char *bytes = data;
    while (size != 0) {
        *bytes = 0;
        bytes++;
        size--;
    }
    return VIREO_OK;
}
