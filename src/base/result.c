/*
 * PROJECT : VIREO
 * FILE    : result.c
 * AUTHOR  : bitofux
 * DATE    : 2026-08-03
 * BRIEF   : vireo_result模块的实现
 * -- 将 vireo_result_t 映射为稳定名称
 * -- 将 vireo_result_t 映射为固定英文说明
 * -- 判断结果为类别是否可能表示暂时性失败
 */
#include <vireo/base/result.h>

/* 返回vireo_result_t 类型的枚举值的英文名称 */

char const *vireo_result_name(vireo_result_t result) {
    switch (result) {
        case VIREO_OK:
            return "ok";
        case VIREO_RESULT_INVALID_ARGUMENT:
            return "invalid_argument";
        case VIREO_RESULT_RANGE:
            return "range";
        case VIREO_RESULT_BUSY:
            return "busy";
        case VIREO_RESULT_CANCELLED:
            return "cancelled";
        case VIREO_RESULT_DATABASE:
            return "database";
        case VIREO_RESULT_INTERNAL:
            return "internal";
        case VIREO_RESULT_IO:
            return "io";
        case VIREO_RESULT_NOT_FOUND:
            return "not_found";
        case VIREO_RESULT_NO_MEMORY:
            return "no_memory";
        case VIREO_RESULT_OVERFLOW:
            return "overflow";
        case VIREO_RESULT_PROTOCOL:
            return "protocol";
        case VIREO_RESULT_TIMEOUT:
            return "timeout";
        default:
            return "unknown";
    }
}

/* 返回 vireo_result_t 类型的枚举值的描述信息 */
char const *vireo_result_description(vireo_result_t result) {
    switch (result) {
        case VIREO_OK:
            return "success";

        case VIREO_RESULT_INVALID_ARGUMENT:
            return "invalid argument";

        case VIREO_RESULT_RANGE:
            return "value out of range";

        case VIREO_RESULT_OVERFLOW:
            return "arithmetic overflow";

        case VIREO_RESULT_NO_MEMORY:
            return "memory allocation failed";

        case VIREO_RESULT_NOT_FOUND:
            return "resource not found";

        case VIREO_RESULT_BUSY:
            return "resource busy";

        case VIREO_RESULT_TIMEOUT:
            return "operation timed out";

        case VIREO_RESULT_CANCELLED:
            return "operation cancelled";

        case VIREO_RESULT_IO:
            return "I/O operation failed";

        case VIREO_RESULT_PROTOCOL:
            return "protocol error";

        case VIREO_RESULT_DATABASE:
            return "database error";

        case VIREO_RESULT_INTERNAL:
            return "internal error";

        default:
            return "unknown result";
    }
}

/* 返回指定 vireo_result_t 类型的枚举值是否重试 */
bool vireo_result_is_retryable(vireo_result_t result) {
    return (result == VIREO_RESULT_TIMEOUT || result == VIREO_RESULT_BUSY) ? true : false;
}
