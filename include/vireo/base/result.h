/*
 * PROJECT : VIREO
 * FILE    : result.h
 * AUTHOR  : bitofux
 * DATE    : 2026-08-03
 * BRIEF   : 此模块负责：
 * -- 定义进程内函数调用使用的稳定结果分类
 * -- 返回结果码对应的稳定名称
 * -- 返回结果码对应的固定英文说明
 * -- 判断结果类别是否可能表示暂时性失败
 */

#ifndef VIREO_BASE_RESULT_H
#define VIREO_BASE_RESULT_H

#include <stdbool.h>

/**
 * @brief vireo进程内部函数调用使用的统一结果类型
 *
 * VIREO_OK 表示操作成功，其他成员表示稳定的失败或特殊结果分类
 */
typedef enum vireo_result {
    VIREO_OK = 0,
    /**< 操作成功 */

    VIREO_RESULT_INVALID_ARGUMENT = 1,
    /**< 调用者提供的参数不满足接口标准，比如非法值或者禁止的空指针 */

    VIREO_RESULT_RANGE = 2,
    /**< 数值、索引、偏移或者长度超出接口允许的有效范围 */

    VIREO_RESULT_OVERFLOW = 3,
    /**< 算术计算、容量计算或类型转换产生无法表示的结果 */

    VIREO_RESULT_NO_MEMORY = 4,
    /**< 无法获得完成当前操作所需的内存 */

    VIREO_RESULT_NOT_FOUND = 5,
    /**< 请求的文件、对象、任务或者其他资源不存在 */

    VIREO_RESULT_BUSY = 6,
    /**< 资源当前繁忙或者暂时不能接受操作，调用者可评估是否重试 */

    VIREO_RESULT_TIMEOUT = 7,
    /**< 操作未在规定时间内完成，操作的最终执行状态可能不确定 */

    VIREO_RESULT_CANCELLED = 8,
    /**< 操作在完成前观察到有效的取消请求，并按接口规定停止 */

    VIREO_RESULT_IO = 9,
    /**< 文件、网络、设备或其他输入输出操作发生未进一步分类的失败 */

    VIREO_RESULT_PROTOCOL = 10,
    /**< 输入数据或者通信内容违反协议规定 */

    VIREO_RESULT_DATABASE = 11,
    /**< 数据库操作发生未进一步分类的失败 */

    VIREO_RESULT_INTERNAL = 12,
    /**< 程序内部出现违反不变量或者理论上不应该发生的状态 */
} vireo_result_t;

/**
 * @brief 获取进程内结果码的名称
 *
 * 已知结果码返回对应的简短名称，未定义的枚举值返回"unknown"
 *
 * @param[in] result 要查询的进程内结果码；允许传入未定义的枚举值
 *
 * @return 指向静态只读字符串的非空指针
 *
 * @note 所有权：返回字符串属于本模块，调用者不可修改或者释放
 * @note 生命周期：返回字符串在整个进程生命周期内有效
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改errno
 */
char const *vireo_result_name(vireo_result_t result);

/**
 * @brief 获取进程内结果码的固定英文说明
 *
 * 已知结果码返回面向开发者的固定英文说明；未定义的枚举值返回"unknown result"
 *
 * @param[in] result 要查询的进程内结果码；允许传入未定义的枚举值
 *
 * @return 指向静态只读字符串的非空指针
 *
 * @note 所有权：返回字符串属于本模块，调用者不得修改或释放
 * @note 生命周期：返回字符串在整个进程生命周期内有效
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 */
char const *vireo_result_description(vireo_result_t result);

/**
 * @brief 判断结果类别是否可能表示暂时性失败
 *
 * 当前只有 VIREO_RESULT_BUSY 和 VIREO_RESULT_TIMEOUT 返回true
 * 其他已知结果以及所有未知结果均返回false
 *
 * @param[in] result 要查询的进程内结果码；允许传入未定义的枚举值
 *
 * @retval true 结果为 VIREO_RESULT_BUSY 或 VIREO_RESULT_TIMEOUT
 * @retval false 结果不提供可重试提示，result可能是一个未知值
 *
 * @note 线程安全：thread-safe；函数不访问或修改共享可变状态
 * @note errno：本函数不读取、不保存且不修改 errno
 * @warning 返回true不代表调用者可以立即、无限次或者无条件的重试
 */
bool vireo_result_is_retryable(vireo_result_t result);

#endif /* VIREO_BASE_RESULT_H */
