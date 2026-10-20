/*
 * PROJECT : VIREO
 * FILE    : auth_password_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : service自身的状态与显式依赖注入，不暴露给其他模块。
 */
#ifndef VIREO_SERVICE_AUTH_PASSWORD_INTERNAL_H
#define VIREO_SERVICE_AUTH_PASSWORD_INTERNAL_H

#include <stdatomic.h>
#include <vireo/service/auth_password.h>

/** @brief 仅本组件own测试可替换，构造时复制且context须活到gate销毁。 */
typedef struct vireo_auth_password_runtime {
    void *context; /**< caller拥有的测试上下文；native使用NULL。 */
    void *(*allocate)(void *context, size_t bytes); /**< 返回独占且对齐的对象内存，失败NULL。 */
    void (*deallocate)(void *context, void *memory); /**< 配对释放，不跳出调用栈。 */
    vireo_result_t (*create)(void *context, vireo_password_policy_t const *policy,
        void const *password, size_t length, char *encoded, size_t capacity,
        size_t *encoded_length); /**< 同035create，测试不得保留借用指针或跳出。 */
    vireo_result_t (*inspect)(void *context, vireo_password_policy_t const *policy,
        char const *encoded, size_t length, vireo_password_info_t *info); /**< 同035纯检查。 */
    vireo_result_t (*verify)(void *context, vireo_password_policy_t const *policy,
        void const *password, size_t length, char const *encoded, size_t encoded_length,
        bool *matches); /**< 同035verify，同步返回前结束全部计算/清理。 */
    bool (*compare_exchange)(void *context, atomic_uint_least64_t *state,
        uint_least64_t *expected, uint_least64_t desired); /**< seq_cst弱CAS，失败更新expected。 */
} vireo_auth_password_runtime_t;

/** @brief 私有布局，无密码、PHC、DB、网络资源或等待者容器。 */
struct vireo_auth_password_gate {
    uint32_t max_parallel; /**< 创建时复制的活动数上限，发布后只读。 */
    uint32_t memory_budget_kib; /**< 创建时复制的m参数和上限，发布后只读。 */
    atomic_uint_least64_t state; /**< count[0,9)、KiB[9,30)、closed第30位。 */
    vireo_auth_password_runtime_t runtime; /**< 复制的不可变依赖；context只借用。 */
};

/**
 * @brief 私有构造接点，复制配对runtime，不改任何全局操作表。
 * @param[in] options 同公开create的合法配置。
 * @param[in,out] out 同公开create的独占空owner。
 * @param[in] runtime 必需完整依赖，context借至gate销毁；独立测试各用自己的上下文。
 * @retval VIREO_OK 发布新对象。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 指针/空owner/runtime函数不满足合同。
 * @retval VIREO_RESULT_RANGE 配置越界。
 * @retval VIREO_RESULT_NO_MEMORY 分配失败。
 * @note 失败保持out、保持errno；线程/销毁前提同公开create，无跨组件私有头依赖。
 */
vireo_result_t vireo_auth_password_gate_create_with_runtime(
    vireo_auth_password_gate_options_t const *options, vireo_auth_password_gate_t **out,
    vireo_auth_password_runtime_t const *runtime);

#endif
