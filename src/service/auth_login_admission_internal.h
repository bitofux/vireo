/* service自身的构造故障接点；不属于公共插件合同，不跨层访问私有状态。 */
#ifndef VIREO_SERVICE_AUTH_LOGIN_ADMISSION_INTERNAL_H
#define VIREO_SERVICE_AUTH_LOGIN_ADMISSION_INTERNAL_H
#include <vireo/service/auth_login_admission.h>

/** @brief 构造时按值复制；context须存活至destroy，所有回调正常返回且不保留短借。 */
typedef struct vireo_auth_login_admission_runtime {
    void *context; /**< native为NULL；own测试的caller拥有上下文。 */
    void *(*allocate)(void *context, size_t bytes); /**< wrapper的对齐独占分配，失败NULL。 */
    void (*release)(void *context, void *memory); /**< 配对释放wrapper，不抛出/跳栈。 */
    vireo_result_t (*create_limiter)(void *context,
        vireo_rate_limiter_options_t const *options, vireo_rate_limit_policy_t const *policies,
        size_t count, vireo_monotonic_ns_t now, vireo_rate_limiter_t **out);
        /**< 同037公开create；成功须返回可由公开check/destroy处理的真实对象。 */
} vireo_auth_login_admission_runtime_t;

/** @brief 不重复保存桶/时钟，无密码、网络或线程资源。 */
struct vireo_auth_login_admission {
    vireo_rate_limiter_t *limiter; /**< 独占真实037 owner，check短借，destroy消费。 */
    vireo_auth_login_admission_runtime_t runtime; /**< 构造复制，仅wrapper释放需要，context只借。 */
};

/**
 * @brief 本service自身依赖注入构造，其他参数/返回/errno/owner合同同公开create。
 * @param[in] options 必需配置，只借到返回。
 * @param[in] now 同域起始纳秒。
 * @param[in,out] out 必需空owner地址，成功才发布。
 * @param[in] runtime 必需完整依赖，按值复制，context借到destroy。
 * @retval VIREO_OK 已发布真实037子对象及wrapper。
 * @retval VIREO_RESULT_INVALID_ARGUMENT NULL/非空out/runtime缺失或037零配置。
 * @retval VIREO_RESULT_OVERFLOW 037资源乘加溢出。
 * @retval VIREO_RESULT_RANGE 037范围或预算不足。
 * @retval VIREO_RESULT_NO_MEMORY 任一分配失败，已取得的子对象回滚。
 * @note 无全局替换、无跨层私有头；两分配阶段都不提前发布out；保持errno。
 */
vireo_result_t vireo_auth_login_admission_create_with_runtime(
    vireo_auth_login_admission_options_t const *options, vireo_monotonic_ns_t now,
    vireo_auth_login_admission_t **out, vireo_auth_login_admission_runtime_t const *runtime);
#endif
