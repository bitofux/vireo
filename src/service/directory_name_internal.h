/* PROJECT : VIREO; FILE : directory_name_internal.h; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : 调用期名字规范化资源接点。 */
#ifndef VIREO_SERVICE_DIRECTORY_NAME_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_NAME_INTERNAL_H
#include <vireo/service/directory_name.h>

/** @brief 同步短借，无全局替换；只用于本组件实现/故障注入。 */
typedef struct vireo_directory_name_runtime {
    void *context; /**< caller拥有，存活至返回，允许NULL。 */
    vireo_result_t (*normalize)(void *, const unsigned char *, size_t, unsigned char **, size_t *);
    /**< 输入已通过NAME/1..255；OK产生非NULL owned结果和实际长度，失败无owner。
     * 原生仅包装显式长度NFC和负码转换，不改写输入；不保存借用。 */
    void (*release)(void *, unsigned char *);
    /**< 消费normalize的成功owner且不失败；不访问释放后的地址。 */
} vireo_directory_name_runtime_t;

/**
 * @brief 本组件私有同步依赖入口，业务/指针/输出合同同公开名字检查
 * @param[in] name 必需短借字节，同公开接口。
 * @param[in] name_length 原字节数，同公开接口。
 * @param[out] issue 必需独立输出，同公开接口。
 * @param[in] runtime 必需完整回调/context，短借至返回，缺失时保持输出。
 * @return 同公开接口；runtime/回调缺失为INVALID_ARGUMENT。
 */
vireo_result_t vireo_directory_name_validate_with_runtime(const unsigned char *name,
    size_t name_length, vireo_directory_name_issue_t *issue,
    const vireo_directory_name_runtime_t *runtime);
#endif
