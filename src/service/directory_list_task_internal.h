/* PROJECT : VIREO; FILE : directory_list_task_internal.h; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : LIST调用期执行接点与显式内部字节操作。 */
#ifndef VIREO_SERVICE_DIRECTORY_LIST_TASK_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_LIST_TASK_INTERNAL_H
#include <string.h>
#include <vireo/service/directory_list_task.h>

typedef vireo_result_t (*vireo_directory_list_service_fn)(vireo_mysql_node_repository_t *,
                                                          const vireo_page_token_key_t *,
                                                          const vireo_mysql_node_actor_t *,
                                                          const vireo_directory_list_query_t *,
                                                          uint32_t, vireo_directory_list_result_t *,
                                                          vireo_directory_list_error_t *);

/* 仅调用期借用函数；生产入口固定使用公开06服务，无全局替换。 */
vireo_result_t vireo_directory_list_task_execute_with_service(
    const vireo_task_t *, const vireo_directory_list_task_options_t *,
    vireo_mysql_node_repository_t *, const vireo_page_token_key_t *, uint64_t,
    vireo_directory_list_task_result_t *, vireo_directory_list_service_fn);

/* 内部格式有界字段大端读取/写入；caller先证明完整字段范围。 */
static inline uint64_t vireo_list_read_be(const unsigned char *p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i)
        v = (v << 8) | p[i];
    return v;
}
static inline void vireo_list_write_be(unsigned char *p, size_t n, uint64_t v) {
    for (size_t i = n; i > 0; --i) {
        p[i - 1] = (unsigned char)v;
        v >>= 8;
    }
}
static inline bool vireo_list_zero(const void *p, size_t n) {
    const unsigned char *s = p;
    for (size_t i = 0; i < n; ++i)
        if (s[i])
            return false;
    return true;
}
/* metadata_same_request只比较身份；这里另外比较operation/deadline。 */
static inline bool vireo_list_same_input(const vireo_directory_list_input_t *a,
                                         const vireo_directory_list_input_t *b) {
    bool same = false;
    return vireo_task_metadata_same_request(a->metadata, b->metadata, &same) == VIREO_OK && same &&
           a->metadata.operation == b->metadata.operation &&
           a->metadata.deadline_ns == b->metadata.deadline_ns &&
           a->actor.user_id == b->actor.user_id && a->actor.session_id == b->actor.session_id &&
           a->request.sequence == b->request.sequence &&
           a->request.session_handle == b->request.session_handle &&
           a->request.directory_id == b->request.directory_id &&
           a->request.page_size == b->request.page_size &&
           a->request.has_page_token == b->request.has_page_token &&
           memcmp(a->request.page_token, b->request.page_token, VIREO_NODE_LIST_TOKEN_SIZE) == 0;
}
#endif
