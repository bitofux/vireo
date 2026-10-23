/* PROJECT : VIREO; AUTHOR : bitofux; DATE : 2026-10-22;
 * BRIEF : 每页授权、原始事实、清理优先与完整页/NEXT原子发布。 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <string.h>
#include <vireo/base/secure_clear.h>
#include "directory_list_internal.h"

#define STAGE(s) VIREO_DIRECTORY_LIST_STAGE_##s
_Static_assert(sizeof(vireo_mysql_node_page_t) <= 24576, "local page budget");
_Static_assert(sizeof(vireo_directory_list_result_t) <= 24576, "caller result budget");

static int native_utc(void *c, struct timespec *t) {
    (void)c;
    return clock_gettime(CLOCK_REALTIME, t);
}
static vireo_result_t native_verify(void *c, const vireo_page_token_key_t *key,
                                    const vireo_page_token_context_t *context,
                                    const vireo_page_token_t *token, uint64_t now,
                                    vireo_page_token_claims_t *claims) {
    (void)c;
    return vireo_page_token_verify(key, context, token, now, claims);
}
static vireo_result_t native_sign(void *c, const vireo_page_token_key_t *key,
                                  const vireo_page_token_claims_t *claims, uint64_t now,
                                  vireo_page_token_t *token) {
    (void)c;
    return vireo_page_token_sign(key, claims, now, token);
}
static vireo_result_t native_list(void *c, vireo_mysql_node_repository_t *r,
                                  const vireo_mysql_node_actor_t *a,
                                  const vireo_mysql_node_list_query_t *q, uint32_t timeout,
                                  vireo_mysql_node_page_t *page, vireo_mysql_node_report_t *report,
                                  vireo_mysql_node_error_t *error) {
    (void)c;
    return vireo_mysql_node_repository_list_children(r, a, q, timeout, page, report, error);
}
static const vireo_directory_list_runtime_t native_runtime = {NULL, native_utc, native_verify,
                                                              native_sign, native_list};

static bool all_zero(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (p[i] != 0) {
            return false;
        }
    }
    return true;
}

/* 非法timespec也拒绝；native errno只在clock_gettime的-1路径发布。 */
static vireo_result_t utc(const vireo_directory_list_runtime_t *r, uint64_t *now,
                          vireo_directory_list_error_t *e) {
    struct timespec t = {0};
    e->stage = STAGE(UTC);
    if (r->utc(r->context, &t) == -1) {
        e->system_errno = errno;
        return VIREO_RESULT_IO;
    }
    if (t.tv_sec < 0 || t.tv_nsec < 0 || t.tv_nsec >= 1000000000L) {
        return VIREO_RESULT_OVERFLOW;
    }
    const uint64_t seconds = (uint64_t)t.tv_sec, fraction = (uint64_t)t.tv_nsec / 1000000;
    if (seconds > (UINT64_MAX - fraction) / 1000) {
        return VIREO_RESULT_OVERFLOW;
    }
    *now = seconds * 1000 + fraction;
    return VIREO_OK;
}

static bool window(const vireo_page_token_claims_t *c, uint64_t now) {
    return c->issued_at_ms <= now && now < c->expires_at_ms;
}

static bool valid_page(const vireo_mysql_node_page_t *p, const vireo_mysql_node_actor_t *a,
                       const vireo_mysql_node_list_query_t *q) {
    if (p->count > q->page_size ||
        (p->has_more ? (p->count != q->page_size || p->next_after_id != p->nodes[p->count - 1].id)
                     : p->next_after_id != 0)) {
        return false;
    }
    uint64_t previous = q->after_id;
    for (size_t i = 0; i < p->count; ++i) {
        const vireo_mysql_node_value_t *v = &p->nodes[i];
        if (v->id <= previous || v->id == q->directory_id || v->owner_id != a->user_id ||
            !v->has_parent || v->parent_id != q->directory_id || v->name_length == 0 ||
            v->name_length > VIREO_MYSQL_NODE_NAME_CAPACITY ||
            v->updated_at_ms < v->created_at_ms || (v->name_length == 1 && v->name[0] == '.') ||
            (v->name_length == 2 && v->name[0] == '.' && v->name[1] == '.')) {
            return false;
        }
        for (size_t j = 0; j < v->name_length; ++j) {
            if (v->name[j] == 0 || v->name[j] == '/') {
                return false;
            }
        }
        if (v->kind == VIREO_MYSQL_NODE_DIRECTORY) {
            if (v->size != 0 || v->has_object_hash ||
                !all_zero(v->object_hash, sizeof(v->object_hash))) {
                return false;
            }
        } else if (v->kind != VIREO_MYSQL_NODE_FILE || !v->has_object_hash) {
            return false;
        }
        previous = v->id;
    }
    return true;
}

vireo_result_t vireo_directory_service_list_with_runtime(
    vireo_mysql_node_repository_t *repository, const vireo_page_token_key_t *key,
    const vireo_mysql_node_actor_t *actor, const vireo_directory_list_query_t *query,
    uint32_t timeout, vireo_directory_list_result_t *result, vireo_directory_list_error_t *error,
    const vireo_directory_list_runtime_t *r) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_page_token_claims_t claims = {0};
    vireo_page_token_t next = {{0}};
    vireo_mysql_node_page_t candidate = {0};
    vireo_directory_list_error_t local = {0}, *e = error != NULL ? error : &local;
    if (repository == NULL || key == NULL || actor == NULL || query == NULL || result == NULL ||
        r == NULL || r->utc == NULL || r->verify == NULL || r->sign == NULL || r->list == NULL) {
        goto done;
    }
    memset(result, 0, sizeof(*result));
    memset(e, 0, sizeof(*e));
    e->stage = STAGE(VALIDATE);
    if (actor->user_id == 0 || actor->session_id == 0 || query->directory_id == 0 ||
        (!query->has_page_token &&
         !all_zero(query->page_token.bytes, sizeof(query->page_token.bytes)))) {
        goto done;
    }
    if (query->page_size == 0 || query->page_size > 64 || timeout > 60000) {
        rc = VIREO_RESULT_RANGE;
        goto done;
    }
    const vireo_page_token_context_t context = {actor->user_id, actor->session_id,
                                                query->directory_id, query->page_size};
    vireo_mysql_node_list_query_t q = {query->directory_id, 0, query->page_size};
    bool bad_token = false;
    uint64_t now = 0;
    if (query->has_page_token) {
        rc = utc(r, &now, e);
        if (rc != VIREO_OK) {
            goto done;
        }
        e->stage = STAGE(TOKEN_VERIFY);
        rc = r->verify(r->context, key, &context, &query->page_token, now, &claims);
        result->token_checked = true;
        result->token_result = rc;
        if (rc != VIREO_OK && rc != VIREO_RESULT_PROTOCOL) {
            goto done;
        }
        bad_token = rc == VIREO_RESULT_PROTOCOL;
        q.after_id = bad_token ? UINT64_MAX : claims.after_id;
        if (bad_token) {
            q.page_size = 1;
        }
    }
    e->stage = STAGE(REPOSITORY);
    result->repository_operation = bad_token ? VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE
                                             : VIREO_DIRECTORY_LIST_REPOSITORY_CHILDREN;
    rc = r->list(r->context, repository, actor, &q, timeout, &candidate, &result->repository,
                 &e->repository);
    result->repository_result = rc;
    if (e->repository.cleanup_result != VIREO_OK) {
        rc = e->repository.cleanup_result == VIREO_RESULT_NOT_FOUND ? VIREO_RESULT_INTERNAL
                                                                    : e->repository.cleanup_result;
        goto done;
    }
    if (result->repository.cleanup_pending) {
        if (rc == VIREO_OK || rc == VIREO_RESULT_NOT_FOUND) {
            rc = VIREO_RESULT_INTERNAL;
        }
        goto done;
    }
    const vireo_mysql_node_report_t *report = &result->repository;
    if (rc != VIREO_OK) {
        if (report->found) {
            rc = VIREO_RESULT_INTERNAL;
            goto done;
        }
        if (rc == VIREO_RESULT_NOT_FOUND) {
            if (!report->rollback_confirmed || (report->issue != VIREO_MYSQL_NODE_AUTH_REJECTED &&
                                                report->issue != VIREO_MYSQL_NODE_NOT_FOUND)) {
                rc = VIREO_RESULT_INTERNAL;
                goto done;
            }
            result->outcome =
                report->issue == VIREO_MYSQL_NODE_AUTH_REJECTED
                    ? VIREO_DIRECTORY_LIST_UNAUTHORIZED
                    : (bad_token ? VIREO_DIRECTORY_LIST_BAD_TOKEN : VIREO_DIRECTORY_LIST_NOT_FOUND);
            if (result->outcome == VIREO_DIRECTORY_LIST_BAD_TOKEN) {
                rc = VIREO_RESULT_PROTOCOL;
            }
        }
        goto done;
    }
    if (!report->found || report->issue != VIREO_MYSQL_NODE_ISSUE_NONE ||
        !report->rollback_confirmed) {
        rc = VIREO_RESULT_INTERNAL;
        goto done;
    }
    e->stage = STAGE(PAGE_VALIDATE);
    if (!valid_page(&candidate, actor, &q)) {
        rc = VIREO_RESULT_INTERNAL;
        goto done;
    }
    if (bad_token) {
        /* 最大after的完整OK页必须为空；不把probe结果交给caller。 */
        if (candidate.count != 0 || candidate.has_more || candidate.next_after_id != 0) {
            rc = VIREO_RESULT_INTERNAL;
            goto done;
        }
        result->outcome = VIREO_DIRECTORY_LIST_BAD_TOKEN;
        rc = VIREO_RESULT_PROTOCOL;
        goto done;
    }
    if (candidate.has_more) {
        rc = utc(r, &now, e);
        if (rc != VIREO_OK) {
            goto done;
        }
        if (!query->has_page_token) {
            if (now > UINT64_MAX - VIREO_PAGE_TOKEN_TTL_MS) {
                rc = VIREO_RESULT_OVERFLOW;
                goto done;
            }
            claims.context = context;
            claims.issued_at_ms = now;
            claims.expires_at_ms = now + VIREO_PAGE_TOKEN_TTL_MS;
        } else if (!window(&claims, now)) {
            e->stage = STAGE(TOKEN_REVALIDATE);
            result->outcome = VIREO_DIRECTORY_LIST_BAD_TOKEN;
            rc = VIREO_RESULT_PROTOCOL;
            goto done;
        }
        claims.after_id = candidate.next_after_id;
        e->stage = STAGE(TOKEN_SIGN);
        rc = r->sign(r->context, key, &claims, now, &next);
        if (rc != VIREO_OK) {
            goto done;
        }
        rc = utc(r, &now, e);
        if (rc != VIREO_OK) {
            goto done;
        }
        e->stage = STAGE(TOKEN_REVALIDATE);
        if (!window(&claims, now)) {
            if (query->has_page_token) {
                result->outcome = VIREO_DIRECTORY_LIST_BAD_TOKEN;
                rc = VIREO_RESULT_PROTOCOL;
            } else {
                rc = VIREO_RESULT_TIMEOUT;
            }
            goto done;
        }
    }
    /* 只复制已校前缀，永不复制未用槽或名字尾部。 */
    result->page.count = candidate.count;
    result->page.has_more = candidate.has_more;
    result->page.next_after_id = candidate.next_after_id;
    for (size_t i = 0; i < candidate.count; ++i) {
        result->page.nodes[i] = candidate.nodes[i];
        memset(result->page.nodes[i].name + candidate.nodes[i].name_length, 0,
               VIREO_MYSQL_NODE_NAME_CAPACITY - candidate.nodes[i].name_length);
    }
    if (candidate.has_more) {
        result->next_page_token = next;
    }
    result->outcome = VIREO_DIRECTORY_LIST_PAGE;
    e->stage = STAGE(NONE);
    rc = VIREO_OK;
done:
    (void)vireo_secure_clear(&claims, sizeof(claims));
    (void)vireo_secure_clear(&next, sizeof(next));
    (void)vireo_secure_clear(&candidate, sizeof(candidate));
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_service_list(vireo_mysql_node_repository_t *repository,
                                            const vireo_page_token_key_t *key,
                                            const vireo_mysql_node_actor_t *actor,
                                            const vireo_directory_list_query_t *query,
                                            uint32_t timeout_ms,
                                            vireo_directory_list_result_t *result,
                                            vireo_directory_list_error_t *error) {
    return vireo_directory_service_list_with_runtime(repository, key, actor, query, timeout_ms,
                                                     result, error, &native_runtime);
}
