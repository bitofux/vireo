#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "directory_list_internal.h"

static max_align_t repo_marker, key_marker;
#define REPO ((vireo_mysql_node_repository_t *)(void *)&repo_marker)
#define KEY ((const vireo_page_token_key_t *)(const void *)&key_marker)
#define OUT(s) VIREO_DIRECTORY_LIST_##s
#define STAGE(s) VIREO_DIRECTORY_LIST_STAGE_##s
static size_t checks;
#define CHECK(call, want)                                                                  \
    do {                                                                                   \
        errno = EDOM;                                                                      \
        vireo_result_t got_ = (call);                                                      \
        if (got_ != (want)) {                                                              \
            fprintf(stderr, "line %d got %d want %d\n", __LINE__, (int)got_, (int)(want)); \
        }                                                                                  \
        assert(got_ == (want) && errno == EDOM);                                           \
        ++checks;                                                                          \
    } while (0)
static const vireo_mysql_node_actor_t actor = {7, 8};
typedef struct scenario {
    vireo_directory_list_query_t query;
    vireo_mysql_node_page_t page;
    vireo_mysql_node_report_t report;
    vireo_mysql_node_error_t diagnostic;
    vireo_result_t repository_rc, verify_rc, sign_rc;
    struct timespec time[3];
    size_t time_count, fail_time, verify_count, sign_count, repository_count;
    vireo_mysql_node_list_query_t actual_query;
    vireo_page_token_claims_t signed_claims;
    bool omit_error;
} scenario_t;

static void zeroed(const void *p, size_t n) {
    const unsigned char *v = p;
    for (size_t i = 0; i < n; ++i) {
        assert(v[i] == 0);
    }
}
static int clock_read(void *c, struct timespec *t) {
    scenario_t *s = c;
    assert(s->time_count < 3);
    ++s->time_count;
    errno = EIO;
    if (s->fail_time == s->time_count) {
        return -1;
    }
    *t = s->time[s->time_count - 1];
    return 0;
}
static vireo_result_t verify(void *c, const vireo_page_token_key_t *key,
                             const vireo_page_token_context_t *ctx, const vireo_page_token_t *token,
                             uint64_t now, vireo_page_token_claims_t *claims) {
    scenario_t *s = c;
    ++s->verify_count;
    errno = EIO;
    assert(key == KEY && token == &s->query.page_token && ctx->user_id == 7 &&
           ctx->session_id == 8 && ctx->directory_id == s->query.directory_id &&
           ctx->page_size == s->query.page_size && now == 1001);
    if (s->verify_rc == VIREO_OK) {
        *claims = (vireo_page_token_claims_t){*ctx, 90, 1000, 601000};
    }
    return s->verify_rc;
}
static vireo_result_t sign(void *c, const vireo_page_token_key_t *key,
                           const vireo_page_token_claims_t *claims, uint64_t now,
                           vireo_page_token_t *token) {
    scenario_t *s = c;
    ++s->sign_count;
    errno = EIO;
    assert(key == KEY && s->repository_count == 1 && claims->context.user_id == 7 &&
           claims->context.session_id == 8 &&
           claims->context.directory_id == s->query.directory_id &&
           claims->context.page_size == s->query.page_size &&
           claims->after_id == s->page.next_after_id && claims->issued_at_ms <= now &&
           now < claims->expires_at_ms);
    s->signed_claims = *claims;
    memset(token, 0x6b, sizeof(*token));
    return s->sign_rc;
}
static vireo_result_t list(void *c, vireo_mysql_node_repository_t *repo,
                           const vireo_mysql_node_actor_t *a,
                           const vireo_mysql_node_list_query_t *q, uint32_t timeout,
                           vireo_mysql_node_page_t *page, vireo_mysql_node_report_t *report,
                           vireo_mysql_node_error_t *e) {
    scenario_t *s = c;
    ++s->repository_count;
    errno = EIO;
    assert(repo == REPO && a == &actor && timeout == 17 && e != NULL);
    assert(q->directory_id == s->query.directory_id);
    s->actual_query = *q;
    *page = s->page;
    *report = s->report;
    *e = s->diagnostic;
    return s->repository_rc;
}
static vireo_directory_list_runtime_t runtime(scenario_t *s) {
    return (vireo_directory_list_runtime_t){s, clock_read, verify, sign, list};
}
static scenario_t valid(bool continuation, bool more) {
    scenario_t s = {.query = {.directory_id = 42, .page_size = 2, .has_page_token = continuation},
                    .report = {.found = true, .rollback_confirmed = true},
                    .time = {{1, 1000000}, {1, 2000000}, {1, 3000000}}};
    if (more) {
        s.page.count = 2;
        s.page.has_more = true;
        s.page.next_after_id = 120;
        for (size_t i = 0; i < 2; ++i) {
            s.page.nodes[i] = (vireo_mysql_node_value_t){.id = 100 + i * 20,
                                                         .owner_id = 7,
                                                         .has_parent = true,
                                                         .parent_id = 42,
                                                         .kind = VIREO_MYSQL_NODE_DIRECTORY,
                                                         .name = {'x'},
                                                         .name_length = 1,
                                                         .created_at_ms = 3,
                                                         .updated_at_ms = 5};
        }
    }
    return s;
}
static vireo_directory_list_result_t run(scenario_t *s, vireo_result_t want,
                                         vireo_directory_list_outcome_t outcome) {
    vireo_directory_list_result_t result;
    vireo_directory_list_error_t e;
    memset(&result, 0xa5, sizeof(result));
    memset(&e, 0xa5, sizeof(e));
    vireo_directory_list_runtime_t r = runtime(s);
    CHECK(vireo_directory_service_list_with_runtime(REPO, KEY, &actor, &s->query, 17, &result,
                                                    s->omit_error ? NULL : &e, &r),
          want);
    assert(result.outcome == outcome && s->repository_count <= 1);
    if (outcome != OUT(PAGE)) {
        zeroed(&result.page, sizeof(result.page));
        zeroed(&result.next_page_token, sizeof(result.next_page_token));
    }
    if (s->repository_count) {
        assert(result.repository_result == s->repository_rc &&
               result.repository.found == s->report.found &&
               result.repository.issue == s->report.issue &&
               result.repository.rollback_confirmed == s->report.rollback_confirmed &&
               result.repository.cleanup_pending == s->report.cleanup_pending);
        assert(result.repository_operation ==
               (s->verify_rc == VIREO_RESULT_PROTOCOL && s->query.has_page_token
                    ? VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE
                    : VIREO_DIRECTORY_LIST_REPOSITORY_CHILDREN));
        assert(s->actual_query.page_size ==
               (result.repository_operation == VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE
                    ? 1
                    : s->query.page_size));
        assert(s->actual_query.after_id ==
               (result.repository_operation == VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE
                    ? UINT64_MAX
                    : (s->query.has_page_token ? 90 : 0)));
        if (!s->omit_error) {
            assert(e.repository.stage == s->diagnostic.stage &&
                   e.repository.cleanup_result == s->diagnostic.cleanup_result &&
                   e.repository.cleanup_stage == s->diagnostic.cleanup_stage &&
                   e.repository.database.mysql_code == s->diagnostic.database.mysql_code &&
                   e.repository.cleanup_database.mysql_code ==
                       s->diagnostic.cleanup_database.mysql_code &&
                   e.repository.pool.system_error == s->diagnostic.pool.system_error);
        }
    } else {
        assert(result.repository_operation == VIREO_DIRECTORY_LIST_REPOSITORY_NONE);
    }
    assert(result.token_checked == (s->verify_count != 0));
    if (result.token_checked) {
        assert(result.token_result == s->verify_rc);
    }
    if (outcome == OUT(PAGE)) {
        assert(result.page.count == s->page.count && result.page.has_more == s->page.has_more &&
               result.page.next_after_id == s->page.next_after_id);
        for (size_t i = 0; i < result.page.count; ++i) {
            assert(result.page.nodes[i].id == s->page.nodes[i].id);
            zeroed(result.page.nodes[i].name + result.page.nodes[i].name_length,
                   255 - result.page.nodes[i].name_length);
        }
        zeroed(result.page.nodes + result.page.count,
               (64 - result.page.count) * sizeof(result.page.nodes[0]));
        if (!result.page.has_more) {
            zeroed(&result.next_page_token, sizeof(result.next_page_token));
        } else {
            for (size_t i = 0; i < 96; ++i) {
                assert(result.next_page_token.bytes[i] == 0x6b);
            }
        }
        if (!s->omit_error) {
            assert(e.stage == STAGE(NONE));
        }
    }
    if (!s->omit_error) {
        assert(e.system_errno == (want == VIREO_RESULT_IO && s->fail_time ? EIO : 0));
    }
    return result;
}

static void domain_cleanup_matrix(void) {
    const vireo_result_t repo_rc[] = {VIREO_OK, VIREO_RESULT_NOT_FOUND, VIREO_RESULT_DATABASE,
                                      VIREO_RESULT_BUSY, VIREO_RESULT_IO};
    const vireo_result_t cleanup[] = {VIREO_OK, VIREO_RESULT_BUSY, VIREO_RESULT_NOT_FOUND};
    for (size_t token = 0; token < 3; ++token)
        for (size_t ri = 0; ri < 5; ++ri)
            for (size_t ci = 0; ci < 3; ++ci)
                for (unsigned int flags = 0; flags < 8; ++flags)
                    for (unsigned int issue = 0; issue < 4; ++issue) {
                        scenario_t s = valid(token != 0, false);
                        s.verify_rc = token == 2 ? VIREO_RESULT_PROTOCOL : VIREO_OK;
                        s.repository_rc = repo_rc[ri];
                        s.diagnostic.cleanup_result = cleanup[ci];
                        s.report.found = (flags & 1) != 0;
                        s.report.rollback_confirmed = (flags & 2) != 0;
                        s.report.cleanup_pending = (flags & 4) != 0;
                        s.report.issue = (vireo_mysql_node_issue_t)issue;
                        s.omit_error = (flags & 1) == 0;
                        s.diagnostic.stage = VIREO_MYSQL_NODE_STAGE_NODE;
                        s.diagnostic.database.mysql_code = 123;
                        s.diagnostic.cleanup_stage =
                            ci ? VIREO_MYSQL_NODE_STAGE_RELEASE : VIREO_MYSQL_NODE_STAGE_NONE;
                        s.diagnostic.cleanup_database.mysql_code = 456;
                        s.diagnostic.pool.system_error = 789;
                        vireo_result_t want = s.repository_rc;
                        vireo_directory_list_outcome_t outcome = OUT(NONE);
                        if (ci) {
                            want = ci == 1 ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
                        } else if (s.report.cleanup_pending) {
                            if (ri <= 1) {
                                want = VIREO_RESULT_INTERNAL;
                            }
                        } else if (ri == 0) {
                            if (!s.report.found || !s.report.rollback_confirmed || issue != 0) {
                                want = VIREO_RESULT_INTERNAL;
                            } else {
                                outcome = token == 2 ? OUT(BAD_TOKEN) : OUT(PAGE);
                                want = token == 2 ? VIREO_RESULT_PROTOCOL : VIREO_OK;
                            }
                        } else if (s.report.found) {
                            want = VIREO_RESULT_INTERNAL;
                        } else if (ri == 1) {
                            if (!s.report.rollback_confirmed || (issue != 1 && issue != 2)) {
                                want = VIREO_RESULT_INTERNAL;
                            } else {
                                outcome = issue == 1
                                              ? OUT(UNAUTHORIZED)
                                              : (token == 2 ? OUT(BAD_TOKEN) : OUT(NOT_FOUND));
                                want = outcome == OUT(BAD_TOKEN) ? VIREO_RESULT_PROTOCOL
                                                                 : VIREO_RESULT_NOT_FOUND;
                            }
                        }
                        (void)run(&s, want, outcome);
                        assert(s.repository_count == 1 && s.sign_count == 0);
                    }
}

int main(void) {
    domain_cleanup_matrix();
    for (size_t continuation = 0; continuation < 2; ++continuation) {
        scenario_t s = valid(continuation != 0, true);
        /* Unused slots/name tails from a lower dependency must not escape. */
        memset(s.page.nodes + 2, 0xa5, sizeof(s.page.nodes) - 2 * sizeof(s.page.nodes[0]));
        memset(s.page.nodes[0].name + 1, 0xa5, 254);
        (void)run(&s, VIREO_OK, OUT(PAGE));
        assert(s.sign_count == 1 && s.time_count == (continuation ? 3 : 2));
        assert(s.signed_claims.issued_at_ms == (continuation ? 1000 : 1001) &&
               s.signed_claims.expires_at_ms == (continuation ? 601000 : 601001));
    }
    for (size_t fault = 0; fault < 23; ++fault) {
        scenario_t s = valid(true, true);
        vireo_mysql_node_value_t *v = &s.page.nodes[0];
        switch (fault) {
            case 0:
                s.page.count = 65;
                break;
            case 1:
                s.page.count = 0;
                break;
            case 2:
                s.page.count = 1;
                break;
            case 3:
                s.page.next_after_id = 121;
                break;
            case 4:
                s.page.has_more = false;
                break;
            case 5:
                v->id = 90;
                break;
            case 6:
                s.page.nodes[1].id = v->id;
                break;
            case 7:
                v->id = 42;
                break;
            case 8:
                v->owner_id = 8;
                break;
            case 9:
                v->has_parent = false;
                break;
            case 10:
                v->parent_id = 43;
                break;
            case 11:
                v->name_length = 0;
                break;
            case 12:
                v->name_length = 256;
                break;
            case 13:
                v->name[0] = 0;
                break;
            case 14:
                v->name[0] = '/';
                break;
            case 15:
                v->name[0] = '.';
                break;
            case 16:
                v->name[0] = '.';
                v->name[1] = '.';
                v->name_length = 2;
                break;
            case 17:
                v->updated_at_ms = 2;
                break;
            case 18:
                v->size = 1;
                break;
            case 19:
                v->has_object_hash = true;
                break;
            case 20:
                v->object_hash[0] = 1;
                break;
            case 21:
                v->kind = (vireo_mysql_node_kind_t)3;
                break;
            case 22:
                v->kind = VIREO_MYSQL_NODE_FILE;
                break;
            default:
                assert(false);
        }
        (void)run(&s, VIREO_RESULT_INTERNAL, OUT(NONE));
        assert(s.sign_count == 0);
    }
    /* Maximum valid page with non-UTF8 names, file hash all bit patterns, and maximum ID. */
    scenario_t large = valid(false, false);
    large.query.page_size = 64;
    large.page.count = 64;
    for (size_t i = 0; i < 64; ++i) {
        large.page.nodes[i] = (vireo_mysql_node_value_t){.id = i == 63 ? UINT64_MAX : 100 + i,
                                                         .owner_id = 7,
                                                         .has_parent = true,
                                                         .parent_id = 42,
                                                         .kind = VIREO_MYSQL_NODE_FILE,
                                                         .name_length = 255,
                                                         .has_object_hash = true,
                                                         .size = UINT64_MAX,
                                                         .created_at_ms = UINT64_MAX,
                                                         .updated_at_ms = UINT64_MAX};
        memset(large.page.nodes[i].name, 0xff, 255);
    }
    (void)run(&large, VIREO_OK, OUT(PAGE));
    assert(large.time_count == 0);
    for (size_t t = 0; t < 2; ++t) {
        for (size_t step = 1; step <= (t ? 3 : 2); ++step) {
            scenario_t s = valid(t != 0, true);
            s.fail_time = step;
            (void)run(&s, VIREO_RESULT_IO, OUT(NONE));
            assert(s.repository_count == ((t && step == 1) ? 0 : 1));
        }
    }
    for (size_t step = 1; step < 3; ++step) {
        for (size_t direction = 0; direction < 2; ++direction) {
            scenario_t s = valid(true, true);
            s.time[step] = (struct timespec){direction ? 601 : 0, 0};
            (void)run(&s, VIREO_RESULT_PROTOCOL, OUT(BAD_TOKEN));
            assert(s.sign_count == (step == 2 ? 1 : 0));
        }
    }
    scenario_t first_expired = valid(false, true);
    first_expired.time[1] = (struct timespec){601, 1000000};
    (void)run(&first_expired, VIREO_RESULT_TIMEOUT, OUT(NONE));
    scenario_t final = valid(true, false);
    final.time[1] = (struct timespec){900, 0};
    (void)run(&final, VIREO_OK, OUT(PAGE));
    assert(final.time_count == 1 && final.sign_count == 0);
    const vireo_result_t crypto[] = {VIREO_RESULT_NO_MEMORY, VIREO_RESULT_INTERNAL};
    for (size_t i = 0; i < 2; ++i) {
        scenario_t v = valid(true, false);
        v.verify_rc = crypto[i];
        (void)run(&v, crypto[i], OUT(NONE));
        assert(v.repository_count == 0);
        scenario_t s = valid(false, true);
        s.sign_rc = crypto[i];
        vireo_directory_list_result_t out = run(&s, crypto[i], OUT(NONE));
        assert(s.sign_count == 1 && out.repository_result == VIREO_OK && out.repository.found);
    }
    for (size_t f = 0; f < 4; ++f) {
        scenario_t s = valid(false, true);
        s.time[0] = f == 0 ? (struct timespec){-1, 0}
                           : (f == 1 ? (struct timespec){1, -1}
                                     : (f == 2 ? (struct timespec){1, 1000000000L}
                                               : (struct timespec){INT64_MAX, 0}));
        (void)run(&s, VIREO_RESULT_OVERFLOW, OUT(NONE));
        assert(s.sign_count == 0);
    }
    scenario_t ttl_overflow = valid(false, true);
    const uint64_t near_max = UINT64_MAX - 599999;
    ttl_overflow.time[0] =
        (struct timespec){(time_t)(near_max / 1000), (long)(near_max % 1000) * 1000000L};
    (void)run(&ttl_overflow, VIREO_RESULT_OVERFLOW, OUT(NONE));
    assert(ttl_overflow.sign_count == 0);
    scenario_t invalid_probe = valid(true, true);
    invalid_probe.verify_rc = VIREO_RESULT_PROTOCOL;
    (void)run(&invalid_probe, VIREO_RESULT_INTERNAL, OUT(NONE));
    assert(invalid_probe.sign_count == 0);
    /* Parameter/NULL output contracts, including optional diagnostics. */
    scenario_t s = valid(false, false);
    vireo_directory_list_runtime_t r = runtime(&s);
    vireo_directory_list_result_t out, saved;
    vireo_directory_list_error_t e, old;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&saved, &out, sizeof(saved));
    memset(&e, 0x5a, sizeof(e));
    memcpy(&old, &e, sizeof(old));
    CHECK(vireo_directory_service_list_with_runtime(NULL, KEY, &actor, &s.query, 17, &out, &e, &r),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&out, &saved, sizeof(out)) && !memcmp(&e, &old, sizeof(e)));
    CHECK(vireo_directory_service_list_with_runtime(REPO, NULL, &actor, &s.query, 17, &out, &e, &r),
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_service_list_with_runtime(REPO, KEY, NULL, &s.query, 17, &out, &e, &r),
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_service_list_with_runtime(REPO, KEY, &actor, NULL, 17, &out, &e, &r),
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_service_list_with_runtime(REPO, KEY, &actor, &s.query, 17, NULL, &e, &r),
          VIREO_RESULT_INVALID_ARGUMENT);
    r.list = NULL;
    CHECK(vireo_directory_service_list_with_runtime(REPO, KEY, &actor, &s.query, 17, &out, &e, &r),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&out, &saved, sizeof(out)) && !memcmp(&e, &old, sizeof(e)));
    r = runtime(&s);
    for (size_t p = 0; p < 7; ++p) {
        vireo_mysql_node_actor_t a = actor;
        s = valid(false, false);
        vireo_result_t want = VIREO_RESULT_INVALID_ARGUMENT;
        if (p == 0) {
            a.user_id = 0;
        } else if (p == 1) {
            a.session_id = 0;
        } else if (p == 2) {
            s.query.directory_id = 0;
        } else if (p == 3) {
            s.query.page_token.bytes[95] = 1;
        } else if (p == 4) {
            s.query.page_size = 0;
            want = VIREO_RESULT_RANGE;
        } else if (p == 5) {
            s.query.page_size = 65;
            want = VIREO_RESULT_RANGE;
        } else {
            want = VIREO_RESULT_RANGE;
        }
        CHECK(vireo_directory_service_list_with_runtime(REPO, KEY, &a, &s.query,
                                                        p == 6 ? 60001 : 17, &out, &e, &r),
              want);
        assert(out.outcome == OUT(NONE) && s.repository_count == 0);
        zeroed(&out.page, sizeof(out.page));
    }
    printf(
        "PASS %zu LIST service calls; domain/cleanup matrix, single-query probes, page isolation "
        "and UTC/crypto atomicity\n",
        checks);
    return 0;
}
