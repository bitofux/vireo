/* Public LOGIN admission traces: actual 037 buckets, no database or network claims. */
#include <vireo/service/auth_login_admission.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static size_t observations;
static unsigned char const device_a[16] = {1};
static vireo_auth_login_peer_t const ipv4 = {4, {192, 0, 2, 1}};
static vireo_auth_login_peer_t const mapped = {6, {0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,1}};
static vireo_auth_login_peer_t const ipv6 = {6, {0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}};

static vireo_auth_login_admission_t *opened(vireo_auth_login_admission_options_t const *o,
    uint64_t now)
{
    vireo_auth_login_admission_t *a = NULL;
    errno = EDOM;
    assert(vireo_auth_login_admission_create(o, now, &a) == VIREO_OK && a != NULL && errno == EDOM);
    return a;
}

static void finished(vireo_auth_login_admission_t **a)
{
    errno = EDOM;
    assert(vireo_auth_login_admission_destroy(a) == VIREO_OK && *a == NULL && errno == EDOM);
    assert(vireo_auth_login_admission_destroy(a) == VIREO_OK);
}

static vireo_rate_limit_decision_t attempt(vireo_auth_login_admission_t *a, uint64_t now,
    vireo_auth_login_peer_t const *peer, char const *name, unsigned char const device[16],
    vireo_rate_limit_outcome_t outcome, uint64_t retry)
{
    vireo_rate_limit_decision_t d;
    errno = EDOM;
    assert(vireo_auth_login_admission_check(a, now, peer, name, strlen(name), device, &d) == VIREO_OK);
    assert(d.outcome == outcome && d.retry_after_ns == retry && errno == EDOM);
    ++observations;
    return d;
}

static void default_traces(void)
{
    vireo_auth_login_admission_options_t const o = VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    assert(o.peer.burst_tokens == 20 && o.peer.refill_interval_ns == UINT64_C(3000000000));
    assert(o.account.burst_tokens == 5 && o.account.refill_interval_ns == UINT64_C(30000000000));
    assert(o.device.burst_tokens == 10 && o.device.refill_interval_ns == UINT64_C(6000000000));
    assert(o.max_keys == 4096 && o.max_memory_bytes == 1048576);
    vireo_auth_login_admission_t *a = opened(&o, 0);
    for (unsigned int i = 0; i < 5; ++i) {
        assert(attempt(a, 0, &ipv4, i % 2 == 0 ? "Alice" : "ALICE", device_a,
            VIREO_RATE_LIMIT_ADMITTED, 0).tracked_keys == 3);
    }
    attempt(a, 0, &mapped, "alice", device_a, VIREO_RATE_LIMIT_THROTTLED, UINT64_C(30000000000));
    attempt(a, UINT64_C(29999999999), &ipv4, "alice", device_a, VIREO_RATE_LIMIT_THROTTLED, 1);
    attempt(a, UINT64_C(30000000000), &ipv4, "alice", device_a, VIREO_RATE_LIMIT_ADMITTED, 0);
    unsigned char const device_b[16] = {2};
    assert(attempt(a, UINT64_C(30000000000), &ipv6, "ALICE", device_b,
        VIREO_RATE_LIMIT_THROTTLED, UINT64_C(30000000000)).tracked_keys == 3);
    for (unsigned int i = 0; i < 5; ++i) {
        attempt(a, UINT64_C(30000000000), &ipv6, "bob", device_b, VIREO_RATE_LIMIT_ADMITTED, 0);
    }
    finished(&a);
    a = opened(&o, 0);
    for (unsigned int i = 0; i < 20; ++i) {
        char name[16]; int const n = snprintf(name, sizeof(name), "acct%u", i);
        assert(n >= 3 && (size_t)n < sizeof(name));
        unsigned char d[16] = {0}; d[15] = (unsigned char)i;
        attempt(a, 0, i % 2 == 0 ? &ipv4 : &mapped, name, d, VIREO_RATE_LIMIT_ADMITTED, 0);
    }
    attempt(a, 0, &ipv4, "another", device_a, VIREO_RATE_LIMIT_THROTTLED, UINT64_C(3000000000));
    attempt(a, UINT64_C(3000000000), &ipv4, "another", device_a, VIREO_RATE_LIMIT_ADMITTED, 0);
    finished(&a);
    a = opened(&o, 0);
    for (unsigned int i = 0; i < 10; ++i) {
        char name[16]; int const n = snprintf(name, sizeof(name), "acct%u", i);
        assert(n >= 3 && (size_t)n < sizeof(name));
        vireo_auth_login_peer_t p = ipv4; p.address[3] = (unsigned char)(i + 1);
        attempt(a, 0, &p, name, device_a, VIREO_RATE_LIMIT_ADMITTED, 0);
    }
    attempt(a, 0, &ipv6, "another", device_a, VIREO_RATE_LIMIT_THROTTLED, UINT64_C(6000000000));
    attempt(a, UINT64_C(6000000000), &ipv6, "another", device_a, VIREO_RATE_LIMIT_ADMITTED, 0);
    finished(&a);
}

static void capacity_and_time(void)
{
    vireo_auth_login_admission_options_t o = VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    o.max_keys = 2;
    vireo_auth_login_admission_t *a = opened(&o, 0);
    assert(attempt(a, 0, &ipv4, "alice", device_a, VIREO_RATE_LIMIT_CAPACITY, 0).tracked_keys == 0);
    finished(&a);
    o.max_keys = 3;
    a = opened(&o, 0);
    attempt(a, 0, &ipv4, "alice", device_a, VIREO_RATE_LIMIT_ADMITTED, 0);
    unsigned char const device_b[16] = {2};
    assert(attempt(a, 0, &ipv6, "bob", device_b, VIREO_RATE_LIMIT_CAPACITY, 0).tracked_keys == 3);
    /* CAPACITY没有误扣旧桶；剩余四次账号额度仍全部可用。 */
    for (unsigned int i = 0; i < 4; ++i) {
        attempt(a, 0, &ipv4, "alice", device_a, VIREO_RATE_LIMIT_ADMITTED, 0);
    }
    attempt(a, 0, &ipv4, "alice", device_a, VIREO_RATE_LIMIT_THROTTLED, UINT64_C(30000000000));
    /* 账号仍欠额，不能LRU回收；到150秒全部补满才可整体复用。 */
    attempt(a, UINT64_C(3000000000), &ipv6, "bob", device_b, VIREO_RATE_LIMIT_CAPACITY, 0);
    assert(attempt(a, UINT64_C(150000000000), &ipv6, "bob", device_b,
        VIREO_RATE_LIMIT_ADMITTED, 0).tracked_keys == 3);
    vireo_rate_limit_decision_t d, before;
    memset(&d, 0xa5, sizeof(d)); memcpy(&before, &d, sizeof(d));
    errno = EDOM;
    assert(vireo_auth_login_admission_check(a, 0, &ipv4, "alice", 5, device_a, &d) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&d, &before, sizeof(d)) && errno == EDOM);
    ++observations;
    finished(&a);
    a = opened(&o, UINT64_MAX);
    attempt(a, UINT64_MAX, &ipv4, "alice", device_a, VIREO_RATE_LIMIT_ADMITTED, 0);
    attempt(a, UINT64_MAX, &mapped, "ALICE", device_a, VIREO_RATE_LIMIT_ADMITTED, 0);
    finished(&a);
}

int main(void)
{
    default_traces();
    capacity_and_time();
    printf("PASS %zu public observations: default quota traces, NAT/mapped/case aliases, all-or-none, capacity/reclaim, time endpoints; no network/DB claims\n", observations);
    return 0;
}
