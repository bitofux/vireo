/* Own service allocation seam and exact-key observations via public 037 only. */
#include "auth_login_admission_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t observations;
static vireo_auth_login_peer_t const ipv4 = {4, {192,0,2,1}};
static unsigned char const device[16] = {0};
typedef struct fixture {
    bool fail_wrapper; /**< manager配置，wrapper分配返回NULL。 */
    bool fail_child; /**< manager配置，模拟公开037构造失败。 */
    size_t allocations; /**< wrapper分配尝试计数，不含037。 */
    size_t frees; /**< wrapper配对释放次数。 */
    size_t creates; /**< 037构造调用次数。 */
} fixture_t;

static void *allocate(void *context, size_t bytes)
{
    fixture_t *f = context; ++f->allocations; errno = EIO;
    return f->fail_wrapper ? NULL : malloc(bytes);
}
static void release(void *context, void *memory)
{
    fixture_t *f = context; ++f->frees; errno = EIO; free(memory);
}
static vireo_result_t create_child(void *context, vireo_rate_limiter_options_t const *o,
    vireo_rate_limit_policy_t const *p, size_t count, vireo_monotonic_ns_t now,
    vireo_rate_limiter_t **out)
{
    fixture_t *f = context; ++f->creates; errno = EIO;
    assert(count == 3 && p[0].policy_id == 1 && p[1].policy_id == 2 && p[2].policy_id == 3);
    return f->fail_child ? VIREO_RESULT_NO_MEMORY : vireo_rate_limiter_create(o, p, count, now, out);
}
static vireo_auth_login_admission_runtime_t runtime(fixture_t *f)
{
    return (vireo_auth_login_admission_runtime_t){f,allocate,release,create_child};
}

static void construction(void)
{
    fixture_t f = {0};
    vireo_auth_login_admission_runtime_t ops = runtime(&f);
    vireo_auth_login_admission_t *a = NULL;
    vireo_auth_login_admission_options_t o = VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    errno = EDOM;
    assert(vireo_auth_login_admission_create(NULL, 0, &a) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_login_admission_create(&o, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_login_admission_create_with_runtime(&o, 0, &a, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    ops.allocate = NULL;
    assert(vireo_auth_login_admission_create_with_runtime(&o, 0, &a, &ops) == VIREO_RESULT_INVALID_ARGUMENT);
    ops = runtime(&f);
    f.fail_child = true;
    assert(vireo_auth_login_admission_create_with_runtime(&o, 0, &a, &ops) == VIREO_RESULT_NO_MEMORY && a == NULL);
    assert(f.creates == 1 && f.allocations == 0 && f.frees == 0);
    f.fail_child = false; f.fail_wrapper = true;
    assert(vireo_auth_login_admission_create_with_runtime(&o, 0, &a, &ops) == VIREO_RESULT_NO_MEMORY && a == NULL);
    assert(f.creates == 2 && f.allocations == 1 && f.frees == 0);
    f.fail_wrapper = false;
    assert(vireo_auth_login_admission_create_with_runtime(&o, 0, &a, &ops) == VIREO_OK && a != NULL);
    assert(vireo_auth_login_admission_create(&o, 0, &a) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_rate_limiter_info_t info;
    assert(vireo_rate_limiter_inspect(a->limiter, &info) == VIREO_OK && info.policy_count == 3);
    size_t const exact = info.allocated_bytes;
    /* runtime和options是已复制值，不保留此栈表/配置地址。 */
    ops.release = NULL; o.peer.burst_tokens = 0;
    assert(vireo_auth_login_admission_destroy(&a) == VIREO_OK && a == NULL && f.frees == 1);
    assert(vireo_auth_login_admission_destroy(&a) == VIREO_OK && errno == EDOM);
    assert(vireo_auth_login_admission_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    o = (vireo_auth_login_admission_options_t)VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    o.max_memory_bytes = exact;
    assert(vireo_auth_login_admission_create(&o, 0, &a) == VIREO_OK);
    assert(vireo_auth_login_admission_destroy(&a) == VIREO_OK);
    --o.max_memory_bytes;
    assert(vireo_auth_login_admission_create(&o, 0, &a) == VIREO_RESULT_RANGE && a == NULL);
    o = (vireo_auth_login_admission_options_t)VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    o.max_keys = SIZE_MAX;
    assert(vireo_auth_login_admission_create(&o, 0, &a) == VIREO_RESULT_OVERFLOW);
    o.max_keys = 4097;
    assert(vireo_auth_login_admission_create(&o, 0, &a) == VIREO_RESULT_RANGE);
    o.max_keys = 0;
    assert(vireo_auth_login_admission_create(&o, 0, &a) == VIREO_RESULT_INVALID_ARGUMENT);
    o = (vireo_auth_login_admission_options_t)VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    o.account.burst_tokens = 0;
    assert(vireo_auth_login_admission_create(&o, 0, &a) == VIREO_RESULT_INVALID_ARGUMENT);
    o.account.burst_tokens = VIREO_RATE_LIMIT_MAX_BURST_TOKENS + 1;
    assert(vireo_auth_login_admission_create(&o, 0, &a) == VIREO_RESULT_RANGE);
    o = (vireo_auth_login_admission_options_t)VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    o.device.refill_interval_ns = VIREO_RATE_LIMIT_MAX_REFILL_INTERVAL_NS + 1;
    assert(vireo_auth_login_admission_create(&o, 0, &a) == VIREO_RESULT_RANGE && errno == EDOM);
    observations += 20;
}

static void errors(void)
{
    vireo_auth_login_admission_options_t const o = VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    vireo_auth_login_admission_t *a = NULL;
    assert(vireo_auth_login_admission_create(&o, 0, &a) == VIREO_OK);
    vireo_rate_limit_decision_t d, before;
    memset(&d, 0xa5, sizeof(d)); memcpy(&before, &d, sizeof(d));
    vireo_auth_login_peer_t bad = ipv4; bad.family = 0;
    char const tiny = 0;
    errno = EDOM;
    assert(vireo_auth_login_admission_check(NULL,0,&ipv4,"alice",5,device,&d) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_login_admission_check(a,0,NULL,"alice",5,device,&d) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_login_admission_check(a,0,&ipv4,NULL,SIZE_MAX,device,&d) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_login_admission_check(a,0,&ipv4,"alice",5,NULL,&d) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_login_admission_check(a,0,&ipv4,"alice",5,device,NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_login_admission_check(a,0,&bad,&tiny,SIZE_MAX,device,&d) == VIREO_RESULT_RANGE);
    assert(vireo_auth_login_admission_check(a,0,&bad,"alice",5,device,&d) == VIREO_RESULT_INVALID_ARGUMENT);
    bad = ipv4; bad.address[15] = 1;
    assert(vireo_auth_login_admission_check(a,0,&bad,"alice",5,device,&d) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_login_admission_check(a,0,&ipv4,"ab\0c",4,device,&d) == VIREO_RESULT_PROTOCOL);
    assert(vireo_auth_login_admission_check(a,0,&ipv4,"a b",3,device,&d) == VIREO_RESULT_PROTOCOL);
    assert(!memcmp(&d,&before,sizeof(d)) && errno == EDOM);
    vireo_rate_limiter_info_t info;
    assert(vireo_rate_limiter_inspect(a->limiter,&info) == VIREO_OK && info.tracked_keys == 0 && info.last_now == 0);
    assert(vireo_auth_login_admission_check(a,100,&ipv4,"alice",5,device,&d) == VIREO_OK);
    memcpy(&before,&d,sizeof(d));
    assert(vireo_auth_login_admission_check(a,99,&ipv4,"alice",5,device,&d) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&d,&before,sizeof(d)) && errno == EDOM);
    assert(vireo_rate_limiter_inspect(a->limiter,&info) == VIREO_OK && info.last_now == 100 && info.tracked_keys == 3);
    assert(vireo_auth_login_admission_destroy(&a) == VIREO_OK);
    observations += 13;
}

/* 用公开037查询冻结的字节期待值，断言三个实际桶都已耗尽；不访问037私有布局。 */
static void exact_keys(vireo_auth_login_peer_t const *p, char const *name, size_t length,
    unsigned char const dev[16], unsigned char const ipkey[32], unsigned char const accountkey[32])
{
    vireo_auth_login_admission_options_t o = VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    o.max_keys = 3; o.peer.burst_tokens = 1; o.account.burst_tokens = 1; o.device.burst_tokens = 1;
    vireo_auth_login_admission_t *a = NULL;
    assert(vireo_auth_login_admission_create(&o,0,&a) == VIREO_OK);
    vireo_rate_limit_decision_t d;
    assert(vireo_auth_login_admission_check(a,0,p,name,length,dev,&d) == VIREO_OK && d.outcome == VIREO_RATE_LIMIT_ADMITTED);
    vireo_rate_limit_request_t expected[3] = {{.policy_id=1,.cost=1},{.policy_id=2,.cost=1},{.policy_id=3,.cost=1}};
    memcpy(expected[0].key,ipkey,32); memcpy(expected[1].key,accountkey,32); memcpy(expected[2].key,dev,16);
    for (size_t i=0;i<3;++i) {
        assert(vireo_rate_limiter_check(a->limiter,0,&expected[i],1,&d) == VIREO_OK);
        assert(d.outcome == VIREO_RATE_LIMIT_THROTTLED && d.tracked_keys == 3);
    }
    assert(vireo_auth_login_admission_destroy(&a) == VIREO_OK);
    ++observations;
}

static void identities(void)
{
    unsigned char const ipkey[32] = {4,192,0,2,1};
    unsigned char const namekey[32] = {'a','l','i','c','e'};
    exact_keys(&ipv4,"Alice",5,device,ipkey,namekey);
    vireo_auth_login_peer_t const mapped = {6,{0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,1}};
    exact_keys(&mapped,"ALICE",5,device,ipkey,namekey);
    vireo_auth_login_peer_t const v6 = {6,{0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}};
    unsigned char const v6key[32] = {6,0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    exact_keys(&v6,"alice",5,device,v6key,namekey);
    char const maxname[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
    unsigned char const maxkey[32] = "abcdefghijklmnopqrstuvwxyz012345";
    exact_keys(&ipv4,maxname,32,device,ipkey,maxkey);
    for (size_t pos=0;pos<16;++pos) {
        unsigned char dev[16] = {0};dev[pos] = 255;
        exact_keys(&ipv4,"Alice",5,dev,ipkey,namekey);
    }
    /* 账号与设备的32字节key相同，policy分域仍保留两个独立桶。 */
    unsigned char collision[16] = {'a','l','i','c','e'};
    exact_keys(&ipv4,"Alice",5,collision,ipkey,namekey);
}

int main(void)
{
    construction(); errors(); identities();
    printf("PASS %zu own observations: two allocation stages/rollback, exact 3-domain keys via public 037, all device positions, errno/output, invalid input and time\n",observations);
    return 0;
}
