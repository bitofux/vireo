/* PROJECT : VIREO
 * FILE : test_auth_service.c
 * AUTHOR : bitofux
 * DATE : 2026-10-19
 * BRIEF : 显式故障依赖核业务顺序、三态交付、清理优先级和live局部擦除。
 */
#include "auth_service_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char phc[] = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static max_align_t markers[3];
#define REPO ((vireo_mysql_user_repository_t *)(void *)&markers[0])
#define GATE ((vireo_auth_password_gate_t *)(void *)&markers[1])
#define VERIFIER ((vireo_auth_login_verifier_t *)(void *)&markers[2])
#define CHECK(call, expected) do { errno = EDOM; vireo_result_t code_ = (call); \
    if (code_ != (expected)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)code_,(int)(expected)); } \
    assert(code_ == (expected) && errno == EDOM); ++checks; } while (0)
static size_t checks, wipes;
typedef struct scenario {
    vireo_result_t hash_rc, lookup_rc, verify_rc, token_rc, write_rc, cleanup_rc, lookup_cleanup_rc;
    bool matched, pending, lookup_pending, disabled, zero_token;
    vireo_mysql_login_commit_t commit;
    char trace[16];
    size_t used;
} scenario_t;

static void step(scenario_t *s, char c)
{ assert(s->used + 1 < sizeof(s->trace)); s->trace[s->used++] = c; s->trace[s->used] = 0; errno = EIO; }
static bool zero(const void *value, size_t size)
{
    const unsigned char *p = value;
    for (size_t i = 0; i < size; ++i) { if (p[i] != 0) { return false; } }
    return true;
}
static void cleared(void *context, const vireo_auth_service_workspace_t *w)
{ (void)context; assert(zero(w, sizeof(*w))); ++wipes; errno = EIO; }
static vireo_result_t hash(void *c, vireo_auth_password_gate_t *g, const void *password,
    size_t n, char *out, size_t capacity, size_t *written)
{
    scenario_t *s = c; assert(g == GATE && password != NULL && n >= 8 && n <= 64);
    assert(capacity == 128); step(s, 'H'); memcpy(out, phc, sizeof(phc));
    *written = sizeof(phc)-1; return s->hash_rc;
}
static vireo_result_t registration(void *c, vireo_mysql_user_repository_t *r,
    const vireo_mysql_registration_input_t *in, uint32_t timeout,
    vireo_mysql_registration_report_t *out, vireo_mysql_user_repository_error_t *error)
{
    scenario_t *s = c; assert(r == REPO && timeout == 17); step(s, 'R');
    assert(in->username_length == 7 && !memcmp(in->username,"Alice_7",7));
    assert(in->username_key_length == 7 && !memcmp(in->username_key,"alice_7",7));
    assert(in->password_hash_length == sizeof(phc)-1 && !memcmp(in->password_hash,phc,sizeof(phc)));
    assert(in->request_id[15] == 9 && in->occurred_at_ms == 1000 && in->latency_us == 31);
    out->commit = (vireo_mysql_registration_commit_t)s->commit;
    out->cleanup_pending = s->pending;
    if (out->commit == VIREO_MYSQL_REGISTRATION_COMMITTED) { out->user_id=41; out->root_node_id=42; out->audit_id=43; }
    if (error != NULL) { error->cleanup_result = s->cleanup_rc; }
    return s->write_rc;
}
static vireo_result_t lookup(void *c, vireo_mysql_user_repository_t *r, const void *key,
    size_t n, uint32_t timeout, vireo_mysql_user_credentials_t *out,
    vireo_mysql_credentials_report_t *report, vireo_mysql_user_repository_error_t *error)
{
    scenario_t *s = c; assert(r == REPO && timeout == 17 && n==7 && !memcmp(key,"alice_7",7)); step(s,'Q');
    report->found = s->lookup_rc == VIREO_OK; report->cleanup_pending = s->lookup_pending;
    error->cleanup_result = s->lookup_cleanup_rc;
    /* 即使失败也故意写秘密片段，观察本层全部出口是否擦除。 */
    memcpy(out->password_hash,phc,sizeof(phc)); out->password_hash_length=sizeof(phc)-1;
    if (report->found) { out->user_id=41; out->status=s->disabled ? VIREO_MYSQL_USER_STATUS_DISABLED : VIREO_MYSQL_USER_STATUS_ACTIVE; }
    return s->lookup_rc;
}
static vireo_result_t verify(void *c, const vireo_auth_login_verifier_t *v,
    vireo_auth_password_gate_t *g, const vireo_mysql_user_credentials_t *in,
    const void *password, size_t n, bool *out)
{
    scenario_t *s = c; assert(v==VERIFIER && g==GATE && password!=NULL && n>=8 && n<=64); step(s,'V');
    assert((in==NULL) == (s->lookup_rc==VIREO_RESULT_NOT_FOUND));
    if (in != NULL) { assert(in->user_id==41 && !memcmp(in->password_hash,phc,sizeof(phc))); }
    *out=s->matched && in!=NULL && !s->disabled; return s->verify_rc;
}
static vireo_result_t token(void *c, vireo_session_token_t *t, vireo_session_token_digest_t *d)
{
    scenario_t *s=c; step(s,'T'); memset(t,s->zero_token ? 0 : 0x69,sizeof(*t));
    memset(d,0x71,sizeof(*d)); return s->token_rc;
}
static vireo_result_t login(void *c, vireo_mysql_user_repository_t *r,
    const vireo_mysql_login_input_t *in, uint32_t timeout, vireo_mysql_login_report_t *out,
    vireo_mysql_user_repository_error_t *error)
{
    scenario_t *s=c; assert(r==REPO && timeout==17); step(s,'L');
    assert(in->user_id==41 && in->issued_at_ms==2000 && in->expires_at_ms==5000 && in->latency_us==37);
    assert(in->request_id[15]==10 && in->verified_password_hash_length==sizeof(phc)-1);
    assert(!memcmp(in->verified_password_hash,phc,sizeof(phc)));
    for (size_t i=0;i<sizeof(in->token_digest.bytes);++i) { assert(in->token_digest.bytes[i]==0x71); }
    out->commit=s->commit; out->cleanup_pending=s->pending;
    if (s->commit==VIREO_MYSQL_LOGIN_COMMITTED) { out->session_id=51; out->audit_id=52; }
    if (s->write_rc==VIREO_RESULT_NOT_FOUND) { out->issue=VIREO_MYSQL_LOGIN_PASSWORD_CHANGED; }
    error->cleanup_result=s->cleanup_rc; return s->write_rc;
}
static vireo_auth_service_runtime_t runtime(scenario_t *s)
{ return (vireo_auth_service_runtime_t){s,hash,registration,lookup,verify,token,login,cleared}; }
static vireo_auth_registration_request_t registration_request(void)
{
    vireo_auth_registration_request_t q={.username="Alice_7",.username_length=7,
        .password="Correct!7",.password_length=9,.occurred_at_ms=1000,.latency_us=31};
    q.request_id[15]=9; return q;
}
static vireo_auth_login_request_t login_request(void)
{
    vireo_auth_login_request_t q={.username="ALICE_7",.username_length=7,
        .password="Correct!7",.password_length=9,.issued_at_ms=2000,.expires_at_ms=5000,.latency_us=37};
    q.request_id[15]=10; return q;
}
static void run_login(scenario_t *s, vireo_result_t expected, const char *trace)
{
    vireo_auth_service_runtime_t rt=runtime(s); vireo_auth_login_request_t q=login_request();
    vireo_auth_login_result_t out; memset(&out,0xa5,sizeof(out));
    CHECK(vireo_auth_service_login_with_runtime(REPO,GATE,VERIFIER,&q,17,&out,NULL,&rt),expected);
    assert(!strcmp(s->trace,trace));
    if (strchr(trace,'L') != NULL) { assert(out.transaction.cleanup_pending==s->pending); }
    if (out.transaction.commit==VIREO_MYSQL_LOGIN_COMMITTED) {
        assert(out.user_id==41 && out.issued_at_ms==2000 && out.expires_at_ms==5000);
        for (size_t i=0;i<32;++i) { assert(out.token.bytes[i]==(s->zero_token ? 0 : 0x69)); }
    } else { assert(out.user_id==0 && out.issued_at_ms==0 && out.expires_at_ms==0 && zero(&out.token,sizeof(out.token))); }
    CHECK(vireo_auth_login_result_clear(&out),VIREO_OK); assert(zero(&out,sizeof(out)));
    CHECK(vireo_auth_login_result_clear(&out),VIREO_OK);
}

int main(void)
{
    vireo_auth_registration_request_t reg=registration_request();
    vireo_auth_login_request_t q=login_request();
    scenario_t s={0}; vireo_auth_service_runtime_t rt=runtime(&s);
    vireo_mysql_registration_report_t report; vireo_mysql_user_repository_error_t error;
    vireo_auth_login_result_t out;
    memset(&out,0xa5,sizeof(out)); vireo_auth_login_result_t old=out;
    CHECK(vireo_auth_service_login_with_runtime(NULL,GATE,VERIFIER,&q,17,&out,NULL,&rt),VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&out,&old,sizeof(out)) && !s.used);
    memset(&report,0xa5,sizeof(report)); vireo_mysql_registration_report_t old_report=report;
    CHECK(vireo_auth_service_register_with_runtime(REPO,NULL,&reg,17,&report,&error,&rt),VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&report,&old_report,sizeof(report)));
    vireo_auth_service_runtime_t bad=rt; bad.token=NULL;
    CHECK(vireo_auth_service_login_with_runtime(REPO,GATE,VERIFIER,&q,17,&out,NULL,&bad),VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&out,&old,sizeof(out)));
    CHECK(vireo_auth_login_result_clear(NULL),VIREO_RESULT_INVALID_ARGUMENT);
    /* 长度先于span访问；这里只提供短字节区，巨大长度不得解引用。 */
    const size_t lengths[]={0,2,33,SIZE_MAX};
    for (size_t i=0;i<sizeof(lengths)/sizeof(lengths[0]);++i) {
        reg.username_length=lengths[i]; q.username_length=lengths[i];
        CHECK(vireo_auth_service_register_with_runtime(REPO,GATE,&reg,17,&report,&error,&rt),VIREO_RESULT_RANGE);
        CHECK(vireo_auth_service_login_with_runtime(REPO,GATE,VERIFIER,&q,17,&out,&error,&rt),VIREO_RESULT_RANGE);
        assert(zero(&report,sizeof(report)) && zero(&out,sizeof(out)) && zero(&error,sizeof(error)) && !s.used);
    }
    reg=registration_request(); q=login_request();
    const size_t bad_password[]={0,7,65,SIZE_MAX};
    for (size_t i=0;i<sizeof(bad_password)/sizeof(bad_password[0]);++i) {
        reg.password_length=bad_password[i]; q.password_length=bad_password[i];
        CHECK(vireo_auth_service_register_with_runtime(REPO,GATE,&reg,17,&report,NULL,&rt),VIREO_RESULT_RANGE);
        CHECK(vireo_auth_service_login_with_runtime(REPO,GATE,VERIFIER,&q,17,&out,NULL,&rt),VIREO_RESULT_RANGE);
        assert(!s.used);
    }
    reg=registration_request(); q=login_request();
    char invalid[9]="Correct!7";
    const unsigned char bytes[]={0,32,127,128,0xe4,'\n','\t'};
    for (size_t i=0;i<sizeof(bytes);++i) {
        invalid[3]=(char)bytes[i]; reg.password=invalid; q.password=invalid;
        CHECK(vireo_auth_service_register_with_runtime(REPO,GATE,&reg,17,&report,NULL,&rt),VIREO_RESULT_PROTOCOL);
        CHECK(vireo_auth_service_login_with_runtime(REPO,GATE,VERIFIER,&q,17,&out,NULL,&rt),VIREO_RESULT_PROTOCOL);
        assert(!s.used && invalid[3]==(char)bytes[i]);
    }
    reg=registration_request(); q=login_request();
    reg.username="Ali ce7"; q.username="Ali ce7";
    CHECK(vireo_auth_service_register_with_runtime(REPO,GATE,&reg,17,&report,NULL,&rt),VIREO_RESULT_PROTOCOL);
    CHECK(vireo_auth_service_login_with_runtime(REPO,GATE,VERIFIER,&q,17,&out,NULL,&rt),VIREO_RESULT_PROTOCOL);
    reg=registration_request(); q=login_request();
    CHECK(vireo_auth_service_register_with_runtime(REPO,GATE,&reg,60001,&report,NULL,&rt),VIREO_RESULT_RANGE);
    CHECK(vireo_auth_service_login_with_runtime(REPO,GATE,VERIFIER,&q,60001,&out,NULL,&rt),VIREO_RESULT_RANGE);
    q.expires_at_ms=q.issued_at_ms;
    CHECK(vireo_auth_service_login_with_runtime(REPO,GATE,VERIFIER,&q,17,&out,NULL,&rt),VIREO_RESULT_RANGE);
    q=login_request(); reg.request_id[15]=0; q.request_id[15]=0;
    CHECK(vireo_auth_service_register_with_runtime(REPO,GATE,&reg,17,&report,NULL,&rt),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_service_login_with_runtime(REPO,GATE,VERIFIER,&q,17,&out,NULL,&rt),VIREO_RESULT_INVALID_ARGUMENT);
    assert(!s.used);
    const vireo_result_t failures[]={VIREO_RESULT_BUSY,VIREO_RESULT_CANCELLED,VIREO_RESULT_NO_MEMORY,
        VIREO_RESULT_IO,VIREO_RESULT_INTERNAL};
    for (size_t i=0;i<sizeof(failures)/sizeof(failures[0]);++i) {
        reg=registration_request(); s=(scenario_t){.hash_rc=failures[i]}; rt=runtime(&s);
        CHECK(vireo_auth_service_register_with_runtime(REPO,GATE,&reg,17,&report,NULL,&rt),failures[i]);
        assert(!strcmp(s.trace,"H") && zero(&report,sizeof(report)));
        s=(scenario_t){.verify_rc=failures[i]}; run_login(&s,failures[i],"QV");
        s=(scenario_t){.matched=true,.token_rc=failures[i]}; run_login(&s,failures[i],"QVT");
    }
    const vireo_result_t lookup_fail[]={VIREO_RESULT_DATABASE,VIREO_RESULT_PROTOCOL,VIREO_RESULT_RANGE,
        VIREO_RESULT_BUSY,VIREO_RESULT_TIMEOUT,VIREO_RESULT_CANCELLED,VIREO_RESULT_NO_MEMORY};
    for (size_t i=0;i<sizeof(lookup_fail)/sizeof(lookup_fail[0]);++i) {
        s=(scenario_t){.lookup_rc=lookup_fail[i],.lookup_pending=true}; run_login(&s,lookup_fail[i],"Q");
    }
    s=(scenario_t){.lookup_rc=VIREO_RESULT_NOT_FOUND}; run_login(&s,VIREO_RESULT_NOT_FOUND,"QV");
    s=(scenario_t){.lookup_rc=VIREO_RESULT_NOT_FOUND,.lookup_cleanup_rc=VIREO_RESULT_DATABASE};
    run_login(&s,VIREO_RESULT_DATABASE,"Q"); /* owner已消费也不能把清理错误当缺失。 */
    s=(scenario_t){.lookup_rc=VIREO_RESULT_NOT_FOUND,.lookup_pending=true,.lookup_cleanup_rc=VIREO_RESULT_INTERNAL};
    run_login(&s,VIREO_RESULT_INTERNAL,"Q");
    s=(scenario_t){.disabled=true,.matched=true}; run_login(&s,VIREO_RESULT_NOT_FOUND,"QV");
    s=(scenario_t){0}; run_login(&s,VIREO_RESULT_NOT_FOUND,"QV");
    /* 可发生的三态/清理组合，包括返回码非OK但已提交和合法全零token。 */
    const vireo_mysql_login_commit_t commits[]={VIREO_MYSQL_LOGIN_NOT_COMMITTED,VIREO_MYSQL_LOGIN_UNKNOWN,VIREO_MYSQL_LOGIN_COMMITTED};
    for (size_t i=0;i<3;++i) {
        s=(scenario_t){.matched=true,.commit=commits[i],.write_rc=VIREO_RESULT_DATABASE,.pending=true};
        /* pending只在写事务阶段注入；查询先保持完整成功。 */
        run_login(&s,VIREO_RESULT_DATABASE,"QVTL");
        reg=registration_request(); s=(scenario_t){.commit=commits[i],.write_rc=VIREO_RESULT_DATABASE,.pending=true}; rt=runtime(&s);
        CHECK(vireo_auth_service_register_with_runtime(REPO,GATE,&reg,17,&report,&error,&rt),VIREO_RESULT_DATABASE);
        assert(!strcmp(s.trace,"HR") && report.cleanup_pending);
        assert((report.user_id==41)==(report.commit==VIREO_MYSQL_REGISTRATION_COMMITTED));
    }
    s=(scenario_t){.matched=true,.commit=VIREO_MYSQL_LOGIN_COMMITTED,.zero_token=true}; run_login(&s,VIREO_OK,"QVTL");
    s=(scenario_t){.matched=true,.write_rc=VIREO_RESULT_NOT_FOUND,.cleanup_rc=VIREO_RESULT_DATABASE};
    /* 查询NOT_FOUND清理逻辑只在NOT_FOUND返回时升级；这里的清理失败来自写事务。 */
    run_login(&s,VIREO_RESULT_DATABASE,"QVTL");
    char password[64]; memset(password,'!',sizeof(password));
    for (size_t n=8;n<=64;n+=56) {
        reg=registration_request(); reg.password=password; reg.password_length=n;
        s=(scenario_t){.commit=VIREO_MYSQL_LOGIN_COMMITTED}; rt=runtime(&s);
        CHECK(vireo_auth_service_register_with_runtime(REPO,GATE,&reg,17,&report,NULL,&rt),VIREO_OK);
        assert(!strcmp(s.trace,"HR") && password[0]=='!' && password[63]=='!');
    }
    printf("PASS auth service: %zu contract checks, %zu live fully cleared workspaces; failure ordering and commit/token ownership\n",checks,wipes);
    return 0;
}
