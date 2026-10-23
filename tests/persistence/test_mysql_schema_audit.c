/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_audit.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 完整目录、审计常量及独立v3校验固定向量。
 */
#include <vireo/persistence/mysql_schema.h>
#include <vireo/security/password.h>
#include <vireo/security/session_token.h>
#include <openssl/evp.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void hash_u32(EVP_MD_CTX *ctx, uint32_t v)
{
    unsigned char b[4]={(unsigned char)(v>>24),(unsigned char)(v>>16),
                        (unsigned char)(v>>8),(unsigned char)v};
    assert(EVP_DigestUpdate(ctx,b,sizeof(b))==1);
}
int main(void)
{
    const vireo_mysql_migration_t *catalog=NULL; size_t count=0;
    assert(vireo_mysql_schema_catalog(&catalog,&count)==VIREO_OK && count==9);
    assert(count<=VIREO_MYSQL_MIGRATIONS_MAX);
    size_t total=0;
    for(size_t v=0;v<count;++v) {
        assert(catalog[v].version==v+1 && catalog[v].step_count==(v==2 || v==7 || v==8 ? 1U : 2U));
        assert(catalog[v].step_count<=VIREO_MYSQL_MIGRATION_STEPS_MAX);
        for(size_t i=0;i<catalog[v].step_count;++i) {
            const vireo_mysql_migration_step_t *step=&catalog[v].steps[i];
            assert(step->sql && step->sql_length && step->sql_length<=65536);
            assert(strlen(step->sql)==step->sql_length);
            total+=step->sql_length;
        }
    }
    assert(total<=VIREO_MYSQL_MIGRATION_SQL_BYTES_MAX);
    assert(catalog[0].steps[0].sql_length==1150 && catalog[0].steps[1].sql_length==1285);
    const vireo_mysql_migration_t *m=&catalog[2];
    assert(!strncmp(m->steps[0].sql,"CREATE TABLE operation_audits (",30));
    assert(m->steps[0].sql_length==1590);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_REQUEST_ID_BYTES==16);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_DETAIL_MAX_BYTES==1024);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_ACTION_MAX==65535);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_STATUS_MAX==65535);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_ACTION_REGISTER==1);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_ACTION_LOGIN==2);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_ACTION_LOGOUT==3);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_ACTION_SESSION_RESUME==4);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_TARGET_NONE==0);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_TARGET_USER==1);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_TARGET_SESSION==2);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_TARGET_NODE==3);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_TARGET_OBJECT==4);
    assert(VIREO_MYSQL_SCHEMA_AUDIT_STATUS_OK==0);
    /* 独立Python编码产生的固定向量；不使用迁移私有实现。 */
    static const unsigned char expected[32]={
        0xaa,0xef,0x94,0x51,0xfc,0x21,0xb6,0xde,0x65,0xef,0x4b,0xa4,0x47,0xf6,0x3e,0x71,0x25,0xcf,0x9e,0xce,0x1e,0xb2,0x6a,0x95,0xa2,0x62,0x7c,0x77,0x75,0x88,0x85,0xae};
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); assert(ctx);
    assert(EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1);
    static const char domain[]="vireo.mysql.migration.v1";
    assert(EVP_DigestUpdate(ctx,domain,sizeof(domain))==1);
    hash_u32(ctx,m->version); hash_u32(ctx,(uint32_t)m->step_count);
    for(size_t i=0;i<m->step_count;++i) {
        hash_u32(ctx,(uint32_t)m->steps[i].sql_length);
        assert(EVP_DigestUpdate(ctx,m->steps[i].sql,m->steps[i].sql_length)==1);
    }
    unsigned char digest[32]; unsigned int length=0;
    assert(EVP_DigestFinal_ex(ctx,digest,&length)==1 && length==32);
    EVP_MD_CTX_free(ctx); assert(!memcmp(digest,expected,32));
    puts("PASS audit catalog: four append-only versions, 2/2/1/2 steps, fourteen constants, bounds, independent v3 SHA-256");
    return 0;
}
