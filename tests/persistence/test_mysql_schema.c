/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 静态目录借用、失败输出、格式容量及独立hash固定向量。
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
    const vireo_mysql_migration_t sentinel={0,NULL,0};
    const vireo_mysql_migration_t *m=&sentinel; size_t count=99;
    errno=EDOM;
    assert(vireo_mysql_schema_catalog(NULL,NULL)==VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_mysql_schema_catalog(NULL,&count)==VIREO_RESULT_INVALID_ARGUMENT && count==99);
    assert(vireo_mysql_schema_catalog(&m,NULL)==VIREO_RESULT_INVALID_ARGUMENT && m==&sentinel);
    assert(errno==EDOM);
    assert(vireo_mysql_schema_catalog(&m,&count)==VIREO_OK && errno==EDOM);
    assert(count==8 && m->version==1 && m->step_count==2 && m->steps);
    const vireo_mysql_migration_t *again=NULL; size_t second=0;
    assert(vireo_mysql_schema_catalog(&again,&second)==VIREO_OK && again==m && second==count && errno==EDOM);
    assert(count<=VIREO_MYSQL_MIGRATIONS_MAX && m->step_count<=VIREO_MYSQL_MIGRATION_STEPS_MAX);
    size_t total=0;
    for(size_t i=0;i<m->step_count;++i) {
        assert(m->steps[i].sql && m->steps[i].sql_length>0 && m->steps[i].sql_length<=65536);
        assert(strlen(m->steps[i].sql)==m->steps[i].sql_length);
        total+=m->steps[i].sql_length;
    }
    assert(total<=VIREO_MYSQL_MIGRATION_SQL_BYTES_MAX);
    assert(!strncmp(m->steps[0].sql,"CREATE TABLE users (",20));
    assert(!strncmp(m->steps[1].sql,"CREATE TABLE sessions (",23));
    assert(VIREO_MYSQL_SCHEMA_MIN_SERVER_VERSION==UINT32_C(80016));
    assert(VIREO_MYSQL_SCHEMA_USERNAME_MAX_CHARACTERS==64);
    assert(VIREO_MYSQL_SCHEMA_USERNAME_KEY_MAX_BYTES==256);
    assert(VIREO_MYSQL_SCHEMA_PASSWORD_HASH_MAX_BYTES+1==VIREO_PASSWORD_ENCODED_CAPACITY);
    assert(VIREO_MYSQL_SCHEMA_TOKEN_DIGEST_BYTES==sizeof(((vireo_session_token_digest_t *)0)->bytes));
    assert(VIREO_MYSQL_SCHEMA_USER_ACTIVE==1 && VIREO_MYSQL_SCHEMA_USER_DISABLED==2);
    assert(VIREO_MYSQL_SCHEMA_SESSION_ACTIVE==1 && VIREO_MYSQL_SCHEMA_SESSION_REVOKED==2);
    /* 独立Python编码产生的固定向量；不使用迁移私有实现。 */
    static const unsigned char expected[32]={
        0x58,0xc6,0x11,0x6c,0x09,0x20,0x29,0x41,0x29,0xf4,0x0a,0xfe,0x77,0x7c,0x4e,0x3f,
        0x61,0x6b,0x45,0x32,0x39,0x3e,0xf0,0x9b,0x7f,0xdd,0xbc,0x48,0x22,0xf6,0x88,0xbe};
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
    puts("PASS schema catalog: failure preserves outputs/errno, static lifetime, bounds, credential capacities, fixed SHA-256");
    return 0;
}
