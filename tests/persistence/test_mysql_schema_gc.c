/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_gc.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 完整目录、GC常量及独立v8校验固定向量。
 */
#include <vireo/persistence/mysql_schema.h>
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
    assert(vireo_mysql_schema_catalog(&catalog,&count)==VIREO_OK && count==8);
    assert(count<=VIREO_MYSQL_MIGRATIONS_MAX);
    size_t total=0;
    for(size_t v=0;v<count;++v) {
        assert(catalog[v].version==v+1 && catalog[v].step_count==(v==2 || v==7 ? 1U : 2U));
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
    const vireo_mysql_migration_t *m=&catalog[7];
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_OBJECT==1,"persistent GC_OBJECT");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_CHUNK==2,"persistent GC_CHUNK");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_UPLOAD_STAGING==3,"persistent GC_UPLOAD_STAGING");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_DELETE==1,"persistent GC_DELETE");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_READY==1,"persistent GC_READY");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_RUNNING==2,"persistent GC_RUNNING");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_SUCCEEDED==3,"persistent GC_SUCCEEDED");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_CANCELLED==4,"persistent GC_CANCELLED");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_FAILED==5,"persistent GC_FAILED");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_ATTEMPTS_MAX==1000000,"persistent GC_ATTEMPTS_MAX");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_CLAIM_ID_BYTES==16,"persistent GC_CLAIM_ID_BYTES");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_ERROR_NONE==0,"persistent GC_ERROR_NONE");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_ERROR_REFERENCED==1,"persistent GC_ERROR_REFERENCED");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_ERROR_IO==2,"persistent GC_ERROR_IO");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_ERROR_LEASE_LOST==3,"persistent GC_ERROR_LEASE_LOST");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_ERROR_CORRUPT==4,"persistent GC_ERROR_CORRUPT");
    _Static_assert(VIREO_MYSQL_SCHEMA_GC_ERROR_INTERNAL==5,"persistent GC_ERROR_INTERNAL");
    assert(m->step_count==1 && m->steps[0].sql_length==2736);
    assert(!strncmp(m->steps[0].sql,"CREATE TABLE gc_jobs (",sizeof("CREATE TABLE gc_jobs (")-1));
    /* Python独立编码v8固定向量。 */
    static const unsigned char expected[32]={0x49,0x38,0x13,0x2d,0xdb,0xfa,0x2f,0xd6,0x1b,0xfe,0x5d,0x14,0xa5,0x26,0x2c,0xea,0xef,0x84,0x89,0xaf,0x8e,0x73,0x92,0x30,0x7e,0xc5,0x02,0x87,0x0c,0x9b,0xb4,0x46};
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
    puts("PASS GC catalog eight versions/14 steps, 17 constants, independent v8 SHA-256");
    return 0;
}
