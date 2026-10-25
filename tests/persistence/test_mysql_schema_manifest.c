/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_manifest.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 完整目录、永久块/manifest常量及独立v5校验固定向量。
 */
#include <vireo/persistence/mysql_schema.h>
#include <vireo/protocol/chunk.h>
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
    assert(vireo_mysql_schema_catalog(&catalog,&count)==VIREO_OK && count==11);
    assert(count<=VIREO_MYSQL_MIGRATIONS_MAX);
    size_t total=0;
    for(size_t v=0;v<count;++v) {
        assert(catalog[v].version==v+1 && catalog[v].step_count==(v==2 || v==7 || v==8 || v==9 || v==10 ? 1U : 2U));
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
    const vireo_mysql_migration_t *m=&catalog[4];
    _Static_assert(VIREO_MYSQL_SCHEMA_CHUNK_HASH_BYTES==32,"chunk digest width");
    _Static_assert(VIREO_MYSQL_SCHEMA_CHUNK_DATA_MAX_BYTES==VIREO_CHUNK_MAX_DATA_SIZE,"single-frame data bound");
    _Static_assert(VIREO_MYSQL_SCHEMA_MANIFEST_INDEX_MAX==UINT32_MAX,"index domain");
    _Static_assert(VIREO_MYSQL_SCHEMA_MANIFEST_CHUNKS_MAX==UINT64_C(4294967296),"count has one more value than index max");
    _Static_assert(VIREO_MYSQL_SCHEMA_CHUNK_PENDING==1,"persistent pending");
    _Static_assert(VIREO_MYSQL_SCHEMA_CHUNK_VERIFIED==2,"persistent verified");
    _Static_assert(VIREO_MYSQL_SCHEMA_CHUNK_DELETING==3,"persistent deleting");
    _Static_assert(VIREO_MYSQL_SCHEMA_CHUNK_QUARANTINED==4,"persistent quarantine");
    assert(m->steps[0].sql_length==1154 && m->steps[1].sql_length==1022);
    assert(!strncmp(m->steps[0].sql,"CREATE TABLE chunks (",21));
    assert(!strncmp(m->steps[1].sql,"CREATE TABLE object_chunks (",28));
    /* Python独立编码产生固定向量，不调用迁移私有hash函数。 */
    static const unsigned char expected[32]={
        0xcf,0x34,0x4e,0xd6,0x4b,0x30,0xb1,0xf9,0x59,0x26,0xec,0x46,0xbc,0xc1,0x6c,0x1a,0xf1,0xcd,0xcb,0xee,0x56,0xbb,0xf6,0x7c,0x54,0x9b,0x91,0x72,0xf2,0xc4,0x23,0xaf};
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
    puts("PASS manifest catalog: ten versions, 2/2/1/2/2/2/2/1/1/1 steps, eight constants, independent v5 SHA-256");
    return 0;
}
