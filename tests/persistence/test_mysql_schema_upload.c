/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_upload.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 完整目录、上传常量及独立v4校验固定向量。
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
    const vireo_mysql_migration_t *m=&catalog[3];
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_PUBLIC_ID_BYTES==16);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_IDEMPOTENCY_KEY_BYTES==16);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_EXPECTED_HASH_BYTES==32);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_HASH_BYTES==32);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_DATA_MAX_BYTES==16777160);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_COUNT_MAX==UINT64_C(4294967296));
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_INDEX_MAX==UINT32_MAX);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_MODE_TRANSFER==1);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_MODE_FAST==2);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_NEW==1);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_RECEIVING==2);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_PAUSED==3);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_VERIFYING==4);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_COMMITTING==5);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_COMPLETED==6);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_FAILED==7);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_CANCELLED==8);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_EXPIRED==9);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_RECEIVED==1);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_INVALID==2);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_DATA_MAX_BYTES==VIREO_CHUNK_MAX_DATA_SIZE);
    assert(VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_HASH_BYTES==VIREO_CHUNK_BLAKE3_SIZE);
    assert(m->steps[0].sql_length==3438 && m->steps[1].sql_length==1127);
    assert(catalog[1].steps[0].sql_length==1130 && catalog[1].steps[1].sql_length==2601);
    assert(catalog[2].steps[0].sql_length==1590);
    /* 独立Python编码产生的固定向量；不使用迁移私有实现。 */
    static const unsigned char expected[32]={
        0x66,0x68,0x7b,0x2c,0xee,0x61,0xbc,0x9b,0xc5,0x06,0xd8,0x9b,0x60,0x55,0xf0,0xa0,0x31,0xd6,0x6c,0x86,0x34,0xda,0xf5,0xd4,0x32,0xff,0x92,0x3e,0x2c,0x51,0x02,0x76};
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
    puts("PASS upload catalog: eight versions, 2/2/1/2/2/2/2/1 steps, twenty constants, wire bounds, independent v4 SHA-256");
    return 0;
}
