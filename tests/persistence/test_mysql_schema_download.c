/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_download.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 完整目录、下载常量及独立v7校验固定向量。
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
    const vireo_mysql_migration_t *m=&catalog[6];
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_PUBLIC_ID_BYTES==16,"persistent download public_id_bytes");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_IDEMPOTENCY_KEY_BYTES==16,"persistent download idempotency_key_bytes");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_MANIFEST_VERSION==1,"persistent download manifest_version");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_COUNT_MAX==UINT64_C(4294967296),"persistent download part_count_max");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_MAX_BYTES==16777160,"persistent download part_max_bytes");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_LEASE_ID_BYTES==16,"persistent download lease_id_bytes");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_NEW==1,"persistent download new");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_READY==2,"persistent download ready");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_TRANSFERRING==3,"persistent download transferring");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_PAUSED==4,"persistent download paused");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_VERIFYING_CLIENT==5,"persistent download verifying_client");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_COMPLETED==6,"persistent download completed");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_FAILED==7,"persistent download failed");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_CANCELLED==8,"persistent download cancelled");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_EXPIRED==9,"persistent download expired");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_PENDING==1,"persistent download part_pending");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_READY==2,"persistent download part_ready");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_TRANSFERRING==3,"persistent download part_transferring");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_COMPLETED==4,"persistent download part_completed");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_FAILED==5,"persistent download part_failed");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_CANCELLED==6,"persistent download part_cancelled");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_SOURCE_UNASSIGNED==0,"persistent download source_unassigned");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_SOURCE_LOCAL==1,"persistent download source_local");
    _Static_assert(VIREO_MYSQL_SCHEMA_DOWNLOAD_SOURCE_REPLICA==2,"persistent download source_replica");
    assert(m->steps[0].sql_length==3045 && m->steps[1].sql_length==3235);
    assert(!strncmp(m->steps[0].sql,"CREATE TABLE download_tasks (",29));
    assert(!strncmp(m->steps[1].sql,"CREATE TABLE download_parts (",29));
    /* Python独立编码的固定v7向量，不调用生产hash函数。 */
    static const unsigned char expected[32]={
        0x8d,0x6a,0x75,0xb6,0x94,0xea,0xde,0xcb,0x3e,0xe8,0xb6,0x25,0x19,0x75,0x9c,0x33,0x09,0x3d,0x16,0x55,0xb3,0xf7,0x4a,0xc1,0x32,0x5b,0x2d,0xb5,0xc4,0xd1,0xc9,0x75};
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
    puts("PASS download catalog: eight versions, 2/2/1/2/2/2/2/1 steps, twenty-four constants, independent v7 SHA-256");
    return 0;
}
