/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_nodes.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : v2前缀目录、节点常量及独立v2校验固定向量。
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
    assert(vireo_mysql_schema_catalog(&catalog,&count)==VIREO_OK && count==11);
    assert(count<=VIREO_MYSQL_MIGRATIONS_MAX);
    size_t total=0;
    for(size_t v=0;v<2;++v) {
        assert(catalog[v].version==v+1 && catalog[v].step_count==2);
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
    const vireo_mysql_migration_t *m=&catalog[1];
    assert(!strncmp(m->steps[0].sql,"CREATE TABLE objects (",22));
    assert(!strncmp(m->steps[1].sql,"CREATE TABLE file_nodes (",25));
    assert(VIREO_MYSQL_SCHEMA_OBJECT_HASH_BYTES==32 && VIREO_MYSQL_SCHEMA_NAME_HASH_BYTES==32);
    assert(VIREO_MYSQL_SCHEMA_NODE_NAME_MAX_BYTES==255);
    assert(VIREO_MYSQL_SCHEMA_OBJECT_PENDING==1 && VIREO_MYSQL_SCHEMA_OBJECT_VERIFIED==2);
    assert(VIREO_MYSQL_SCHEMA_OBJECT_DELETING==3 && VIREO_MYSQL_SCHEMA_OBJECT_QUARANTINED==4);
    assert(VIREO_MYSQL_SCHEMA_OBJECT_STORAGE_LOCAL==1);
    assert(VIREO_MYSQL_SCHEMA_NODE_DIRECTORY==1 && VIREO_MYSQL_SCHEMA_NODE_FILE==2);
    assert(VIREO_MYSQL_SCHEMA_NODE_UPLOADING==1 && VIREO_MYSQL_SCHEMA_NODE_ACTIVE==2 && VIREO_MYSQL_SCHEMA_NODE_DELETED==3);
    /* 独立Python编码产生的固定向量；不使用迁移私有实现。 */
    static const unsigned char expected[32]={
        0xd8,0xfc,0x1a,0x1e,0x07,0x98,0x1a,0xf9,0xd4,0xc5,0xdb,0x32,0xc9,0xcb,0x71,0xd6,0x6c,0xfd,0x32,0x6b,0x13,0xe7,0xeb,0x77,0x1c,0xb2,0x17,0x23,0xd9,0x6e,0xd9,0x0c};
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
    puts("PASS nodes catalog: v2 prefix of append-only catalog, persistent constants, bounds, independent fixed v2 SHA-256");
    return 0;
}
