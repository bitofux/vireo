/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_replica.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 完整目录、节点/副本常量及独立v6校验固定向量。
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
    assert(vireo_mysql_schema_catalog(&catalog,&count)==VIREO_OK && count==10);
    assert(count<=VIREO_MYSQL_MIGRATIONS_MAX);
    size_t total=0;
    for(size_t v=0;v<count;++v) {
        assert(catalog[v].version==v+1 && catalog[v].step_count==(v==2 || v==7 || v==8 || v==9 ? 1U : 2U));
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
    const vireo_mysql_migration_t *m=&catalog[5];
    _Static_assert(VIREO_MYSQL_SCHEMA_STORAGE_NODE_UUID_BYTES==16,"persistent node_uuid_bytes");
    _Static_assert(VIREO_MYSQL_SCHEMA_STORAGE_NODE_ENDPOINT_MAX_BYTES==512,"persistent node_endpoint_max_bytes");
    _Static_assert(VIREO_MYSQL_SCHEMA_STORAGE_NODE_ZONE_MAX_BYTES==64,"persistent node_zone_max_bytes");
    _Static_assert(VIREO_MYSQL_SCHEMA_STORAGE_NODE_ACTIVE==1,"persistent node_active");
    _Static_assert(VIREO_MYSQL_SCHEMA_STORAGE_NODE_DRAINING==2,"persistent node_draining");
    _Static_assert(VIREO_MYSQL_SCHEMA_STORAGE_NODE_OFFLINE==3,"persistent node_offline");
    _Static_assert(VIREO_MYSQL_SCHEMA_STORAGE_NODE_DISABLED==4,"persistent node_disabled");
    _Static_assert(VIREO_MYSQL_SCHEMA_REPLICA_PENDING==1,"persistent replica_pending");
    _Static_assert(VIREO_MYSQL_SCHEMA_REPLICA_VERIFIED==2,"persistent replica_verified");
    _Static_assert(VIREO_MYSQL_SCHEMA_REPLICA_DELETING==3,"persistent replica_deleting");
    _Static_assert(VIREO_MYSQL_SCHEMA_REPLICA_MISSING==4,"persistent replica_missing");
    _Static_assert(VIREO_MYSQL_SCHEMA_REPLICA_QUARANTINED==5,"persistent replica_quarantined");
    assert(m->steps[0].sql_length==1742 && m->steps[1].sql_length==1533);
    assert(!strncmp(m->steps[0].sql,"CREATE TABLE storage_nodes (",28));
    assert(!strncmp(m->steps[1].sql,"CREATE TABLE chunk_replicas (",29));
    /* Python独立编码产生v6固定向量，不调用迁移私有hash函数。 */
    static const unsigned char expected[32]={
        0xb8,0x6f,0x68,0x18,0xef,0xb6,0xc6,0x5b,0x26,0x4a,0xad,0x10,0xb0,0x9d,0x7f,0xf0,0xeb,0xa9,0xf3,0x95,0xfa,0x87,0xfd,0x70,0x93,0x9b,0x68,0x0a,0x4a,0x0a,0xa3,0xd5};
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
    puts("PASS replica catalog: ten versions, 2/2/1/2/2/2/2/1/1/1 steps, twelve constants, independent v6 SHA-256");
    return 0;
}
