/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_directory_receipts.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : v1至v9独立迁移hash与回执结构。
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
    assert(vireo_mysql_schema_catalog(&catalog,&count)==VIREO_OK && count==11);
    static const char *const golden[]={
        "58c6116c0920294129f40afe777c4e3f616b4532393ef09b7fddbc4822f688be",
        "d8fc1a1e07981af9d4c5db32c9cb71d66cfd326b13e7eb771cb21723d96ed90c",
        "aaef9451fc21b6de65ef4ba447f63e7125cf9ece1eb26a95a2627c77758885ae",
        "66687b2cee61bc9bc506d89b6055f0a031d66c8634daf5d432ff923e2c510276",
        "cf344ed64b30b1f95926ec46bcc16c1af1cdcbee56bbf67c549b9172f2c423af",
        "b86f6818efb6c65b264aad10b09d7ff0eba9f395fa87fd70939b680a4a0aa3d5",
        "8d6a75b694eadecb3ee8b62519759c33093d1655b3f74ac1325b2db5c4d1c975",
        "4938132ddbfa2fd61bfe5d14a5262ceaef8489af8e7392307ec502870c9bb446",
        "a82a5954cfae90f9b49498d8001182449c2f9419880e39fbd2496924dd8d41d7",
    };
    size_t steps=0;
    for(size_t j=0;j<9;++j) {
        const vireo_mysql_migration_t *m=catalog+j; assert(m->version==j+1);steps+=m->step_count;
        EVP_MD_CTX *ctx=EVP_MD_CTX_new();assert(ctx);
        assert(EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1);
        static const char domain[]="vireo.mysql.migration.v1";
        assert(EVP_DigestUpdate(ctx,domain,sizeof(domain))==1);
        hash_u32(ctx,m->version);hash_u32(ctx,(uint32_t)m->step_count);
        for(size_t i=0;i<m->step_count;++i) {
            hash_u32(ctx,(uint32_t)m->steps[i].sql_length);
            assert(EVP_DigestUpdate(ctx,m->steps[i].sql,m->steps[i].sql_length)==1);
        }
        unsigned char digest[32];unsigned int n=0;char hex[65];
        assert(EVP_DigestFinal_ex(ctx,digest,&n)==1 && n==32);EVP_MD_CTX_free(ctx);
        for(size_t i=0;i<32;++i) { assert(snprintf(hex+2*i,3,"%02x",digest[i])==2); }
        assert(!strcmp(hex,golden[j]));
    }
    assert(steps==15 && catalog[8].step_count==1 && catalog[8].steps[0].sql_length==1364);
    const char *sql=catalog[8].steps[0].sql;
    assert(strstr(sql,"PRIMARY KEY (user_id,command,idempotency_key)") && !strstr(sql,"FOREIGN KEY") && !strstr(sql,"AUTO_INCREMENT"));
    size_t checks=0;for(const char *p=sql;(p=strstr(p," ENFORCED"))!=NULL;p+=9) { ++checks; }assert(checks==8);
    puts("PASS nine independent migration hashes; unchanged v1-v8, v9 1364 bytes, 9 versions/15 steps, eight enforced receipt checks");
    return 0;
}
