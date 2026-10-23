/* NODE_LIST独立golden、嵌套关系、完整发布/errno、全状态/flags与最大页边界。 */
#include <vireo/protocol/node_list.h>
#include <vireo/protocol/codec.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); abort(); } } while (0)
typedef struct vector { char const *name; bool response; vireo_node_list_issue_t issue; size_t size; unsigned char const *wire; } vector_t;
#include "node_list_test_vectors.h"

/** @brief 只修CRC；输入必须至少32字节，不依赖被测LIST encoder。 */
static void repair(unsigned char *w, size_t n) {
    uint32_t c=0; CHECK(n>=32);
    CHECK(vireo_protocol_frame_crc32c_calculate(w,32,w+32,n-32,&c)==VIREO_OK);
    w[28]=(unsigned char)(c>>24); w[29]=(unsigned char)(c>>16);
    w[30]=(unsigned char)(c>>8); w[31]=(unsigned char)c;
}
static void put16(unsigned char *p, uint16_t n) { p[0]=(unsigned char)(n>>8); p[1]=(unsigned char)n; }
static vireo_node_list_response_t page(void) {
    vireo_node_list_response_t p={.sequence=1,.session_handle=9,.directory_id=42,.page_size=2,.count=2};
    for (size_t i=0;i<2;++i) {
        p.entries[i].node_id=100+(uint64_t)i*20; p.entries[i].parent_id=42;
        p.entries[i].name[0]='a'; p.entries[i].name_length=1;
        p.entries[i].type=VIREO_NODE_LIST_DIRECTORY; p.entries[i].updated_at_ms=1;
    }
    return p;
}
/** @brief 验证任一方向decoder失败时原值含padding保持，errno与issue可预测。 */
static void decode(unsigned char const *w, size_t n, bool response, vireo_node_list_issue_t expected) {
    vireo_node_list_issue_t issue=VIREO_NODE_LIST_ISSUE_VALUE;
    errno=EDOM;
    if (response) {
        vireo_node_list_response_t out,old;
        memset(&out,0xa5,sizeof out); memcpy(&old,&out,sizeof old);
        vireo_result_t rc=vireo_node_list_response_decode(w,n,&out,&issue);
        CHECK(errno==EDOM && issue==expected);
        CHECK(rc==(expected==VIREO_NODE_LIST_ISSUE_NONE ? VIREO_OK : VIREO_RESULT_PROTOCOL));
        if (rc!=VIREO_OK) CHECK(memcmp(&out,&old,sizeof out)==0);
        else {
            unsigned char a[23511],b[23511]; size_t x=999,y=998;
            memset(a,0x7a,sizeof a);
            CHECK(vireo_node_list_response_encode(&out,a,sizeof a,&x)==VIREO_OK);
            CHECK(a[x]==0x7a && errno==EDOM);
            CHECK(vireo_node_list_response_decode(a,x,&out,&issue)==VIREO_OK);
            CHECK(vireo_node_list_response_encode(&out,b,sizeof b,&y)==VIREO_OK);
            CHECK(x==y && memcmp(a,b,x)==0);
        }
    } else {
        vireo_node_list_request_t out,old;
        memset(&out,0xa5,sizeof out); memcpy(&old,&out,sizeof old);
        vireo_result_t rc=vireo_node_list_request_decode(w,n,&out,&issue);
        CHECK(errno==EDOM && issue==expected);
        CHECK(rc==(expected==VIREO_NODE_LIST_ISSUE_NONE ? VIREO_OK : VIREO_RESULT_PROTOCOL));
        if (rc!=VIREO_OK) CHECK(memcmp(&out,&old,sizeof out)==0);
        else {
            unsigned char a[151],b[151]; size_t x=999,y=998;
            memset(a,0x7a,sizeof a);
            CHECK(vireo_node_list_request_encode(&out,a,sizeof a,&x)==VIREO_OK);
            CHECK(a[x]==0x7a && errno==EDOM);
            CHECK(vireo_node_list_request_decode(a,x,&out,&issue)==VIREO_OK);
            CHECK(vireo_node_list_request_encode(&out,b,sizeof b,&y)==VIREO_OK);
            CHECK(x==y && memcmp(a,b,x)==0);
        }
    }
    CHECK(errno==EDOM);
}
static void goldens(void) {
    for (size_t i=0;i<sizeof vectors/sizeof vectors[0];++i) {
        vector_t const *v=&vectors[i]; decode(v->wire,v->size,v->response,v->issue);
        /* Canonical vectors compare encoder bytes to independent fixed wire, not just roundtrip. */
        if (v->issue==VIREO_NODE_LIST_ISSUE_NONE && strcmp(v->name,"inner-arbitrary-order")!=0 &&
            strcmp(v->name,"outer-interleaved")!=0) {
            unsigned char wire[23510]; size_t n=0; vireo_node_list_issue_t issue;
            if (v->response) {
                vireo_node_list_response_t p;
                CHECK(vireo_node_list_response_decode(v->wire,v->size,&p,&issue)==VIREO_OK);
                CHECK(vireo_node_list_response_encode(&p,wire,sizeof wire,&n)==VIREO_OK);
            } else {
                vireo_node_list_request_t p;
                CHECK(vireo_node_list_request_decode(v->wire,v->size,&p,&issue)==VIREO_OK);
                CHECK(vireo_node_list_request_encode(&p,wire,sizeof wire,&n)==VIREO_OK);
            }
            CHECK(n==v->size && memcmp(wire,v->wire,n)==0);
        }
    }
}
static void invalid_response(vireo_node_list_response_t const *p) {
    unsigned char w[23511],old[23511]; size_t n=999;
    memset(w,0x6b,sizeof w); memcpy(old,w,sizeof w); errno=EDOM;
    CHECK(vireo_node_list_response_encode(p,w,sizeof w,&n)==VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(n==999 && memcmp(w,old,sizeof w)==0 && errno==EDOM);
}
static void host_values(void) {
    vireo_node_list_response_t p=page();
#define BAD(change) do { p=page(); change; invalid_response(&p); } while (0)
    BAD(p.sequence=0); BAD(p.session_handle=0); BAD(p.directory_id=0); BAD(p.page_size=0);
    BAD(p.page_size=65); BAD(p.count=SIZE_MAX); BAD(p.count=3); BAD(p.has_more=true;p.count=1);
    BAD(p.next_page_token[0]=1); BAD(p.entries[1].node_id=100); BAD(p.entries[1].node_id=99);
    BAD(p.entries[0].node_id=42); BAD(p.entries[0].node_id=0); BAD(p.entries[0].parent_id=43);
    BAD(p.entries[0].name_length=0); BAD(p.entries[0].name_length=SIZE_MAX);
    BAD(p.entries[0].name[0]=0); BAD(p.entries[0].name[0]='/'); BAD(p.entries[0].name[0]='.');
    BAD(p.entries[0].name[0]='.';p.entries[0].name[1]='.';p.entries[0].name_length=2);
    BAD(p.entries[0].type=3); BAD(p.entries[0].size=1); BAD(p.entries[0].object_hash[31]=1);
    BAD(p.entries[0].has_object_hash=true); BAD(p.entries[0].type=VIREO_NODE_LIST_FILE);
    BAD(p.entries[0].created_at_ms=2);
#undef BAD
    p=page(); p.count=1; p.page_size=1;
    memset(&p.entries[1],0x7a,sizeof p.entries[1]); /* valid unused slot ignored */
    p.entries[0].name[0]=0xff; p.entries[0].name[254]=0x8a;
    p.entries[0].node_id=UINT64_MAX; p.directory_id=UINT64_MAX-1; p.entries[0].parent_id=p.directory_id;
    p.sequence=UINT32_MAX; p.session_handle=UINT32_MAX;
    unsigned char w[23511]; size_t n=0; vireo_node_list_response_t out; vireo_node_list_issue_t issue;
    CHECK(vireo_node_list_response_encode(&p,w,sizeof w,&n)==VIREO_OK);
    CHECK(vireo_node_list_response_decode(w,n,&out,&issue)==VIREO_OK);
    CHECK(out.entries[0].node_id==UINT64_MAX && out.entries[0].name[0]==0xff && out.entries[0].name[254]==0);
    unsigned char zeros[sizeof out.entries[1]]={0};
    /* Check members/arrays, rather than unspecified successful padding. */
    CHECK(out.entries[1].node_id==0 && out.entries[1].name_length==0 &&
        memcmp(out.entries[1].name,zeros,sizeof out.entries[1].name)==0);
    p=(vireo_node_list_response_t){.status=VIREO_STATUS_BAD_REQUEST,.sequence=1};
    for (size_t i=0;i<64;++i) { p.entries[i].name[254]=1; invalid_response(&p); p.entries[i].name[254]=0; }
    p.entries[63].updated_at_ms=1; invalid_response(&p);
    p=(vireo_node_list_response_t){.status=VIREO_STATUS_BAD_REQUEST,.sequence=1};
    p.entries[63].has_object_hash=true; invalid_response(&p);
}
static void capacities(void) {
    vireo_node_list_request_t q={.sequence=1,.directory_id=42,.page_size=64,.has_page_token=true};
    vireo_node_list_response_t p=page(); p.count=64;p.page_size=64;p.has_more=true;
    for (size_t i=0;i<64;++i) {
        p.entries[i]=(vireo_node_list_entry_t){.node_id=100+(uint64_t)i,.parent_id=42,
            .name_length=255,.type=VIREO_NODE_LIST_FILE,.size=UINT64_MAX,.has_object_hash=true};
        memset(p.entries[i].name,0xff,255);
    }
    unsigned char w[23511],old[23511]; size_t n=0;
    for (size_t cap=0;cap<=150;++cap) {
        memset(w,0x6b,sizeof w); memcpy(old,w,sizeof w);n=999;errno=EDOM;
        vireo_result_t rc=vireo_node_list_request_encode(&q,w,cap,&n);
        CHECK(errno==EDOM && rc==(cap<150 ? VIREO_RESULT_RANGE : VIREO_OK));
        if (rc!=VIREO_OK) CHECK(n==999 && memcmp(w,old,sizeof w)==0);
        else CHECK(n==150 && w[150]==0x6b);
    }
    size_t const caps[]={0,31,32,49,50,149,150,23509,23510,23511};
    for (size_t i=0;i<sizeof caps/sizeof caps[0];++i) {
        memset(w,0x6b,sizeof w);memcpy(old,w,sizeof w);n=999;errno=EDOM;
        vireo_result_t rc=vireo_node_list_response_encode(&p,w,caps[i],&n);
        CHECK(errno==EDOM && rc==(caps[i]<23510 ? VIREO_RESULT_RANGE : VIREO_OK));
        if (rc!=VIREO_OK) CHECK(n==999 && memcmp(w,old,sizeof w)==0);
        else CHECK(n==23510 && w[n]==0x6b);
    }
    CHECK(vireo_node_list_response_encode(&p,w,sizeof w,&n)==VIREO_OK);
    /* Every prefix is a complete-length rejection; out stays intact even for large pages. */
    for (size_t i=0;i<n;++i) decode(w,i,true,i<32 ? VIREO_NODE_LIST_ISSUE_HEADER : VIREO_NODE_LIST_ISSUE_ENVELOPE);
    decode(w,n+1,true,VIREO_NODE_LIST_ISSUE_ENVELOPE);
    decode(w,SIZE_MAX,true,VIREO_NODE_LIST_ISSUE_ENVELOPE); /* oversized before touching body */
    q.has_page_token=false;q.page_token[95]=1;n=999;
    CHECK(vireo_node_list_request_encode(&q,w,sizeof w,&n)==VIREO_RESULT_INVALID_ARGUMENT && n==999);
}
static void status_flags(void) {
    unsigned char w[23511];size_t n=0;vireo_node_list_issue_t issue;
    vireo_node_list_response_t p={.sequence=1};
    size_t accepted=0;
    for (uint32_t i=0;i<=UINT16_MAX;++i) {
        p.status=(uint16_t)i; errno=EDOM;
        vireo_result_t rc=vireo_node_list_response_encode(&p,w,sizeof w,&n);
        CHECK(errno==EDOM);
        if (rc==VIREO_OK) { ++accepted;decode(w,n,true,VIREO_NODE_LIST_ISSUE_NONE); }
        else CHECK(rc==VIREO_RESULT_INVALID_ARGUMENT);
    }
    CHECK(accepted==14); /* OK requires nonzero handle/context. */
    vireo_node_list_request_t q={.sequence=1,.directory_id=42,.page_size=2};
    CHECK(vireo_node_list_request_encode(&q,w,sizeof w,&n)==VIREO_OK);
    for (uint32_t i=0;i<=UINT16_MAX;++i) {
        put16(w+8,(uint16_t)i);repair(w,n);
        vireo_node_list_request_t out;
        vireo_result_t rc=vireo_node_list_request_decode(w,n,&out,&issue);
        CHECK((i==0)==(rc==VIREO_OK));CHECK(errno==EDOM);
    }
    p=page();CHECK(vireo_node_list_response_encode(&p,w,sizeof w,&n)==VIREO_OK);
    for (uint32_t i=0;i<=UINT16_MAX;++i) {
        put16(w+8,(uint16_t)i);repair(w,n);
        vireo_node_list_response_t out;
        vireo_result_t rc=vireo_node_list_response_decode(w,n,&out,&issue);
        CHECK((i==1)==(rc==VIREO_OK)); /* MORE33 needs NEXT token */
    }
}
static void nulls(void) {
    vireo_node_list_request_t q={.sequence=1,.directory_id=42,.page_size=2};
    vireo_node_list_response_t p=page();unsigned char w[23510];size_t n=999;
    vireo_node_list_issue_t issue=VIREO_NODE_LIST_ISSUE_VALUE;errno=EDOM;
    CHECK(vireo_node_list_request_encode(NULL,w,sizeof w,&n)==VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_node_list_request_encode(&q,NULL,0,&n)==VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_node_list_request_encode(&q,w,sizeof w,NULL)==VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_node_list_response_encode(NULL,w,sizeof w,&n)==VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_node_list_response_encode(&p,NULL,0,&n)==VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_node_list_response_encode(&p,w,sizeof w,NULL)==VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(n==999);
    CHECK(vireo_node_list_request_decode(NULL,0,&q,&issue)==VIREO_RESULT_INVALID_ARGUMENT && issue==0);
    CHECK(vireo_node_list_request_decode(w,0,NULL,&issue)==VIREO_RESULT_INVALID_ARGUMENT && issue==0);
    CHECK(vireo_node_list_request_decode(w,0,&q,NULL)==VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_node_list_response_decode(NULL,0,&p,&issue)==VIREO_RESULT_INVALID_ARGUMENT && issue==0);
    CHECK(vireo_node_list_response_decode(w,0,NULL,&issue)==VIREO_RESULT_INVALID_ARGUMENT && issue==0);
    CHECK(vireo_node_list_response_decode(w,0,&p,NULL)==VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno==EDOM);
}
int main(void) {
    goldens();host_values();capacities();status_flags();nulls();
    printf("NODE_LIST: %zu checks; %zu independent wire vectors\n",checks,sizeof vectors/sizeof vectors[0]);
    return 0;
}
