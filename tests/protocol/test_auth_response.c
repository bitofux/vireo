/* PROJECT: VIREO; FILE: test_auth_response.c; AUTHOR: bitofux; DATE: 2026-10-20. */
#include <vireo/protocol/auth_response.h>
#include <vireo/protocol/codec.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#define EXPECT(x,r) do { errno=EDOM; assert((x)==(r)); assert(errno==EDOM); } while(0)
static void crc(unsigned char wire[104])
{
    vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(wire,32,&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,h.body_len,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
}
int main(void)
{
    vireo_auth_response_t input={.command=VIREO_COMMAND_LOGIN,.sequence=7,.status=VIREO_STATUS_OK,
        .session_handle=0x10203040,.user_id=0x0102030405060708,.issued_at_ms=5,.expires_at_ms=9};
    for(size_t i=0;i<32;++i) input.token[i]=(unsigned char)i;
    unsigned char wire[104],golden[104]; size_t n=0;
    EXPECT(vireo_auth_response_encode(&input,wire,sizeof(wire),&n),VIREO_OK); assert(n==104);
    unsigned char const body[72]={0,1,0,8,1,2,3,4,5,6,7,8, 0,3,0,32,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
        0,4,0,8,0,0,0,0,0,0,0,5, 0,5,0,8,0,0,0,0,0,0,0,9};
    assert(!memcmp(wire+32,body,sizeof(body))); memcpy(golden,wire,sizeof(wire));
    vireo_auth_response_t output={0};
    EXPECT(vireo_auth_response_decode(wire,n,&output),VIREO_OK);
    assert(output.command==input.command && output.user_id==input.user_id && output.session_handle==input.session_handle &&
        output.issued_at_ms==5 && output.expires_at_ms==9 && !memcmp(output.token,input.token,32));
    /* 顺序可变，仍要求精确字段集合，不能只接受自己编码器的排序。 */
    memcpy(wire+32,body+60,12); memcpy(wire+44,body,60); crc(wire);
    EXPECT(vireo_auth_response_decode(wire,104,&output),VIREO_OK);
    vireo_auth_response_t old; memset(&old,0xa5,sizeof(old));
    for(unsigned i=0;i<13;++i) {
        memcpy(wire,golden,sizeof(wire)); size_t size=104; bool fix=true;
        switch(i) {
        case 0: size=31; fix=false; break; case 1: size=103; fix=false; break;
        case 2: wire[103]^=1; fix=false; break; case 3: wire[35]=7; break;
        case 4: wire[33]=5; break; case 5: wire[45]=0; break;
        case 6: memset(wire+36,0,8); break; case 7: wire[103]=5; break;
        case 8: memset(wire+20,0,4); break; case 9: wire[27]=1; break;
        case 10: wire[9]|=VIREO_PROTOCOL_FLAG_MORE; break;
        case 11: memset(wire+16,0,4); break; default: wire[10]=4; wire[11]=0x50; break;
        }
        if(fix) crc(wire);
        output=old; EXPECT(vireo_auth_response_decode(wire,size,&output),VIREO_RESULT_PROTOCOL);
        assert(!memcmp(&output,&old,sizeof(old)));
    }
    memcpy(wire,golden,sizeof(wire)); size_t untouched=77;
    EXPECT(vireo_auth_response_encode(&input,wire,103,&untouched),VIREO_RESULT_RANGE);
    assert(untouched==77 && !memcmp(wire,golden,sizeof(wire)));
    input.session_handle=0;
    EXPECT(vireo_auth_response_encode(&input,wire,sizeof(wire),&untouched),VIREO_RESULT_INVALID_ARGUMENT);
    assert(untouched==77 && !memcmp(wire,golden,sizeof(wire)));
    input=(vireo_auth_response_t){.command=VIREO_COMMAND_REGISTER,.status=VIREO_STATUS_OK,.sequence=8,.user_id=1,.root_node_id=2};
    EXPECT(vireo_auth_response_encode(&input,wire,sizeof(wire),&n),VIREO_OK); assert(n==56);
    EXPECT(vireo_auth_response_decode(wire,n,&output),VIREO_OK); assert(output.root_node_id==2 && output.session_handle==0);
    input=(vireo_auth_response_t){.command=VIREO_COMMAND_LOGIN,.status=VIREO_STATUS_AUTHENTICATION_FAILED,.sequence=9};
    EXPECT(vireo_auth_response_encode(&input,wire,sizeof(wire),&n),VIREO_OK); assert(n==32);
    EXPECT(vireo_auth_response_decode(wire,n,&output),VIREO_OK); assert(output.status==VIREO_STATUS_AUTHENTICATION_FAILED && output.user_id==0);
    input=(vireo_auth_response_t){.command=VIREO_COMMAND_LOGIN,.status=VIREO_STATUS_OK,.sequence=9,.session_handle=1,.user_id=1,.expires_at_ms=1};
    EXPECT(vireo_auth_response_encode(&input,wire,sizeof(wire),&n),VIREO_OK);
    EXPECT(vireo_auth_response_decode(wire,n,&output),VIREO_OK); assert(output.token[31]==0);
    input=(vireo_auth_response_t){.command=VIREO_COMMAND_SESSION_RESUME,.status=VIREO_STATUS_OK,.sequence=11,
        .user_id=7,.session_handle=8,.issued_at_ms=100,.expires_at_ms=200};
    EXPECT(vireo_auth_response_encode(&input,wire,sizeof wire,&n),VIREO_OK); assert(n==68);
    EXPECT(vireo_auth_response_decode(wire,n,&output),VIREO_OK);
    assert(output.token[0]==0 && output.token[31]==0 && output.session_handle==8 && output.issued_at_ms==100);
    input.token[0]=1; EXPECT(vireo_auth_response_encode(&input,wire,sizeof wire,&n),VIREO_RESULT_INVALID_ARGUMENT);
    input.token[0]=0;
    for(size_t k=0;k<68;++k) EXPECT(vireo_auth_response_decode(wire,k,&output),VIREO_RESULT_PROTOCOL);
    input=(vireo_auth_response_t){.command=VIREO_COMMAND_LOGOUT,.status=VIREO_STATUS_OK,.sequence=12};
    EXPECT(vireo_auth_response_encode(&input,wire,sizeof wire,&n),VIREO_OK); assert(n==32);
    EXPECT(vireo_auth_response_decode(wire,n,&output),VIREO_OK); assert(!output.session_handle && !output.user_id);
    input.session_handle=7; EXPECT(vireo_auth_response_encode(&input,wire,sizeof wire,&n),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_response_decode(NULL,0,&output),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_response_clear(NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_response_clear(&output),VIREO_OK);
    unsigned char const zero[sizeof(output)]={0}; assert(!memcmp(&output,zero,sizeof(output)));
    EXPECT(vireo_auth_response_clear(&input),VIREO_OK); EXPECT(vireo_auth_response_clear(&old),VIREO_OK);
    puts("PASS auth_response: canonical TLV bytes, reordered fields, REGISTER/LOGIN/error, 13 malformed frames, output atomicity, owned token/clear");
    return 0;
}
