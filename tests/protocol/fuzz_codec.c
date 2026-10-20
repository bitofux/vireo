#include <vireo/protocol/codec.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size);
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size)
{
    vireo_protocol_header_t h,old; memset(&old,0xa5,sizeof old); h=old;
    vireo_protocol_codec_issue_t issue; errno=EDOM;
    vireo_result_t rc=vireo_protocol_header_decode(data,size,&h,&issue); assert(errno==EDOM);
    if(rc!=VIREO_OK) assert(!memcmp(&h,&old,sizeof h));
    else {
        unsigned char wire[32]; assert(vireo_protocol_header_encode(&h,wire,sizeof wire)==VIREO_OK);
        assert(!memcmp(wire,data,32));
        (void)vireo_protocol_request_header_validate(&h,&issue);
        (void)vireo_protocol_response_header_validate(&h,&issue);
        (void)vireo_protocol_frame_crc32c_verify(data,32,data+32,size-32,&issue);
    }
    return 0;
}
