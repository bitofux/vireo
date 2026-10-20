#include <vireo/protocol/auth_response.h>
#include <vireo/protocol/codec.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size);
static void check(uint8_t const *data,size_t size)
{
    vireo_auth_response_t v,old; memset(&old,0xa5,sizeof old); v=old;
    errno=EDOM; vireo_result_t rc=vireo_auth_response_decode(data,size,&v); assert(errno==EDOM);
    if(rc!=VIREO_OK) { assert(!memcmp(&v,&old,sizeof v)); return; }
    unsigned char wire[104]; size_t n; vireo_auth_response_t again={0};
    assert(vireo_auth_response_encode(&v,wire,sizeof wire,&n)==VIREO_OK);
    assert(vireo_auth_response_decode(wire,n,&again)==VIREO_OK);
    assert(again.command==v.command && again.user_id==v.user_id && again.status==v.status &&
        again.session_handle==v.session_handle && again.root_node_id==v.root_node_id &&
        again.issued_at_ms==v.issued_at_ms && again.expires_at_ms==v.expires_at_ms && !memcmp(again.token,v.token,32));
    assert(vireo_auth_response_clear(&again)==VIREO_OK); assert(vireo_auth_response_clear(&v)==VIREO_OK);
}
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size)
{
    check(data,size);
    if(size>=32 && size<=512) {
        unsigned char wire[512]; memcpy(wire,data,size);
        vireo_protocol_header_t h={.command=(vireo_command_t)(VIREO_COMMAND_REGISTER+(data[7]&3U)),
            .sequence=1,.flags=VIREO_PROTOCOL_FLAG_RESPONSE,.body_len=(uint32_t)(size-32)};
        if(h.command==VIREO_COMMAND_LOGIN || h.command==VIREO_COMMAND_SESSION_RESUME) h.session_handle=1;
        assert(vireo_protocol_header_encode(&h,wire,32)==VIREO_OK);
        assert(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,size-32,&h.crc32c)==VIREO_OK);
        assert(vireo_protocol_header_encode(&h,wire,32)==VIREO_OK); check(wire,size);
    }
    return 0;
}
