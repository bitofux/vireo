#define _GNU_SOURCE
#include <vireo/net/connection.h>
#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size);
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size)
{
    int pair[2]; assert(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair)==0);
    size_t const capacity=1048608;
    vireo_connection_options_t const o={capacity,1,capacity+1}; vireo_connection_t *c=NULL;
    assert(vireo_connection_create(&o,&pair[0],&c,NULL)==VIREO_OK);
    size_t sent=0;
    while(sent<size) {
        size_t amount=size-sent; if(amount>16384) amount=16384;
        ssize_t n=send(pair[1],data+sent,amount,MSG_NOSIGNAL); assert(n>0); sent+=(size_t)n;
        vireo_connection_receive_budget_t const b={capacity,8}; vireo_connection_receive_info_t info;
        assert(vireo_connection_receive(c,&b,&info,NULL)==VIREO_OK);
    }
    assert(shutdown(pair[1],SHUT_WR)==0);
    vireo_connection_receive_budget_t const b={capacity,8}; vireo_connection_receive_info_t received;
    assert(vireo_connection_receive(c,&b,&received,NULL)==VIREO_OK);
    vireo_connection_frame_options_t const framing={VIREO_CONNECTION_FRAME_REQUEST,capacity};
    vireo_connection_frame_budget_t const budget={16,capacity*16};
    vireo_connection_frame_view_t views[16]; vireo_connection_frame_info_t info,again;
    vireo_connection_frame_error_t error; errno=EDOM;
    vireo_result_t rc=vireo_connection_frames_peek(c,&framing,&budget,views,16,&info,&error); assert(errno==EDOM);
    assert(rc==VIREO_OK || rc==VIREO_RESULT_PROTOCOL);
    assert(vireo_connection_frames_peek(c,&framing,&budget,views,16,&again,&error)==rc);
    assert(info.frame_count==again.frame_count && info.frame_bytes==again.frame_bytes && info.frame_bytes<=size);
    size_t total=0;
    for(size_t i=0;i<info.frame_count;++i) { assert(views[i].wire_size==32+views[i].body_size); total+=views[i].wire_size; }
    assert(total==info.frame_bytes);
    assert(vireo_connection_destroy(&c,NULL)==VIREO_OK); assert(close(pair[1])==0); return 0;
}
