#include <vireo/protocol/chunk.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size);
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size)
{
    vireo_chunk_view_t v,old; memset(&old,0xa5,sizeof old); v=old;
    vireo_chunk_issue_t issue; errno=EDOM;
    vireo_result_t rc=vireo_chunk_body_decode(data,size,&v,&issue); assert(errno==EDOM);
    if(rc!=VIREO_OK) assert(!memcmp(&v,&old,sizeof v));
    else {
        (void)vireo_chunk_data_crc32c_verify(&v,&issue);
        assert(v.data>=data && v.data+v.header.data_len<=data+size);
    }
    return 0;
}
