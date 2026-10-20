#include <vireo/base/config.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size);
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size)
{
    vireo_config_t base,out,old; vireo_config_error_t error;
    assert(vireo_config_defaults(&base)==VIREO_OK); memset(&old,0xa5,sizeof old); out=old;
    errno=EDOM; vireo_result_t rc=vireo_config_parse_text(&base,(char const *)data,size,&out,&error); assert(errno==EDOM);
    if(rc!=VIREO_OK) assert(!memcmp(&out,&old,sizeof out));
    else assert(vireo_config_validate(&out,&error)==VIREO_OK);
    return 0;
}
