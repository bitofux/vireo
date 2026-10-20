#include <vireo/protocol/tlv.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size);
int LLVMFuzzerTestOneInput(uint8_t const *data,size_t size)
{
    vireo_tlv_reader_t r; vireo_tlv_issue_t issue;
    assert(vireo_tlv_reader_init(&r,data,size)==VIREO_OK);
    while(r.offset<r.size) {
        size_t old=r.offset; vireo_tlv_view_t v; errno=EDOM;
        vireo_result_t rc=vireo_tlv_reader_next(&r,&v,&issue); assert(errno==EDOM);
        if(rc!=VIREO_OK) { assert(r.offset==old); break; }
        assert(r.offset>old && r.offset<=size && v.value>=data && v.value+v.length<=data+size);
        uint64_t number; (void)vireo_tlv_view_read_u64(&v,&number);
    }
    vireo_tlv_rule_t const rule={.type=1,.min_length=8,.max_length=8,.value_kind=VIREO_TLV_VALUE_U64,.required=true};
    uint8_t seen[1]; (void)vireo_tlv_schema_validate(data,size,&rule,1,VIREO_TLV_UNKNOWN_REJECT,seen,sizeof seen,&issue);
    return 0;
}
