/* NODE_LIST纯codec；无外部资源，嵌套只一层，失败不发布半页。 */
#include <vireo/protocol/node_list.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include <errno.h>
#include <string.h>

static vireo_tlv_rule_t const request_rules[] = {
    {0x0410,8,8,VIREO_TLV_VALUE_U64,true,false},
    {0x0411,2,2,VIREO_TLV_VALUE_U16,true,false},
    {0x0412,96,96,VIREO_TLV_VALUE_BYTES,false,false}
};
static vireo_tlv_rule_t const response_rules[] = {
    {0x0410,8,8,VIREO_TLV_VALUE_U64,true,false},
    {0x0411,2,2,VIREO_TLV_VALUE_U16,true,false},
    {0x0413,0,361,VIREO_TLV_VALUE_BYTES,false,true},
    {0x0414,96,96,VIREO_TLV_VALUE_BYTES,false,false}
};
static vireo_tlv_rule_t const entry_rules[] = {
    {0x0401,8,8,VIREO_TLV_VALUE_U64,true,false},
    {0x0402,8,8,VIREO_TLV_VALUE_U64,true,false},
    {0x0403,1,255,VIREO_TLV_VALUE_BYTES,true,false},
    {0x0404,2,2,VIREO_TLV_VALUE_U16,true,false},
    {0x0405,8,8,VIREO_TLV_VALUE_U64,true,false},
    {0x0406,8,8,VIREO_TLV_VALUE_U64,true,false},
    {0x0407,8,8,VIREO_TLV_VALUE_U64,true,false},
    {0x0408,32,32,VIREO_TLV_VALUE_BYTES,false,false}
};

/** @brief 检查有效字节区，不读取结构体padding。 */
static bool zero_bytes(unsigned char const *p, size_t n) {
    for (size_t i=0; i<n; ++i) if (p[i]!=0) return false;
    return true;
}
/** @brief 本命令允许的业务状态；禁止内部rc强转。 */
static bool status_allowed(vireo_status_t status) {
    switch (status) {
    case VIREO_STATUS_OK: case VIREO_STATUS_BAD_REQUEST: case VIREO_STATUS_UNSUPPORTED:
    case VIREO_STATUS_CRC_MISMATCH: case VIREO_STATUS_BODY_TOO_LARGE:
    case VIREO_STATUS_INVALID_FLAGS: case VIREO_STATUS_DUPLICATE_REQUEST:
    case VIREO_STATUS_RATE_LIMITED: case VIREO_STATUS_UNAUTHORIZED: case VIREO_STATUS_NOT_FOUND:
    case VIREO_STATUS_BUSY: case VIREO_STATUS_INTERNAL_ERROR: case VIREO_STATUS_TIMEOUT:
    case VIREO_STATUS_OVERLOADED: case VIREO_STATUS_UNAVAILABLE: return true;
    default: return false;
    }
}
/** @brief 借用entry，检查错误响应成员全零，无padding要求。 */
static bool entry_zero(vireo_node_list_entry_t const *e) {
    return e->node_id==0 && e->parent_id==0 && e->name_length==0 &&
        zero_bytes(e->name,sizeof e->name) && e->type==0 && e->size==0 &&
        e->created_at_ms==0 && e->updated_at_ms==0 && !e->has_object_hash &&
        zero_bytes(e->object_hash,sizeof e->object_hash);
}
/** @brief 借用有效entry，检查直接孩子名字与类型；父/有序关系由page检查。 */
static bool entry_valid(vireo_node_list_entry_t const *e) {
    if (e->node_id==0 || e->name_length==0 || e->name_length>sizeof e->name ||
        e->updated_at_ms<e->created_at_ms) return false;
    for (size_t i=0; i<e->name_length; ++i)
        if (e->name[i]==0 || e->name[i]=='/') return false;
    if ((e->name_length==1 && e->name[0]=='.') ||
        (e->name_length==2 && e->name[0]=='.' && e->name[1]=='.')) return false;
    if (e->type==VIREO_NODE_LIST_DIRECTORY)
        return e->size==0 && !e->has_object_hash && zero_bytes(e->object_hash,32);
    return e->type==VIREO_NODE_LIST_FILE && e->has_object_hash;
}
/** @brief 请求成员关联，不解释token的版本/MAC/权限。 */
static bool request_valid(vireo_node_list_request_t const *v) {
    return v->sequence!=0 && v->directory_id!=0 && v->page_size>=1 && v->page_size<=64 &&
        (v->has_page_token || zero_bytes(v->page_token,sizeof v->page_token));
}
/** @brief 整页宿主值关联；先限制count再按前缀访问，错误逐成员检查。 */
static bool response_valid(vireo_node_list_response_t const *v) {
    if (v->sequence==0 || !status_allowed(v->status)) return false;
    if (v->status!=VIREO_STATUS_OK) {
        if (v->session_handle!=0 || v->directory_id!=0 || v->page_size!=0 ||
            v->count!=0 || v->has_more || !zero_bytes(v->next_page_token,96)) return false;
        for (size_t i=0;i<64;++i) if (!entry_zero(&v->entries[i])) return false;
        return true;
    }
    if (v->session_handle==0 || v->directory_id==0 || v->page_size<1 || v->page_size>64 ||
        v->count>v->page_size || (v->has_more ? v->count!=v->page_size :
        !zero_bytes(v->next_page_token,96))) return false;
    uint64_t last=0;
    for (size_t i=0;i<v->count;++i) {
        vireo_node_list_entry_t const *e=&v->entries[i];
        if (!entry_valid(e) || e->parent_id!=v->directory_id || e->node_id==v->directory_id ||
            e->node_id<=last) return false;
        last=e->node_id;
    }
    return true;
}
static vireo_result_t finish(vireo_result_t rc, int saved) { errno=saved; return rc; }
static vireo_result_t reject(vireo_node_list_issue_t *issue, vireo_node_list_issue_t kind) {
    *issue=kind; return VIREO_RESULT_PROTOCOL;
}
/** @brief 完成局部帧CRC后一次发布，调用者已检查真实capacity。 */
static vireo_result_t publish(vireo_protocol_header_t *h, unsigned char *frame, size_t size,
    unsigned char *wire, size_t *out_size) {
    vireo_result_t rc=vireo_protocol_header_encode(h,frame,32);
    if (rc==VIREO_OK) rc=vireo_protocol_frame_crc32c_calculate(frame,32,frame+32,size-32,&h->crc32c);
    if (rc==VIREO_OK) rc=vireo_protocol_header_encode(h,frame,32);
    if (rc==VIREO_OK) { memcpy(wire,frame,size); *out_size=size; }
    return rc;
}
/** @brief 方向限长先于扫描；再公共header、命令envelope、CRC；无业务out发布。 */
static vireo_result_t envelope(unsigned char const *wire, size_t size, bool response,
    vireo_protocol_header_t *h, vireo_node_list_issue_t *issue) {
    if (size<32) return reject(issue,VIREO_NODE_LIST_ISSUE_HEADER);
    if (size>(response ? VIREO_NODE_LIST_RESPONSE_FRAME_MAX : VIREO_NODE_LIST_REQUEST_FRAME_MAX))
        return reject(issue,VIREO_NODE_LIST_ISSUE_ENVELOPE);
    vireo_protocol_codec_issue_t ci;
    if (vireo_protocol_header_decode(wire,size,h,&ci)!=VIREO_OK ||
        (response ? vireo_protocol_response_header_validate(h,&ci) :
            vireo_protocol_request_header_validate(h,&ci))!=VIREO_OK)
        return reject(issue,VIREO_NODE_LIST_ISSUE_HEADER);
    if (h->command!=VIREO_COMMAND_NODE_LIST || h->task_handle!=0 ||
        (response ? ((h->flags!=VIREO_PROTOCOL_FLAG_RESPONSE &&
            h->flags!=(VIREO_PROTOCOL_FLAG_RESPONSE|VIREO_PROTOCOL_FLAG_MORE)) ||
            !status_allowed(h->status) || (h->status==VIREO_STATUS_OK ? h->session_handle==0 :
                (h->session_handle!=0 || h->body_len!=0 || h->flags!=VIREO_PROTOCOL_FLAG_RESPONSE))) :
            h->flags!=0) || size!=(size_t)32+h->body_len)
        return reject(issue,VIREO_NODE_LIST_ISSUE_ENVELOPE);
    if (vireo_protocol_frame_crc32c_verify(wire,32,wire+32,h->body_len,&ci)!=VIREO_OK)
        return reject(issue,VIREO_NODE_LIST_ISSUE_CRC);
    return VIREO_OK;
}
/** @brief 在独立seen空间校验局部schema，无借用逸出。 */
static bool schema(unsigned char const *p, size_t n, vireo_tlv_rule_t const *rules, size_t count) {
    unsigned char seen[8]; vireo_tlv_issue_t ti;
    return vireo_tlv_schema_validate(p,n,rules,count,VIREO_TLV_UNKNOWN_REJECT,
        seen,sizeof seen,&ti)==VIREO_OK;
}

vireo_result_t vireo_node_list_request_encode(vireo_node_list_request_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size) {
    int const saved=errno;
    if (value==NULL || wire==NULL || out_size==NULL || !request_valid(value))
        return finish(VIREO_RESULT_INVALID_ARGUMENT,saved);
    size_t const body=value->has_page_token ? 118U : 18U;
    if (capacity<32+body) return finish(VIREO_RESULT_RANGE,saved);
    unsigned char frame[VIREO_NODE_LIST_REQUEST_FRAME_MAX]; vireo_tlv_writer_t w;
    vireo_result_t rc=vireo_tlv_writer_init(&w,frame+32,body);
    if (rc==VIREO_OK) rc=vireo_tlv_writer_put_u64(&w,VIREO_NODE_LIST_TLV_DIRECTORY_ID,value->directory_id);
    if (rc==VIREO_OK) rc=vireo_tlv_writer_put_u16(&w,VIREO_NODE_LIST_TLV_PAGE_SIZE,value->page_size);
    if (rc==VIREO_OK && value->has_page_token)
        rc=vireo_tlv_writer_put(&w,VIREO_NODE_LIST_TLV_PAGE_TOKEN,value->page_token,96);
    vireo_protocol_header_t h={.command=VIREO_COMMAND_NODE_LIST,.body_len=(uint32_t)body,
        .sequence=value->sequence,.session_handle=value->session_handle};
    if (rc==VIREO_OK) rc=publish(&h,frame,32+body,wire,out_size);
    return finish(rc,saved);
}

vireo_result_t vireo_node_list_request_decode(unsigned char const *wire, size_t wire_size,
    vireo_node_list_request_t *out, vireo_node_list_issue_t *issue) {
    int const saved=errno;
    if (issue!=NULL) *issue=VIREO_NODE_LIST_ISSUE_NONE;
    if (wire==NULL || out==NULL || issue==NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT,saved);
    vireo_protocol_header_t h;
    vireo_result_t rc=envelope(wire,wire_size,false,&h,issue);
    if (rc!=VIREO_OK) return finish(rc,saved);
    if (!schema(wire+32,h.body_len,request_rules,3))
        return finish(reject(issue,VIREO_NODE_LIST_ISSUE_FIELDS),saved);
    vireo_node_list_request_t next={.sequence=h.sequence,.session_handle=h.session_handle};
    vireo_tlv_reader_t r; vireo_tlv_view_t f; vireo_tlv_issue_t ti;
    rc=vireo_tlv_reader_init(&r,wire+32,h.body_len);
    while (rc==VIREO_OK && r.offset<r.size) {
        rc=vireo_tlv_reader_next(&r,&f,&ti);
        if (rc!=VIREO_OK) break;
        switch (f.type) {
        case VIREO_NODE_LIST_TLV_DIRECTORY_ID: rc=vireo_tlv_view_read_u64(&f,&next.directory_id); break;
        case VIREO_NODE_LIST_TLV_PAGE_SIZE: rc=vireo_tlv_view_read_u16(&f,&next.page_size); break;
        case VIREO_NODE_LIST_TLV_PAGE_TOKEN: next.has_page_token=true; memcpy(next.page_token,f.value,96); break;
        default: rc=VIREO_RESULT_PROTOCOL; break;
        }
    }
    if (rc!=VIREO_OK) return finish(reject(issue,VIREO_NODE_LIST_ISSUE_FIELDS),saved);
    if (!request_valid(&next)) return finish(reject(issue,VIREO_NODE_LIST_ISSUE_VALUE),saved);
    *out=next; return finish(VIREO_OK,saved);
}

/** @brief 单项完整有界编码到调用者局部暂存，不发布公共wire。 */
static vireo_result_t write_entry(vireo_node_list_entry_t const *e, unsigned char *buf, size_t *size) {
    vireo_tlv_writer_t w;
    vireo_result_t rc=vireo_tlv_writer_init(&w,buf,VIREO_NODE_LIST_ENTRY_BODY_MAX);
#define PUT(call) do { if (rc==VIREO_OK) rc=(call); } while (0)
    PUT(vireo_tlv_writer_put_u64(&w,VIREO_NODE_LIST_TLV_NODE_ID,e->node_id));
    PUT(vireo_tlv_writer_put_u64(&w,VIREO_NODE_LIST_TLV_PARENT_ID,e->parent_id));
    PUT(vireo_tlv_writer_put(&w,VIREO_NODE_LIST_TLV_NAME_BYTES,e->name,e->name_length));
    PUT(vireo_tlv_writer_put_u16(&w,VIREO_NODE_LIST_TLV_NODE_TYPE,e->type));
    PUT(vireo_tlv_writer_put_u64(&w,VIREO_NODE_LIST_TLV_SIZE,e->size));
    PUT(vireo_tlv_writer_put_u64(&w,VIREO_NODE_LIST_TLV_CREATED_AT_MS,e->created_at_ms));
    PUT(vireo_tlv_writer_put_u64(&w,VIREO_NODE_LIST_TLV_UPDATED_AT_MS,e->updated_at_ms));
    if (e->has_object_hash) PUT(vireo_tlv_writer_put(&w,VIREO_NODE_LIST_TLV_OBJECT_HASH,e->object_hash,32));
#undef PUT
    if (rc==VIREO_OK) *size=w.used;
    return rc;
}

vireo_result_t vireo_node_list_response_encode(vireo_node_list_response_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size) {
    int const saved=errno;
    if (value==NULL || wire==NULL || out_size==NULL || !response_valid(value))
        return finish(VIREO_RESULT_INVALID_ARGUMENT,saved);
    size_t body=0;
    if (value->status==VIREO_STATUS_OK) {
        body=18+(value->has_more ? 100U : 0U);
        for (size_t i=0;i<value->count;++i)
            body+=4+70+value->entries[i].name_length+(value->entries[i].has_object_hash ? 36U : 0U);
    }
    if (capacity<32+body) return finish(VIREO_RESULT_RANGE,saved);
    unsigned char frame[VIREO_NODE_LIST_RESPONSE_FRAME_MAX]; vireo_tlv_writer_t w;
    vireo_result_t rc=vireo_tlv_writer_init(&w,frame+32,body);
    if (value->status==VIREO_STATUS_OK) {
        if (rc==VIREO_OK) rc=vireo_tlv_writer_put_u64(&w,VIREO_NODE_LIST_TLV_DIRECTORY_ID,value->directory_id);
        if (rc==VIREO_OK) rc=vireo_tlv_writer_put_u16(&w,VIREO_NODE_LIST_TLV_PAGE_SIZE,value->page_size);
        for (size_t i=0;rc==VIREO_OK && i<value->count;++i) {
            unsigned char inner[VIREO_NODE_LIST_ENTRY_BODY_MAX]; size_t n=0;
            rc=write_entry(&value->entries[i],inner,&n);
            if (rc==VIREO_OK) rc=vireo_tlv_writer_put(&w,VIREO_NODE_LIST_TLV_NODE_ENTRY,inner,n);
        }
        if (rc==VIREO_OK && value->has_more)
            rc=vireo_tlv_writer_put(&w,VIREO_NODE_LIST_TLV_NEXT_PAGE_TOKEN,value->next_page_token,96);
    }
    vireo_protocol_header_t h={.command=VIREO_COMMAND_NODE_LIST,
        .flags=(uint16_t)(VIREO_PROTOCOL_FLAG_RESPONSE|(value->has_more ? VIREO_PROTOCOL_FLAG_MORE : 0)),
        .status=value->status,.body_len=(uint32_t)body,.sequence=value->sequence,.session_handle=value->session_handle};
    if (rc==VIREO_OK) rc=publish(&h,frame,32+body,wire,out_size);
    return finish(rc,saved);
}
/** @brief 读取schema已验证的一项到零初始化局部entry，仅复制无语义判断。 */
static vireo_result_t read_entry(unsigned char const *p, size_t n, vireo_node_list_entry_t *e) {
    vireo_tlv_reader_t r; vireo_tlv_view_t f; vireo_tlv_issue_t ti;
    vireo_result_t rc=vireo_tlv_reader_init(&r,p,n);
    while (rc==VIREO_OK && r.offset<r.size) {
        rc=vireo_tlv_reader_next(&r,&f,&ti);
        if (rc!=VIREO_OK) break;
        switch (f.type) {
        case VIREO_NODE_LIST_TLV_NODE_ID: rc=vireo_tlv_view_read_u64(&f,&e->node_id); break;
        case VIREO_NODE_LIST_TLV_PARENT_ID: rc=vireo_tlv_view_read_u64(&f,&e->parent_id); break;
        case VIREO_NODE_LIST_TLV_NAME_BYTES: e->name_length=f.length; memcpy(e->name,f.value,f.length); break;
        case VIREO_NODE_LIST_TLV_NODE_TYPE: rc=vireo_tlv_view_read_u16(&f,&e->type); break;
        case VIREO_NODE_LIST_TLV_SIZE: rc=vireo_tlv_view_read_u64(&f,&e->size); break;
        case VIREO_NODE_LIST_TLV_CREATED_AT_MS: rc=vireo_tlv_view_read_u64(&f,&e->created_at_ms); break;
        case VIREO_NODE_LIST_TLV_UPDATED_AT_MS: rc=vireo_tlv_view_read_u64(&f,&e->updated_at_ms); break;
        case VIREO_NODE_LIST_TLV_OBJECT_HASH: e->has_object_hash=true; memcpy(e->object_hash,f.value,32); break;
        default: rc=VIREO_RESULT_PROTOCOL; break;
        }
    }
    return rc;
}

vireo_result_t vireo_node_list_response_decode(unsigned char const *wire, size_t wire_size,
    vireo_node_list_response_t *out, vireo_node_list_issue_t *issue) {
    int const saved=errno;
    if (issue!=NULL) *issue=VIREO_NODE_LIST_ISSUE_NONE;
    if (wire==NULL || out==NULL || issue==NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT,saved);
    vireo_protocol_header_t h;
    vireo_result_t rc=envelope(wire,wire_size,true,&h,issue);
    if (rc!=VIREO_OK) return finish(rc,saved);
    vireo_node_list_response_t next={.status=h.status,.sequence=h.sequence,.session_handle=h.session_handle};
    if (h.status==VIREO_STATUS_OK) {
        if (!schema(wire+32,h.body_len,response_rules,4))
            return finish(reject(issue,VIREO_NODE_LIST_ISSUE_FIELDS),saved);
        vireo_tlv_reader_t r; vireo_tlv_view_t f; vireo_tlv_issue_t ti;
        bool token_present=false;
        rc=vireo_tlv_reader_init(&r,wire+32,h.body_len);
        while (rc==VIREO_OK && r.offset<r.size) {
            rc=vireo_tlv_reader_next(&r,&f,&ti);
            if (rc!=VIREO_OK) break;
            switch (f.type) {
            case VIREO_NODE_LIST_TLV_DIRECTORY_ID: rc=vireo_tlv_view_read_u64(&f,&next.directory_id); break;
            case VIREO_NODE_LIST_TLV_PAGE_SIZE: rc=vireo_tlv_view_read_u16(&f,&next.page_size); break;
            case VIREO_NODE_LIST_TLV_NEXT_PAGE_TOKEN:
                token_present=true; memcpy(next.next_page_token,f.value,96); break;
            case VIREO_NODE_LIST_TLV_NODE_ENTRY:
                if (!schema(f.value,f.length,entry_rules,8)) rc=VIREO_RESULT_PROTOCOL;
                else {
                    if (next.count<64) rc=read_entry(f.value,f.length,&next.entries[next.count]);
                    ++next.count; /* body<=23478，最多5869个空ENTRY，不会溢出size_t。 */
                }
                break;
            default: rc=VIREO_RESULT_PROTOCOL; break;
            }
        }
        if (rc!=VIREO_OK) return finish(reject(issue,VIREO_NODE_LIST_ISSUE_FIELDS),saved);
        next.has_more=(h.flags&VIREO_PROTOCOL_FLAG_MORE)!=0;
        if (next.has_more!=token_present) return finish(reject(issue,VIREO_NODE_LIST_ISSUE_VALUE),saved);
    }
    if (!response_valid(&next)) return finish(reject(issue,VIREO_NODE_LIST_ISSUE_VALUE),saved);
    *out=next; return finish(VIREO_OK,saved);
}
