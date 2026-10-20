/* PROJECT: VIREO; FILE: test_auth_response_consumer.c; AUTHOR: bitofux; DATE: 2026-10-20. */
#define _GNU_SOURCE
#include "auth_reactor_test_support.h"
#include "auth_response_consumer_internal.h"
#include "auth_session_internal.h"
static vireo_auth_response_consumer_options_t const options={100,101,102,103};
static unsigned sequence=1;
/* 只在publisher边界构造可信业务事实；实际TLS/FIFO/inflight仍使用公开真实路径。 */
static vireo_completion_t *completion(fixture_t *f,bool login,bool committed,vireo_result_t result)
{
    unsigned char wire[156]; size_t n=request_frame(wire,login,sequence,false);
    vireo_task_metadata_t metadata;
    EXPECT(vireo_inflight_metadata_make(f->server,f->client,sequence,sequence,login?101U:100U,UINT64_MAX,&metadata,NULL),VIREO_OK); ++sequence;
    EXPECT(vireo_inflight_store_register(f->store,f->server,metadata,NULL),VIREO_OK);
    vireo_task_t *task=NULL; EXPECT(vireo_task_create_copy(metadata,wire,n,4096,&task),VIREO_OK);
    vireo_auth_task_result_t r={.stage=VIREO_AUTH_TASK_SERVICE,.result=result,.metadata=metadata,
        .command=login?VIREO_COMMAND_LOGIN:VIREO_COMMAND_REGISTER};
    if(committed && login) {
        r.login.transaction.commit=VIREO_MYSQL_LOGIN_COMMITTED; r.login.user_id=7;
        r.login.transaction.session_id=8; r.login.transaction.audit_id=9;
        r.login.issued_at_ms=100; r.login.expires_at_ms=200;
        for(size_t i=0;i<32;++i) r.login.token.bytes[i]=(unsigned char)(i+1);
    } else if(committed) {
        r.registration.commit=VIREO_MYSQL_REGISTRATION_COMMITTED;
        r.registration.user_id=7; r.registration.root_node_id=6; r.registration.audit_id=9;
    }
    vireo_completion_queue_t *queue=NULL; vireo_completion_queue_options_t qo={1,65536};
    vireo_notifier_t *notifier=NULL; vireo_notifier_options_t no={4096};
    EXPECT(vireo_completion_queue_create(&qo,&queue),VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(queue),VIREO_OK);
    EXPECT(vireo_notifier_create(&no,&notifier,NULL),VIREO_OK);
    vireo_completion_t *owner=NULL; vireo_auth_completion_publish_report_t report;
    EXPECT(vireo_auth_completion_publish(task,&r,4096,queue,notifier,&owner,&report),VIREO_OK);
    vireo_completion_queue_transfer_report_t transfer;
    EXPECT(vireo_completion_queue_try_pop(queue,&owner,&transfer),VIREO_OK);
    EXPECT(vireo_task_destroy(&task),VIREO_OK); EXPECT(vireo_auth_task_result_clear(&r),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue),VIREO_OK); EXPECT(vireo_notifier_destroy(&notifier,NULL),VIREO_OK);
    EXPECT(vireo_secure_clear(wire,sizeof(wire)),VIREO_OK); return owner;
}
static vireo_auth_response_t response(fixture_t *f,size_t n)
{
    unsigned char wire[104]; REQUIRE(n<=sizeof(wire)); drain(f,wire,n);
    vireo_auth_response_t value={0}; EXPECT(vireo_auth_response_decode(wire,n,&value),VIREO_OK);
    EXPECT(vireo_secure_clear(wire,sizeof(wire)),VIREO_OK); return value;
}
typedef struct script { unsigned enqueues,refreshes; bool fail_refresh; } script_t;
static vireo_result_t enqueue_test(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,
    unsigned char const *wire,size_t n,vireo_tcp_server_client_error_t *error)
{ script_t *p=context; ++p->enqueues; return vireo_tcp_server_client_write_enqueue(s,c,wire,n,error); }
static vireo_result_t refresh_test(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,
    vireo_tcp_server_tls_flow_info_t *info,vireo_tcp_server_tls_application_error_t *error)
{
    script_t *p=context; ++p->refreshes;
    if(p->fail_refresh) { errno=EINTR; return VIREO_RESULT_IO; }
    return vireo_tcp_server_client_tls_flow_refresh(s,c,info,error);
}
static vireo_auth_response_consumer_ops_t const ops={enqueue_test,refresh_test};
static void ordinary(void)
{
    fixture_t f; setup(&f,true); vireo_auth_response_consumer_receipt_t receipt={0}; vireo_auth_response_consumer_report_t report;
    vireo_completion_t *owner=completion(&f,false,true,VIREO_OK);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_OK);
    REQUIRE(!owner && report.enqueued && !report.bound && report.consumption.record_consumed);
    vireo_auth_response_t v=response(&f,56); REQUIRE(v.user_id==7 && v.root_node_id==6 && v.session_handle==0);
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK);
    EXPECT(vireo_auth_response_consumer_acknowledge(owner,&receipt),VIREO_OK);
    owner=completion(&f,true,true,VIREO_RESULT_DATABASE);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_OK);
    REQUIRE(!owner && report.bound && report.enqueued && receipt.state==VIREO_AUTH_CONSUMER_READY);
    v=response(&f,104); REQUIRE(v.status==VIREO_STATUS_OK && v.token[31]==32 && v.session_handle!=0);
    uint32_t const handle=v.session_handle;
    vireo_auth_session_identity_t identity;
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,handle,100,&identity),VIREO_OK); REQUIRE(identity.user_id==7 && identity.session_id==8);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_OK);
    REQUIRE(!report.enqueue_called && !report.bound);
    EXPECT(vireo_auth_response_consumer_acknowledge(owner,&receipt),VIREO_OK);
    owner=completion(&f,true,false,VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_OK);
    vireo_auth_response_t failed=response(&f,32); REQUIRE(failed.status==VIREO_STATUS_AUTHENTICATION_FAILED && failed.session_handle==0);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,handle,100,&identity),VIREO_OK);
    EXPECT(vireo_auth_response_consumer_acknowledge(owner,&receipt),VIREO_OK);
    owner=completion(&f,true,true,VIREO_OK);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_OK);
    vireo_auth_response_t replacement=response(&f,104);
    REQUIRE(replacement.session_handle!=handle && report.bound);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,handle,100,&identity),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,replacement.session_handle,100,&identity),VIREO_OK);
    EXPECT(vireo_auth_response_consumer_acknowledge(owner,&receipt),VIREO_OK);
    EXPECT(vireo_auth_response_clear(&replacement),VIREO_OK);
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK); EXPECT(vireo_auth_response_clear(&failed),VIREO_OK);
    cleanup(&f);
}
static void backpressure(void)
{
    fixture_t f; setup(&f,true); unsigned char full[4096],drained[4096]; memset(full,0xa5,sizeof(full));
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.client,full,sizeof(full),NULL),VIREO_OK);
    vireo_completion_t *owner=completion(&f,true,true,VIREO_OK);
    vireo_auth_response_consumer_receipt_t receipt={0}; vireo_auth_response_consumer_report_t report; script_t script={0};
    EXPECT(vireo_auth_response_consumer_with(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report,&ops,&script),VIREO_RESULT_RANGE);
    REQUIRE(owner && receipt.ticket_pending && receipt.state==VIREO_AUTH_CONSUMER_NEEDS_ENQUEUE &&
        report.consumption.record_consumed && !report.enqueued && !report.bound);
    uint32_t const candidate=receipt.ticket.handle;
    vireo_auth_session_identity_t identity;
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,candidate,100,&identity),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_sessions_destroy(&f.sessions),VIREO_RESULT_BUSY);
    drain(&f,drained,sizeof(drained)); REQUIRE(!memcmp(full,drained,sizeof(full)));
    script.fail_refresh=true;
    EXPECT(vireo_auth_response_consumer_with(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report,&ops,&script),VIREO_RESULT_IO);
    REQUIRE(owner && !report.consume_called && report.enqueued && report.bound && !receipt.ticket_pending && receipt.state==VIREO_AUTH_CONSUMER_NEEDS_REFRESH);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,candidate,100,&identity),VIREO_OK);
    REQUIRE(script.enqueues==2 && script.refreshes==1);
    script.fail_refresh=false;
    EXPECT(vireo_auth_response_consumer_with(f.server,f.store,f.sessions,&owner,&options,300,&receipt,&report,&ops,&script),VIREO_OK);
    REQUIRE(!owner && !report.enqueued && !report.bound && script.enqueues==2 && script.refreshes==2);
    vireo_auth_response_t v=response(&f,104); REQUIRE(v.session_handle==candidate);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,candidate,300,&identity),VIREO_RESULT_TIMEOUT);
    unsigned char extra; size_t n=0; ERR_clear_error(); int rc=SSL_read_ex(f.ssl,&extra,1,&n);
    REQUIRE(rc==0 && n==0 && SSL_get_error(f.ssl,rc)==SSL_ERROR_WANT_READ);
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK); EXPECT(vireo_auth_response_consumer_acknowledge(owner,&receipt),VIREO_OK);
    cleanup(&f);
}
static void expiry_and_late(void)
{
    fixture_t f; setup(&f,true); vireo_auth_response_consumer_receipt_t receipt={0}; vireo_auth_response_consumer_report_t report;
    vireo_completion_t *owner=completion(&f,true,true,VIREO_OK);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,200,&receipt,&report),VIREO_OK);
    REQUIRE(!owner && !report.bound && receipt.ticket.handle==0);
    vireo_auth_response_t v=response(&f,32); REQUIRE(v.status==VIREO_STATUS_SESSION_EXPIRED && v.token[31]==0);
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK); EXPECT(vireo_auth_response_consumer_acknowledge(owner,&receipt),VIREO_OK);
    owner=completion(&f,true,true,VIREO_OK);
    vireo_connection_pool_lease_t const old=f.client; client_close(&f); client_open(&f,true);
    REQUIRE(old.slot_index==f.client.slot_index && old.generation!=f.client.generation);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_OK);
    REQUIRE(!owner && !report.enqueued && !report.bound && receipt.state==VIREO_AUTH_CONSUMER_EMPTY &&
        report.consumption.disposition==VIREO_INFLIGHT_COMPLETION_CLIENT_GONE);
    owner=completion(&f,true,true,VIREO_OK); vireo_completion_info_t info; EXPECT(vireo_completion_inspect(owner,&info),VIREO_OK);
    vireo_task_metadata_t removed; EXPECT(vireo_inflight_store_take(f.store,info.metadata.request,&removed,NULL),VIREO_OK);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_OK);
    REQUIRE(!owner && report.consumption.disposition==VIREO_INFLIGHT_COMPLETION_REQUEST_GONE && !report.enqueued);
    cleanup(&f);
}
typedef struct random_script { uint32_t value; int result; unsigned calls; } random_script_t;
static int random_test(void *context,unsigned char out[4])
{
    random_script_t *s=context; ++s->calls;
    for(size_t i=0;i<4;++i) out[i]=(unsigned char)(s->value>>((3-i)*8)); errno=EIO; return s->result;
}
static void sessions(void)
{
    fixture_t f; setup(&f,true); vireo_auth_session_identity_t const a={1,2,100,200,false},b={3,4,100,300,false};
    vireo_auth_session_identity_t out,old; memset(&old,0xa5,sizeof(old)); out=old;
    vireo_auth_session_ticket_t first={0},next={0},untouched; memset(&untouched,0xa5,sizeof(untouched));
    random_script_t random={7,1,0};
    EXPECT(vireo_auth_session_reserve_with(f.sessions,f.client,&a,&first,random_test,&random),VIREO_OK);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,7,100,&out),VIREO_RESULT_NOT_FOUND); REQUIRE(!memcmp(&out,&old,sizeof(out)));
    EXPECT(vireo_auth_session_commit(f.sessions,first),VIREO_OK);
    EXPECT(vireo_auth_session_commit(f.sessions,first),VIREO_RESULT_NOT_FOUND);
    next=untouched; EXPECT(vireo_auth_session_reserve_with(f.sessions,f.client,&b,&next,random_test,&random),VIREO_RESULT_BUSY);
    REQUIRE(!memcmp(&next,&untouched,sizeof(next)) && random.calls==2);
    random.value=0; EXPECT(vireo_auth_session_reserve_with(f.sessions,f.client,&b,&next,random_test,&random),VIREO_RESULT_BUSY);
    random.result=-1; EXPECT(vireo_auth_session_reserve_with(f.sessions,f.client,&b,&next,random_test,&random),VIREO_RESULT_IO);
    random.result=1; random.value=8;
    EXPECT(vireo_auth_session_reserve_with(f.sessions,f.client,&b,&next,random_test,&random),VIREO_OK);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,7,100,&out),VIREO_OK); REQUIRE(out.user_id==1);
    EXPECT(vireo_auth_session_abort(f.sessions,next),VIREO_OK);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,7,200,&out),VIREO_RESULT_TIMEOUT);
    EXPECT(vireo_auth_session_reserve_with(f.sessions,f.client,&b,&next,random_test,&random),VIREO_OK);
    EXPECT(vireo_auth_session_commit(f.sessions,next),VIREO_OK);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,7,100,&out),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,8,100,&out),VIREO_OK); REQUIRE(out.user_id==3);
    EXPECT(vireo_auth_session_revoke(f.sessions,4),VIREO_OK);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,8,100,&out),VIREO_RESULT_CANCELLED);
    vireo_connection_pool_lease_t const lease=f.client; client_close(&f); client_open(&f,true);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,8,100,&out),VIREO_RESULT_NOT_FOUND);
    random.value=9; EXPECT(vireo_auth_session_reserve_with(f.sessions,f.client,&a,&next,random_test,&random),VIREO_OK);
    EXPECT(vireo_auth_session_forget(f.sessions,lease),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_session_abort(f.sessions,first),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_session_commit(f.sessions,next),VIREO_OK);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,9,100,&out),VIREO_OK);
    cleanup(&f);
}
static void abandon_and_invalid(void)
{
    fixture_t f; setup(&f,false); vireo_completion_t *owner=completion(&f,true,true,VIREO_OK);
    vireo_auth_response_consumer_receipt_t receipt={0}; vireo_auth_response_consumer_report_t report;
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_RESULT_BUSY);
    REQUIRE(owner && report.consumption.record_consumed && !report.enqueued && !receipt.ticket_pending);
    EXPECT(vireo_auth_response_consumer_abandon(f.sessions,&owner,&receipt),VIREO_OK); REQUIRE(!owner && receipt.state==0);
    cleanup(&f); setup(&f,true);
    unsigned char full[4096]; memset(full,0xa5,sizeof(full));
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.client,full,sizeof(full),NULL),VIREO_OK);
    owner=completion(&f,true,true,VIREO_OK);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_RESULT_RANGE);
    REQUIRE(receipt.ticket_pending && owner); uint32_t const handle=receipt.ticket.handle;
    vireo_completion_info_t original; EXPECT(vireo_completion_inspect(owner,&original),VIREO_OK);
    ++original.metadata.request.request_instance_id;
    vireo_completion_t *unrelated=NULL;
    EXPECT(vireo_completion_create_copy(original.metadata,NULL,0,4096,&unrelated),VIREO_OK);
    EXPECT(vireo_auth_response_consumer_abandon(f.sessions,&unrelated,&receipt),VIREO_RESULT_INVALID_ARGUMENT);
    REQUIRE(unrelated && owner && receipt.ticket_pending);
    EXPECT(vireo_completion_destroy(&unrelated),VIREO_OK);
    EXPECT(vireo_auth_response_consumer_abandon(f.sessions,&owner,&receipt),VIREO_OK);
    REQUIRE(!owner && receipt.state==0); vireo_auth_session_identity_t identity;
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,handle,100,&identity),VIREO_RESULT_NOT_FOUND);
    cleanup(&f); setup(&f,true);
    owner=completion(&f,true,true,VIREO_OK); vireo_completion_info_t info; EXPECT(vireo_completion_inspect(owner,&info),VIREO_OK);
    receipt.command=VIREO_COMMAND_LOGOUT;
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_RESULT_INVALID_ARGUMENT);
    REQUIRE(owner && !report.consume_called); receipt=(vireo_auth_response_consumer_receipt_t){0};
    vireo_auth_response_consumer_options_t const wrong={10,11,102,103};
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&wrong,100,&receipt,&report),VIREO_RESULT_INVALID_ARGUMENT);
    REQUIRE(owner && !report.consume_called && receipt.state==0);
    vireo_task_metadata_t registered; EXPECT(vireo_inflight_store_get(f.store,info.metadata.request,&registered,NULL),VIREO_OK);
    unsigned char broken[88]={0}; vireo_completion_t *bad=NULL;
    EXPECT(vireo_completion_create_copy(info.metadata,broken,sizeof(broken),4096,&bad),VIREO_OK);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&bad,&options,100,&receipt,&report),VIREO_RESULT_PROTOCOL);
    REQUIRE(!report.consume_called && bad); EXPECT(vireo_completion_destroy(&bad),VIREO_OK);
    EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&options,100,&receipt,&report),VIREO_RESULT_CANCELLED);
    REQUIRE(owner && receipt.state==VIREO_AUTH_CONSUMER_NEEDS_ENQUEUE && report.consumption.record_consumed);
    EXPECT(vireo_auth_response_consumer_abandon(f.sessions,&owner,&receipt),VIREO_OK); cleanup(&f);
}
/* 模型只注入提交三态/清理错；TLS、登记、payload、所有权和屏障使用产品路径。 */
static vireo_completion_t *session_completion(fixture_t *f,bool logout,uint64_t session,
    vireo_auth_commit_t commit,bool cleanup_error)
{
    unsigned char wire[68]={0};
    vireo_protocol_header_t h={.command=logout?VIREO_COMMAND_LOGOUT:VIREO_COMMAND_SESSION_RESUME,
        .sequence=sequence,.session_handle=logout?7:0,.body_len=logout?0:36};
    if(!logout) { wire[33]=4; wire[35]=32; memset(wire+36,0x35,32); }
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,h.body_len,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    vireo_task_metadata_t m;
    EXPECT(vireo_inflight_metadata_make(f->server,f->client,sequence,sequence,logout?102:103,UINT64_MAX,&m,NULL),VIREO_OK);
    ++sequence;
    if(!logout) EXPECT(vireo_auth_session_note_resume(f->sessions,m.request_instance_id),VIREO_OK);
    EXPECT(vireo_inflight_store_register(f->store,f->server,m,NULL),VIREO_OK);
    vireo_task_t *task=NULL; vireo_auth_logout_identity_t target={7,session};
    if(logout) EXPECT(vireo_auth_task_create_logout(m,102,wire,32,&target,4096,NULL,&task),VIREO_OK);
    else EXPECT(vireo_task_create_copy(m,wire,68,4096,&task),VIREO_OK);
    vireo_auth_task_result_t r={.stage=VIREO_AUTH_TASK_SERVICE,.metadata=m,.command=h.command};
    if(logout) {
        r.logout_target=target;
        r.result=cleanup_error || commit!=VIREO_AUTH_COMMITTED?VIREO_RESULT_DATABASE:VIREO_OK;
        r.logout_report.commit=commit==VIREO_AUTH_COMMITTED?VIREO_MYSQL_LOGOUT_COMMITTED:
            commit==VIREO_AUTH_COMMIT_UNKNOWN?VIREO_MYSQL_LOGOUT_UNKNOWN:VIREO_MYSQL_LOGOUT_NOT_COMMITTED;
        if(commit==VIREO_AUTH_COMMITTED) {
            r.logout_report.session_id=session; r.logout_report.audit_id=9; r.logout_report.revoked_at_ms=120;
        }
    } else {
        r.resume_report.valid=true;
        r.resume_identity=(vireo_mysql_session_identity_t){.user_id=7,.session_id=session,.issued_at_ms=100,.expires_at_ms=200};
    }
    vireo_completion_queue_t *q=NULL; vireo_completion_queue_options_t qo={1,65536};
    vireo_notifier_t *notifier=NULL; vireo_notifier_options_t no={4096};
    EXPECT(vireo_completion_queue_create(&qo,&q),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(q),VIREO_OK);
    EXPECT(vireo_notifier_create(&no,&notifier,NULL),VIREO_OK);
    vireo_completion_t *owner=NULL; vireo_auth_completion_publish_report_t published;
    EXPECT(vireo_auth_completion_publish(task,&r,4096,q,notifier,&owner,&published),VIREO_OK);
    vireo_completion_queue_transfer_report_t moved;
    EXPECT(vireo_completion_queue_try_pop(q,&owner,&moved),VIREO_OK);
    vireo_auth_completion_outcome_t o={0}; EXPECT(vireo_auth_completion_decode(owner,&o),VIREO_OK);
    REQUIRE(o.commit==commit && o.command==h.command && o.resume_validated==!logout);
    vireo_completion_info_t ci; vireo_completion_payload_view_t payload;
    EXPECT(vireo_completion_inspect(owner,&ci),VIREO_OK);
    EXPECT(vireo_completion_borrow_payload(owner,&payload),VIREO_OK); REQUIRE(payload.size==120);
    size_t const invalid[]={0,6,7,16,56,113,119};
    for(size_t k=0;k<sizeof invalid/sizeof invalid[0];++k) {
        unsigned char bad[120]; memcpy(bad,payload.data,120); bad[invalid[k]]=0xff;
        vireo_completion_t *broken=NULL; EXPECT(vireo_completion_create_copy(ci.metadata,bad,120,4096,&broken),VIREO_OK);
        vireo_auth_completion_outcome_t untouched; memset(&untouched,0xa5,sizeof untouched);
        unsigned char before[sizeof untouched]; memcpy(before,&untouched,sizeof before);
        EXPECT(vireo_auth_completion_decode(broken,&untouched),VIREO_RESULT_PROTOCOL);
        REQUIRE(!memcmp(before,&untouched,sizeof before)); EXPECT(vireo_completion_destroy(&broken),VIREO_OK);
    }
    for(size_t i=0;i<32;++i) REQUIRE(!o.token.bytes[i]);
    EXPECT(vireo_auth_completion_outcome_clear(&o),VIREO_OK);
    EXPECT(vireo_task_destroy(&task),VIREO_OK); EXPECT(vireo_auth_task_result_clear(&r),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&q),VIREO_OK); EXPECT(vireo_notifier_destroy(&notifier,NULL),VIREO_OK);
    EXPECT(vireo_secure_clear(wire,sizeof wire),VIREO_OK); return owner;
}
static uint32_t bind_session(fixture_t *f,uint64_t session)
{
    vireo_auth_session_identity_t const i={7,session,100,200,false}; vireo_auth_session_ticket_t t;
    EXPECT(vireo_auth_session_reserve(f->sessions,f->client,&i,&t),VIREO_OK);
    EXPECT(vireo_auth_session_commit(f->sessions,t),VIREO_OK); return t.handle;
}
static void consume_session(fixture_t *f,vireo_completion_t **owner,vireo_status_t status,bool resume)
{
    vireo_auth_response_consumer_receipt_t r={0}; vireo_auth_response_consumer_report_t p;
    vireo_result_t rc=vireo_auth_response_consumer_step(f->server,f->store,f->sessions,owner,&options,120,&r,&p);
    if(rc!=VIREO_OK) fprintf(stderr,"session consume status=%u resume=%d rc=%d stage=%d state=%d\n",status,resume,rc,p.stage,r.state);
    REQUIRE(rc==VIREO_OK);
    REQUIRE(!*owner && p.enqueued);
    vireo_auth_response_t v=response(f,resume && status==VIREO_STATUS_OK?68:32);
    REQUIRE(v.status==status && (status!=VIREO_STATUS_OK || !resume || v.session_handle));
    for(size_t i=0;i<32;++i) REQUIRE(!v.token[i]);
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK);
    EXPECT(vireo_auth_response_consumer_acknowledge(*owner,&r),VIREO_OK);
}
static void resume_logout_interleavings(void)
{
    fixture_t f; setup_capacity(&f,true,2);
    fixture_t g={.server=f.server,.store=f.store,.sessions=f.sessions,.address=f.address,.peer=-1}; client_open(&g,true);
    vireo_auth_session_identity_t i;
    uint32_t a=bind_session(&f,8),b=bind_session(&g,8);
    /* 可控暂扣旧完成，退出先消费：所有旧在途恢复（包括无关SQL Session）BUSY。 */
    vireo_completion_t *old=session_completion(&f,false,8,VIREO_AUTH_NOT_COMMITTED,false);
    vireo_completion_t *unrelated=session_completion(&f,false,99,VIREO_AUTH_NOT_COMMITTED,false);
    vireo_completion_t *logout=session_completion(&g,true,8,VIREO_AUTH_COMMITTED,true);
    consume_session(&g,&logout,VIREO_STATUS_OK,false);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,a,120,&i),VIREO_RESULT_CANCELLED);
    EXPECT(vireo_auth_session_lookup(f.sessions,g.client,b,120,&i),VIREO_RESULT_CANCELLED);
    consume_session(&f,&old,VIREO_STATUS_BUSY,true); consume_session(&f,&unrelated,VIREO_STATUS_BUSY,true);
    /* 相反顺序：先成功绑定，再退出；新发起恢复允许越过先前屏障。 */
    old=session_completion(&f,false,8,VIREO_AUTH_NOT_COMMITTED,false);
    vireo_auth_response_consumer_receipt_t r={0}; vireo_auth_response_consumer_report_t p;
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&old,&options,120,&r,&p),VIREO_OK);
    vireo_auth_response_t v=response(&f,68); a=v.session_handle; REQUIRE(p.bound);
    EXPECT(vireo_auth_response_consumer_acknowledge(old,&r),VIREO_OK);
    b=bind_session(&g,99);
    logout=session_completion(&g,true,8,VIREO_AUTH_COMMIT_UNKNOWN,false);
    consume_session(&g,&logout,VIREO_STATUS_INTERNAL_ERROR,false);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,a,120,&i),VIREO_RESULT_CANCELLED);
    EXPECT(vireo_auth_session_lookup(f.sessions,g.client,b,120,&i),VIREO_OK);
    /* 已reserve但FIFO满：退出撤销候选；重试必须abort票据且只回一次BUSY。 */
    unsigned char full[4096],out[4096]; memset(full,0xa5,sizeof full);
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.client,full,sizeof full,NULL),VIREO_OK);
    old=session_completion(&f,false,8,VIREO_AUTH_NOT_COMMITTED,false); r=(vireo_auth_response_consumer_receipt_t){0};
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&old,&options,120,&r,&p),VIREO_RESULT_RANGE);
    REQUIRE(old && r.ticket_pending); uint32_t candidate=r.ticket.handle;
    logout=session_completion(&g,true,8,VIREO_AUTH_COMMITTED,false); consume_session(&g,&logout,VIREO_STATUS_OK,false);
    drain(&f,out,sizeof out); REQUIRE(!memcmp(full,out,sizeof full));
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&old,&options,120,&r,&p),VIREO_OK);
    REQUIRE(!old && !r.ticket_pending && !p.bound); v=response(&f,32); REQUIRE(v.status==VIREO_STATUS_BUSY);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,candidate,120,&i),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_response_consumer_acknowledge(old,&r),VIREO_OK);
    /* 退出第一次消费失败后，后来新登记恢复不能被同一效果的重试再推进cutoff。 */
    EXPECT(vireo_tcp_server_client_write_enqueue(g.server,g.client,full,sizeof full,NULL),VIREO_OK);
    logout=session_completion(&g,true,8,VIREO_AUTH_COMMITTED,false); r=(vireo_auth_response_consumer_receipt_t){0};
    EXPECT(vireo_auth_response_consumer_step(g.server,g.store,g.sessions,&logout,&options,120,&r,&p),VIREO_RESULT_RANGE);
    REQUIRE(r.effect_applied && logout);
    old=session_completion(&f,false,99,VIREO_AUTH_NOT_COMMITTED,false);
    vireo_completion_info_t info; EXPECT(vireo_completion_inspect(old,&info),VIREO_OK);
    drain(&g,out,sizeof out);
    EXPECT(vireo_auth_response_consumer_step(g.server,g.store,g.sessions,&logout,&options,120,&r,&p),VIREO_OK);
    v=response(&g,32); REQUIRE(v.status==VIREO_STATUS_OK);
    EXPECT(vireo_auth_response_consumer_acknowledge(logout,&r),VIREO_OK);
    EXPECT(vireo_auth_session_check_resume(f.sessions,info.metadata.request.request_instance_id),VIREO_OK);
    consume_session(&f,&old,VIREO_STATUS_OK,true);
    /* 登记已取消、旧连接代与显式放弃都必须先执行撤销；旧目标不误清新Session。 */
    for(unsigned mode=0;mode<3;++mode) {
        a=bind_session(&f,8); b=bind_session(&g,99);
        logout=session_completion(&g,true,8,VIREO_AUTH_COMMITTED,false);
        EXPECT(vireo_completion_inspect(logout,&info),VIREO_OK);
        if(mode==0) { vireo_task_metadata_t removed; EXPECT(vireo_inflight_store_take(g.store,info.metadata.request,&removed,NULL),VIREO_OK); }
        if(mode==1) { client_close(&g); client_open(&g,true); b=bind_session(&g,99); }
        r=(vireo_auth_response_consumer_receipt_t){0};
        if(mode==2) EXPECT(vireo_auth_response_consumer_abandon(g.sessions,&logout,&r),VIREO_OK);
        else EXPECT(vireo_auth_response_consumer_step(g.server,g.store,g.sessions,&logout,&options,120,&r,&p),VIREO_OK);
        REQUIRE(!logout && r.state==0);
        EXPECT(vireo_auth_session_lookup(f.sessions,f.client,a,120,&i),VIREO_RESULT_CANCELLED);
        EXPECT(vireo_auth_session_lookup(g.sessions,g.client,b,120,&i),VIREO_OK);
        if(mode==2) { vireo_task_metadata_t removed; EXPECT(vireo_inflight_store_take(g.store,info.metadata.request,&removed,NULL),VIREO_OK); }
    }
    /* NOT_COMMITTED不产生撤销，时间倒退/过期不发布恢复身份。 */
    a=bind_session(&f,8); logout=session_completion(&g,true,8,VIREO_AUTH_NOT_COMMITTED,false);
    consume_session(&g,&logout,VIREO_STATUS_INTERNAL_ERROR,false);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,a,120,&i),VIREO_OK);
    old=session_completion(&f,false,8,VIREO_AUTH_NOT_COMMITTED,false); r=(vireo_auth_response_consumer_receipt_t){0};
    EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&old,&options,99,&r,&p),VIREO_OK);
    v=response(&f,32); REQUIRE(v.status==VIREO_STATUS_AUTHENTICATION_FAILED && !p.bound);
    EXPECT(vireo_auth_response_consumer_acknowledge(old,&r),VIREO_OK);
    EXPECT(vireo_auth_session_check_resume(f.sessions,UINT64_MAX),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_session_note_resume(f.sessions,0),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_session_note_resume(f.sessions,1),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK); client_close(&g); cleanup(&f);
}

int main(void)
{
    int previous=0; REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&previous)==0);
    struct sigaction action={0}; action.sa_handler=SIG_IGN; REQUIRE(sigemptyset(&action.sa_mask)==0 && sigaction(SIGPIPE,&action,NULL)==0);
    size_t before=fds(); ordinary(); backpressure(); expiry_and_late(); sessions(); abandon_and_invalid(); resume_logout_interleavings();
    REQUIRE(fds()==before); REQUIRE(pthread_setcancelstate(previous,NULL)==0);
    printf("PASS auth_response_consumer: 6 groups, VAC2 malformed/atomicity, two-client resume/logout permutations, COMMITTED cleanup error/UNKNOWN model, barrier retry exactly once,, real TLS responses, reserve/replace/revoke/expiry, full FIFO and refresh-only recovery, old-generation/request gone, abandon, FD %zu->%zu\n",before,fds());
    return 0;
}
