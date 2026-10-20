/* PROJECT : VIREO
 * FILE : test_connection_peer.c
 * AUTHOR : bitofux
 * DATE : 2026-10-19
 * BRIEF : 真实IP来源、失败输出保持、TLS资源查询及当前租约/LOGIN准入接点。
 */
#define _GNU_SOURCE
#include "net/connection_internal.h"
#include "tls_context_fixtures.h"
#include <vireo/net/tcp_server.h>
#include <vireo/service/auth_login_admission.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static size_t checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while (0)
#define EXPECT(x,y) do { errno=ECHILD; CHECK((x)==(y)); CHECK(errno==ECHILD); } while (0)
static vireo_connection_options_t const options = {256,256,512};

static size_t fd_count(void)
{
    DIR *d=opendir("/proc/self/fd"); CHECK(d!=NULL);
    size_t count=0; struct dirent *entry;
    while ((entry=readdir(d))!=NULL) if (entry->d_name[0]!='.') ++count;
    CHECK(closedir(d)==0); return count;
}

/** 全是真实内核socket；双栈监听时以IPv4连接取得mapped IPv6。 */
static int listener(int family, bool mapped, struct sockaddr_storage *address, socklen_t *size)
{
    int fd=socket(family,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    if (family==AF_INET) {
        struct sockaddr_in a={.sin_family=AF_INET,.sin_addr={htonl(INADDR_LOOPBACK)}};
        CHECK(bind(fd,(struct sockaddr *)&a,(socklen_t)sizeof(a))==0);
    } else {
        int only=mapped ? 0 : 1;
        CHECK(setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&only,(socklen_t)sizeof(only))==0);
        struct sockaddr_in6 a={.sin6_family=AF_INET6};
        a.sin6_addr=mapped ? in6addr_any : in6addr_loopback;
        CHECK(bind(fd,(struct sockaddr *)&a,(socklen_t)sizeof(a))==0);
    }
    *size=(socklen_t)sizeof(*address);
    CHECK(getsockname(fd,(struct sockaddr *)address,size)==0); CHECK(listen(fd,4)==0);
    return fd;
}

static int connect_peer(struct sockaddr_storage const *address, socklen_t size, bool mapped,
    char const *source)
{
    int family=mapped ? AF_INET : (int)address->ss_family;
    int fd=socket(family,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(fd>=0);
    if (source!=NULL) {
        struct sockaddr_in local={.sin_family=AF_INET};
        CHECK(inet_pton(AF_INET,source,&local.sin_addr)==1);
        CHECK(bind(fd,(struct sockaddr *)&local,(socklen_t)sizeof(local))==0);
    }
    if (mapped) {
        struct sockaddr_in6 original; memcpy(&original,address,sizeof(original));
        struct sockaddr_in ipv4={.sin_family=AF_INET,.sin_port=original.sin6_port,
            .sin_addr={htonl(INADDR_LOOPBACK)}};
        CHECK(connect(fd,(struct sockaddr *)&ipv4,(socklen_t)sizeof(ipv4))==0);
    } else CHECK(connect(fd,(struct sockaddr const *)address,size)==0);
    return fd;
}

static vireo_connection_peer_t expected_peer(int family, bool mapped, char const *source)
{
    vireo_connection_peer_t value={0}; value.family=family==AF_INET ? 4 : 6;
    if (family==AF_INET) CHECK(inet_pton(AF_INET,source==NULL ? "127.0.0.1" : source,value.address)==1);
    else CHECK(inet_pton(AF_INET6,mapped ? "::ffff:127.0.0.1" : "::1",value.address)==1);
    return value;
}
static void equal_peer(vireo_connection_peer_t a, vireo_connection_peer_t b)
{ CHECK(a.family==b.family); CHECK(memcmp(a.address,b.address,sizeof(a.address))==0); }

typedef struct query_script {
    int fd, returned, cause;
    size_t calls;
    struct sockaddr_storage address;
    socklen_t size;
} query_script_t;
static int query(void *context, int fd, struct sockaddr *address, socklen_t *size)
{
    query_script_t *script=context; CHECK(fd==script->fd); ++script->calls;
    CHECK(*size==(socklen_t)sizeof(script->address));
    memcpy(address,&script->address,sizeof(script->address)); *size=script->size;
    errno=script->cause; return script->returned;
}
static void script_case(vireo_connection_t const *c, query_script_t *script,
    vireo_result_t result, bool diagnostic)
{
    vireo_connection_peer_t output; memset(&output,0xA5,sizeof(output));
    unsigned char before[sizeof(output)]; memcpy(before,&output,sizeof(output));
    vireo_connection_error_t error; memset(&error,0xA5,sizeof(error)); script->calls=0;
    EXPECT(vireo_connection_peer_query_with(c,&output,diagnostic ? &error : NULL,query,script),result);
    CHECK(script->calls==1);
    if (result!=VIREO_OK) CHECK(memcmp(&output,before,sizeof(output))==0);
    if (diagnostic) {
        CHECK(error.stage==(result==VIREO_OK ? VIREO_CONNECTION_STAGE_NONE : VIREO_CONNECTION_STAGE_QUERY_PEER));
        CHECK(error.system_errno==(result==VIREO_RESULT_IO ? script->cause : 0));
        CHECK(error.tls_error.system_errno==0);
    }
}

static void failure_contracts(void)
{
    int pair[2]; CHECK(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair)==0);
    vireo_connection_t *c=NULL; int const original=pair[0];
    EXPECT(vireo_connection_create(&options,&pair[0],&c,NULL),VIREO_OK);
    vireo_connection_peer_t output; memset(&output,0xA5,sizeof(output));
    unsigned char before[sizeof(output)]; memcpy(before,&output,sizeof(output));
    vireo_connection_error_t error;
    EXPECT(vireo_connection_peer_query(c,&output,&error),VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(before,&output,sizeof(output))==0); CHECK(error.system_errno==0);
    query_script_t script={.fd=original,.cause=EDOM};
    EXPECT(vireo_connection_peer_query_with(NULL,&output,&error,query,&script),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_connection_peer_query_with(c,NULL,&error,query,&script),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_connection_peer_query_with(c,&output,&error,NULL,&script),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(script.calls==0); CHECK(error.stage==0 && error.system_errno==0);
    CHECK(memcmp(before,&output,sizeof(output))==0);
    int const errors[]={EINTR,ENOTCONN,EBADF,EIO};
    for (size_t i=0;i<sizeof(errors)/sizeof(errors[0]);++i) {
        script.returned=-1; script.cause=errors[i];
        script_case(c,&script,VIREO_RESULT_IO,true); script_case(c,&script,VIREO_RESULT_IO,false);
    }
    script.returned=1; script_case(c,&script,VIREO_RESULT_INTERNAL,true);
    script.returned=-2; script_case(c,&script,VIREO_RESULT_INTERNAL,true);
    script.returned=0;
    socklen_t const bad_sizes[]={0,1,(socklen_t)sizeof(struct sockaddr_storage)+1};
    for (size_t i=0;i<sizeof(bad_sizes)/sizeof(bad_sizes[0]);++i) {
        script.size=bad_sizes[i]; script_case(c,&script,VIREO_RESULT_INTERNAL,true);
    }
    for (int family=AF_INET;family<=AF_INET6;family+=AF_INET6-AF_INET) {
        script.address.ss_family=(sa_family_t)family;
        socklen_t const valid=(socklen_t)(family==AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        script.size=valid-1; script_case(c,&script,VIREO_RESULT_INTERNAL,true);
        script.size=valid+1; script_case(c,&script,VIREO_RESULT_INTERNAL,true);
        script.size=valid; script_case(c,&script,VIREO_OK,true);
    }
    script.address.ss_family=(sa_family_t)65535; script.size=2;
    script_case(c,&script,VIREO_RESULT_NOT_FOUND,true);
    EXPECT(vireo_connection_destroy(&c,NULL),VIREO_OK); CHECK(close(pair[1])==0);
}

static void native_connection(int family, bool mapped, bool tls)
{
    struct sockaddr_storage address={0}; socklen_t size;
    int listener_fd=listener(family,mapped,&address,&size);
    int peer_fd=connect_peer(&address,size,mapped,NULL);
    int fd=accept4(listener_fd,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC); CHECK(fd>=0);
    vireo_connection_t *c=NULL; vireo_tls_context_t *context=NULL;
    if (tls) {
        vireo_tls_context_options_t const context_options={fixture_leaf,sizeof(fixture_leaf)-1,
            fixture_key,sizeof(fixture_key)-1,4096};
        vireo_tls_connection_options_t const tls_options={4096};
        EXPECT(vireo_tls_context_create_server(&context_options,&context,NULL),VIREO_OK);
        EXPECT(vireo_connection_create_tls_server(context,&tls_options,&fd,&c,NULL),VIREO_OK);
    } else EXPECT(vireo_connection_create(&options,&fd,&c,NULL),VIREO_OK);
    CHECK(fd==-1); vireo_connection_peer_t peer; vireo_connection_error_t error;
    vireo_connection_info_t before,after;
    EXPECT(vireo_connection_inspect(c,&before),VIREO_OK);
    uint8_t const *view=NULL; size_t bytes=0;
    if (!tls) EXPECT(vireo_connection_read_peek(c,&view,&bytes),VIREO_OK);
    EXPECT(vireo_connection_peer_query(c,&peer,&error),VIREO_OK);
    equal_peer(peer,expected_peer(family,mapped,NULL)); CHECK(error.stage==0);
    EXPECT(vireo_connection_peer_query(c,&peer,NULL),VIREO_OK);
    EXPECT(vireo_connection_inspect(c,&after),VIREO_OK);
    CHECK(before.transport==after.transport && before.read_buffer.readable_size==after.read_buffer.readable_size);
    if (!tls) {
        uint8_t const *view_after=NULL; size_t bytes_after=99;
        EXPECT(vireo_connection_read_peek(c,&view_after,&bytes_after),VIREO_OK);
        CHECK(view==view_after && bytes==bytes_after);
    } else CHECK(before.transport==VIREO_CONNECTION_TRANSPORT_TLS);
    CHECK(close(peer_fd)==0);
    /* 对端关闭不伪装为本地fd已失效，不主动recv/判断TLS认证。 */
    EXPECT(vireo_connection_peer_query(c,&peer,NULL),VIREO_OK);
    equal_peer(peer,expected_peer(family,mapped,NULL));
    EXPECT(vireo_connection_destroy(&c,NULL),VIREO_OK);
    if (context!=NULL) EXPECT(vireo_tls_context_destroy(&context,NULL),VIREO_OK);
    CHECK(close(listener_fd)==0);
}

static vireo_connection_pool_lease_t admit(vireo_tcp_server_t *server)
{
    vireo_connection_pool_lease_t client={0};
    vireo_tcp_server_admit_budget_t const budget={1,1}; vireo_tcp_server_admit_info_t info;
    EXPECT(vireo_tcp_server_admit_batch(server,&options,&budget,&client,1,&info,NULL),VIREO_OK);
    CHECK(info.admitted_count==1); return client;
}
static void server_and_admission(void)
{
    vireo_tcp_server_options_t const server_options={1,1,1048576,1024};
    vireo_tcp_server_t *server=NULL; EXPECT(vireo_tcp_server_create(&server_options,&server,NULL),VIREO_OK);
    struct sockaddr_storage address={0}; socklen_t size;
    int fd=listener(AF_INET,false,&address,&size); vireo_acceptor_t *acceptor=NULL;
    vireo_acceptor_options_t const accept_options={4096};
    EXPECT(vireo_acceptor_create(&accept_options,&fd,&acceptor,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(server,&acceptor,NULL),VIREO_OK);
    int peer_fd=connect_peer(&address,size,false,"127.0.0.1");
    vireo_connection_pool_lease_t client=admit(server), stale=client;
    vireo_connection_peer_t peer; vireo_tcp_server_client_error_t error;
    EXPECT(vireo_tcp_server_client_peer_query(server,client,&peer,&error),VIREO_OK);
    equal_peer(peer,expected_peer(AF_INET,false,"127.0.0.1")); CHECK(error.primary.stage==0);
    vireo_auth_login_admission_t *admission=NULL;
    vireo_auth_login_admission_options_t policy=VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    policy.account.burst_tokens=1;
    EXPECT(vireo_auth_login_admission_create(&policy,0,&admission),VIREO_OK);
    unsigned char device[VIREO_AUTH_LOGIN_DEVICE_BYTES]={0};
    vireo_auth_login_peer_t trusted={.family=peer.family}; memcpy(trusted.address,peer.address,16);
    vireo_rate_limit_decision_t decision;
    EXPECT(vireo_auth_login_admission_check(admission,0,&trusted,"Alice_7",7,device,&decision),VIREO_OK);
    CHECK(decision.outcome==VIREO_RATE_LIMIT_ADMITTED);
    EXPECT(vireo_tcp_server_release_client(server,&client,NULL),VIREO_OK); CHECK(close(peer_fd)==0);
    peer_fd=connect_peer(&address,size,false,"127.0.0.2"); client=admit(server);
    CHECK(client.pool_id==stale.pool_id && client.slot_index==stale.slot_index && client.generation!=stale.generation);
    memset(&peer,0xA5,sizeof(peer)); unsigned char before[sizeof(peer)]; memcpy(before,&peer,sizeof(peer));
    EXPECT(vireo_tcp_server_client_peer_query(server,stale,&peer,&error),VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(before,&peer,sizeof(peer))==0); CHECK(error.primary.stage==VIREO_TCP_SERVER_CLIENT_LOOKUP);
    EXPECT(vireo_tcp_server_client_peer_query(server,client,&peer,&error),VIREO_OK);
    equal_peer(peer,expected_peer(AF_INET,false,"127.0.0.2"));
    trusted.family=peer.family; memcpy(trusted.address,peer.address,16); ++device[0];
    EXPECT(vireo_auth_login_admission_check(admission,0,&trusted,"ALICE_7",7,device,&decision),VIREO_OK);
    CHECK(decision.outcome==VIREO_RATE_LIMIT_THROTTLED);
    EXPECT(vireo_tcp_server_client_peer_query(NULL,client,&peer,&error),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_client_peer_query(server,client,NULL,&error),VIREO_RESULT_INVALID_ARGUMENT);
    vireo_connection_pool_lease_t invalid=client; ++invalid.pool_id;
    EXPECT(vireo_tcp_server_client_peer_query(server,invalid,&peer,&error),VIREO_RESULT_INVALID_ARGUMENT);
    invalid=client; invalid.slot_index=1;
    EXPECT(vireo_tcp_server_client_peer_query(server,invalid,&peer,&error),VIREO_RESULT_RANGE);
    EXPECT(vireo_tcp_server_client_peer_query(server,(vireo_connection_pool_lease_t){0},&peer,NULL),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_login_admission_destroy(&admission),VIREO_OK);
    EXPECT(vireo_tcp_server_release_client(server,&client,NULL),VIREO_OK); CHECK(close(peer_fd)==0);
    EXPECT(vireo_tcp_server_destroy(&server,NULL),VIREO_OK);
}

int main(void)
{
    size_t before=fd_count(); failure_contracts();
    native_connection(AF_INET,false,false); native_connection(AF_INET6,false,false);
    native_connection(AF_INET6,true,false); native_connection(AF_INET,false,true);
    native_connection(AF_INET6,false,true); native_connection(AF_INET6,true,true);
    server_and_admission(); CHECK(fd_count()==before);
    printf("connection_peer: %zu checks, real IPv4/IPv6/mapped RAW+TLS resources, stale lease, LOGIN quota, fd %zu -> %zu\n",checks,before,before);
    return EXIT_SUCCESS;
}
