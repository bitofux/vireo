/*
- PROJECT : VIREO
- FILE    : test_connection_receive_clear.c
- AUTHOR  : bitofux
- DATE    : 2026-10-19
- BRIEF   : 此模块负责：同次接收循环的栈暂存清理与实际FIFO数据保持
 */
#define _GNU_SOURCE
#include "net/connection_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while (0)
typedef struct fixture { unsigned int calls; unsigned int ending; } fixture_t;
static void *allocate(void *ctx, size_t n) { (void)ctx; return malloc(n); }
static void deallocate(void *ctx, void *p) { (void)ctx; free(p); }
static int flags_get(void *ctx, int fd, int command) { (void)ctx; return fcntl(fd, command); }
static int type_get(void *ctx, int fd, int *out)
{ (void)ctx; socklen_t n = sizeof(*out); return getsockopt(fd, SOL_SOCKET, SO_TYPE, out, &n); }
static int peer(void *ctx, int fd)
{ (void)ctx; struct sockaddr_storage a; socklen_t n = sizeof(a); return getpeername(fd, (struct sockaddr *)&a, &n); }
static int close_fd(void *ctx, int fd) { (void)ctx; return close(fd); }
static vireo_result_t create_buffer(void *ctx, size_t n, vireo_buffer_t **out)
{ (void)ctx; return vireo_buffer_create(n, out); }
static void destroy_buffer(void *ctx, vireo_buffer_t **out)
{ (void)ctx; CHECK(vireo_buffer_destroy(out) == VIREO_OK); }
static ssize_t receive_bytes(void *ctx, int fd, void *bytes, size_t request, int flags)
{
    fixture_t *f = ctx; (void)fd; CHECK(flags == MSG_DONTWAIT && request >= 8);
    uint8_t *p = bytes;
    if (f->calls != 0) for (size_t i = 0; i < 8; ++i) CHECK(p[i] == 0);
    /* 当前receive栈帧仍存活，只读取本次callback获得的有效8字节，不保存旧指针。 */
    ++f->calls;
    if (f->calls <= 2) { memset(bytes, (int)(0x30 + f->calls), 8); return 8; }
    if (f->ending == 0) { errno = EAGAIN; return -1; }
    if (f->ending == 1) return 0;
    errno = EIO; return -1;
}
static ssize_t send_bytes(void *ctx, int fd, void const *bytes, size_t n, int flags)
{ (void)ctx; return send(fd, bytes, n, flags); }
int main(void)
{
    for (unsigned int ending = 0; ending < 3; ++ending) {
        fixture_t f = {.ending = ending}; int sockets[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0);
        vireo_connection_ops_t ops = {&f,allocate,deallocate,flags_get,type_get,peer,close_fd,
            create_buffer,destroy_buffer,receive_bytes,send_bytes};
        vireo_connection_options_t options = {64,64,128}; vireo_connection_t *c = NULL;
        CHECK(vireo_connection_create_with_ops(&options, &sockets[0], &ops, &c, NULL) == VIREO_OK);
        vireo_connection_receive_budget_t budget = {64,4}; vireo_connection_receive_info_t info;
        errno = ECHILD;
        CHECK(vireo_connection_receive(c, &budget, &info, NULL) == (ending == 2 ? VIREO_RESULT_IO : VIREO_OK));
        CHECK(errno == ECHILD && f.calls == 3 && info.received_bytes == 16);
        uint8_t const *p = NULL; size_t n = 0;
        CHECK(vireo_connection_read_peek(c, &p, &n) == VIREO_OK && n == 16);
        for (size_t i = 0; i < 16; ++i) CHECK(p[i] == (i < 8 ? 0x31 : 0x32));
        CHECK(vireo_connection_destroy(&c, NULL) == VIREO_OK); CHECK(close(sockets[1]) == 0);
    }
    puts("RAW clear: two confirmed copies before EAGAIN, EOF and IO error passed"); return 0;
}
