/* PROJECT: VIREO; FILE: auth_session.c; AUTHOR: bitofux; DATE: 2026-10-20. */
#include "auth_session_internal.h"
#include <vireo/base/checked.h>
#include <vireo/base/secure_clear.h>
#include <openssl/rand.h>
#include <errno.h>
#include <stdlib.h>

typedef struct session_slot {
    vireo_connection_pool_lease_t client;
    bool active, pending;
    vireo_auth_session_identity_t identity, candidate;
    uint32_t handle;
    vireo_auth_session_ticket_t ticket;
} session_slot_t;
struct vireo_auth_sessions {
    vireo_tcp_server_t *server; /* 短借server的生命周期由caller维持，不拥有。 */
    size_t capacity, allocation_bytes;
    uint64_t serial;
    uint64_t last_resume_instance, resume_cutoff; /* Reactor独占，不随连接forget清除。 */
    session_slot_t slots[];
};
static bool lease_valid(vireo_connection_pool_lease_t c) { return c.pool_id != 0 && c.generation != 0; }
static bool same(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b)
{ return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation; }
static int native_random(void *context, unsigned char out[4])
{ (void)context; return RAND_priv_bytes(out, 4); }

vireo_result_t vireo_auth_sessions_create(vireo_tcp_server_t *server,
    vireo_auth_sessions_options_t const *options, vireo_auth_sessions_t **out)
{
    int const saved_errno = errno; vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (server == NULL || options == NULL || out == NULL || *out != NULL || options->max_memory_bytes == 0) goto done;
    rc = VIREO_RESULT_RANGE; if (options->max_memory_bytes > VIREO_AUTH_SESSION_MEMORY_MAX) goto done;
    vireo_tcp_server_info_t info;
    rc = vireo_tcp_server_inspect(server, &info); if (rc != VIREO_OK) goto done;
    size_t bytes = 0;
    rc = vireo_checked_size_mul(info.connection_capacity, sizeof(session_slot_t), &bytes); if (rc != VIREO_OK) goto done;
    rc = vireo_checked_size_add(bytes, sizeof(vireo_auth_sessions_t), &bytes); if (rc != VIREO_OK) goto done;
    rc = VIREO_RESULT_RANGE; if (bytes > options->max_memory_bytes) goto done;
    vireo_auth_sessions_t *t = calloc(1, bytes); rc = VIREO_RESULT_NO_MEMORY; if (t == NULL) goto done;
    t->server = server; t->capacity = info.connection_capacity; t->allocation_bytes = bytes;
    *out = t; rc = VIREO_OK;
done: errno = saved_errno; return rc;
}

vireo_result_t vireo_auth_session_reserve_with(vireo_auth_sessions_t *t,
    vireo_connection_pool_lease_t client, vireo_auth_session_identity_t const *identity,
    vireo_auth_session_ticket_t *out, vireo_auth_handle_random_fn random, void *context)
{
    int const saved_errno = errno; unsigned char bytes[4] = {0};
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (t == NULL || identity == NULL || out == NULL || random == NULL || !lease_valid(client) ||
        identity->user_id == 0 || identity->session_id == 0 || identity->revoked ||
        identity->expires_at_ms <= identity->issued_at_ms) goto done;
    vireo_tcp_server_client_info_t info;
    rc = vireo_tcp_server_client_inspect(t->server, client, &info); if (rc != VIREO_OK) goto done;
    rc = VIREO_RESULT_RANGE; if (client.slot_index >= t->capacity) goto done;
    session_slot_t *s = &t->slots[client.slot_index];
    rc = VIREO_RESULT_BUSY; if (same(s->client, client) && s->pending) goto done;
    rc = VIREO_RESULT_OVERFLOW; if (t->serial == UINT64_MAX) goto done;
    rc = VIREO_RESULT_IO; if (random(context, bytes) != 1) goto done;
    uint32_t const handle = (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | bytes[3];
    rc = VIREO_RESULT_BUSY; if (handle == 0) goto done;
    for (size_t i = 0; i < t->capacity; ++i)
        if ((t->slots[i].active && t->slots[i].handle == handle) ||
            (t->slots[i].pending && t->slots[i].ticket.handle == handle)) goto done;
    if (!same(s->client, client)) *s = (session_slot_t){.client = client};
    s->candidate = *identity; s->pending = true;
    s->ticket = (vireo_auth_session_ticket_t){client, ++t->serial, handle};
    *out = s->ticket; rc = VIREO_OK;
done: (void)vireo_secure_clear(bytes, sizeof(bytes)); errno = saved_errno; return rc;
}
vireo_result_t vireo_auth_session_reserve(vireo_auth_sessions_t *t,
    vireo_connection_pool_lease_t c, vireo_auth_session_identity_t const *i, vireo_auth_session_ticket_t *out)
{ return vireo_auth_session_reserve_with(t, c, i, out, native_random, NULL); }
static vireo_result_t ticket_slot(vireo_auth_sessions_t *t, vireo_auth_session_ticket_t ticket, session_slot_t **out)
{
    if (t == NULL || !lease_valid(ticket.client) || ticket.serial == 0 || ticket.handle == 0) return VIREO_RESULT_INVALID_ARGUMENT;
    if (ticket.client.slot_index >= t->capacity) return VIREO_RESULT_NOT_FOUND;
    session_slot_t *s = &t->slots[ticket.client.slot_index];
    if (!s->pending || !same(s->client, ticket.client) || s->ticket.serial != ticket.serial || s->ticket.handle != ticket.handle)
        return VIREO_RESULT_NOT_FOUND;
    *out = s; return VIREO_OK;
}
vireo_result_t vireo_auth_session_commit(vireo_auth_sessions_t *t, vireo_auth_session_ticket_t ticket)
{
    session_slot_t *s = NULL; vireo_result_t rc = ticket_slot(t, ticket, &s); if (rc != VIREO_OK) return rc;
    s->identity = s->candidate; s->handle = ticket.handle; s->active = true;
    s->pending = false; s->candidate = (vireo_auth_session_identity_t){0}; s->ticket = (vireo_auth_session_ticket_t){0}; return VIREO_OK;
}
vireo_result_t vireo_auth_session_abort(vireo_auth_sessions_t *t, vireo_auth_session_ticket_t ticket)
{
    session_slot_t *s = NULL; vireo_result_t rc = ticket_slot(t, ticket, &s); if (rc != VIREO_OK) return rc;
    s->pending = false; s->candidate = (vireo_auth_session_identity_t){0}; s->ticket = (vireo_auth_session_ticket_t){0}; return VIREO_OK;
}
vireo_result_t vireo_auth_session_lookup(vireo_auth_sessions_t const *t,
    vireo_connection_pool_lease_t client, uint32_t handle, uint64_t now, vireo_auth_session_identity_t *out)
{
    if (t == NULL || out == NULL || !lease_valid(client) || handle == 0) return VIREO_RESULT_INVALID_ARGUMENT;
    vireo_tcp_server_client_info_t info; vireo_result_t rc = vireo_tcp_server_client_inspect(t->server, client, &info);
    if (rc != VIREO_OK) return rc;
    if (client.slot_index >= t->capacity) return VIREO_RESULT_RANGE;
    session_slot_t const *s = &t->slots[client.slot_index];
    if (!same(s->client, client) || !s->active || s->handle != handle) return VIREO_RESULT_NOT_FOUND;
    if (s->identity.revoked) return VIREO_RESULT_CANCELLED;
    if (now >= s->identity.expires_at_ms) return VIREO_RESULT_TIMEOUT;
    *out = s->identity; return VIREO_OK;
}
vireo_result_t vireo_auth_session_revoke(vireo_auth_sessions_t *t, uint64_t session_id)
{
    if (t == NULL || session_id == 0) return VIREO_RESULT_INVALID_ARGUMENT;
    bool found = false;
    for (size_t i = 0; i < t->capacity; ++i) {
        session_slot_t *s = &t->slots[i];
        if (s->active && s->identity.session_id == session_id) { s->identity.revoked = true; found = true; }
        if (s->pending && s->candidate.session_id == session_id) { s->candidate.revoked = true; found = true; }
    }
    return found ? VIREO_OK : VIREO_RESULT_NOT_FOUND;
}
vireo_result_t vireo_auth_session_forget(vireo_auth_sessions_t *t, vireo_connection_pool_lease_t client)
{
    if (t == NULL || !lease_valid(client)) return VIREO_RESULT_INVALID_ARGUMENT;
    if (client.slot_index >= t->capacity) return VIREO_RESULT_NOT_FOUND;
    session_slot_t *s = &t->slots[client.slot_index];
    if (!same(s->client, client)) return VIREO_RESULT_NOT_FOUND;
    (void)vireo_secure_clear(s, sizeof(*s)); return VIREO_OK;
}
vireo_result_t vireo_auth_sessions_destroy(vireo_auth_sessions_t **owner)
{
    int const saved_errno = errno; vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (owner == NULL) goto done;
    rc = VIREO_OK; if (*owner == NULL) goto done;
    vireo_auth_sessions_t *t = *owner;
    for (size_t i = 0; i < t->capacity; ++i) if (t->slots[i].pending) { rc = VIREO_RESULT_BUSY; goto done; }
    size_t const bytes = t->allocation_bytes; (void)vireo_secure_clear(t, bytes); free(t); *owner = NULL;
done: errno = saved_errno; return rc;
}


vireo_result_t vireo_auth_session_note_resume(vireo_auth_sessions_t *t,uint64_t id)
{
    if (!t || !id || id<=t->last_resume_instance) return VIREO_RESULT_INVALID_ARGUMENT;
    t->last_resume_instance=id; return VIREO_OK;
}
vireo_result_t vireo_auth_session_check_resume(vireo_auth_sessions_t const *t,uint64_t id)
{
    if (!t || !id) return VIREO_RESULT_INVALID_ARGUMENT;
    if (id>t->last_resume_instance) return VIREO_RESULT_NOT_FOUND;
    return id<=t->resume_cutoff?VIREO_RESULT_BUSY:VIREO_OK;
}
vireo_result_t vireo_auth_session_apply_logout(vireo_auth_sessions_t *t,uint64_t id)
{
    if (!t || !id) return VIREO_RESULT_INVALID_ARGUMENT;
    t->resume_cutoff=t->last_resume_instance;
    vireo_result_t const rc=vireo_auth_session_revoke(t,id);
    return rc==VIREO_RESULT_NOT_FOUND?VIREO_OK:rc;
}
