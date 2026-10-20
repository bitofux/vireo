/* 仅新Session组件随机边界；不借其他模块私有合同。 */
#ifndef VIREO_NET_AUTH_SESSION_INTERNAL_H
#define VIREO_NET_AUTH_SESSION_INTERNAL_H
#include <vireo/net/auth_session.h>
typedef int (*vireo_auth_handle_random_fn)(void *, unsigned char [4]);
vireo_result_t vireo_auth_session_reserve_with(vireo_auth_sessions_t *table,
    vireo_connection_pool_lease_t client, vireo_auth_session_identity_t const *identity,
    vireo_auth_session_ticket_t *out, vireo_auth_handle_random_fn random, void *context);
#endif
