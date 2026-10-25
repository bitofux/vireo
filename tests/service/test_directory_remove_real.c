/*
 * PROJECT : VIREO
 * FILE    : test_directory_remove_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-25
 * BRIEF   : 验证remove service与真实MySQL回执/领域拒绝。
 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <vireo/service/directory_remove.h>

#define CHECK(call, want)                                                                     \
    do {                                                                                      \
        vireo_result_t got_ = (call);                                                         \
        if (got_ != (want)) {                                                                 \
            fprintf(stderr, "line %d result %d want %d\n", __LINE__, (int)got_, (int)(want)); \
            abort();                                                                          \
        }                                                                                     \
    } while (0)

int main(int argc, char **argv) {
    assert(argc == 5);
    char password[1026];
    FILE *credentials = fopen(argv[3], "r");
    assert(credentials != NULL && fgets(password, (int)sizeof(password), credentials) != NULL);
    assert(fclose(credentials) == 0);
    password[strcspn(password, "\n")] = 0;
    struct sigaction action = {0};
    action.sa_handler = SIG_IGN;
    assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    vireo_mysql_runtime_t *runtime = NULL;
    vireo_mysql_thread_t *thread = NULL;
    vireo_mysql_pool_t *pool = NULL;
    vireo_mysql_connection_t *observer = NULL;
    vireo_mysql_user_repository_t *users = NULL;
    vireo_mysql_node_repository_t *nodes = NULL;
    CHECK(vireo_mysql_runtime_create(&runtime, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime, &thread, NULL), VIREO_OK);
    vireo_mysql_connection_options_t connection = {argv[1], argv[2], password, argv[4], 3, 3, 3};
    const vireo_mysql_migration_t *catalog = NULL;
    size_t migration_count = 0;
    CHECK(vireo_mysql_schema_catalog(&catalog, &migration_count), VIREO_OK);
    vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread, &connection, catalog, migration_count, &migration,
                                      NULL),
          VIREO_OK);
    CHECK(vireo_mysql_connection_open(thread, &connection, &observer, NULL), VIREO_OK);
    const vireo_mysql_pool_options_t pool_options = {connection, 3, 3, VIREO_MYSQL_POOL_MEMORY_MAX};
    CHECK(vireo_mysql_pool_create(thread, &pool_options, &pool, NULL), VIREO_OK);
    const vireo_password_policy_t policy = VIREO_PASSWORD_POLICY_DEFAULT;
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &users, NULL), VIREO_OK);
    CHECK(vireo_mysql_node_repository_create(thread, pool, &nodes, NULL), VIREO_OK);

    char phc[VIREO_PASSWORD_ENCODED_CAPACITY];
    size_t phc_length = 0;
    CHECK(vireo_password_hash_create(&policy, "Correct!7", 9, phc, sizeof(phc), &phc_length),
          VIREO_OK);
    struct timespec now;
    assert(clock_gettime(CLOCK_REALTIME, &now) == 0);
    uint64_t issued_at = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    vireo_mysql_registration_input_t registration = {.username = "remove_service",
                                                     .username_length = 14,
                                                     .username_key = "remove_service",
                                                     .username_key_length = 14,
                                                     .password_hash = phc,
                                                     .password_hash_length = phc_length,
                                                     .occurred_at_ms = issued_at - 10000,
                                                     .request_id = {1}};
    vireo_mysql_registration_report_t registered;
    CHECK(vireo_mysql_user_repository_register(users, &registration, 0, &registered, NULL),
          VIREO_OK);
    vireo_mysql_login_input_t login = {.user_id = registered.user_id,
                                       .verified_password_hash = phc,
                                       .verified_password_hash_length = phc_length,
                                       .issued_at_ms = issued_at,
                                       .expires_at_ms = issued_at + 3600000,
                                       .request_id = {2},
                                       .token_digest = {.bytes = {3}}};
    vireo_mysql_login_report_t logged;
    CHECK(vireo_mysql_user_repository_login(users, &login, 0, &logged, NULL), VIREO_OK);
    const vireo_mysql_node_actor_t actor = {registered.user_id, logged.session_id};

    vireo_mysql_node_mkdir_input_t create = {.parent_id = registered.root_node_id,
                                             .name = (const unsigned char *)"remove",
                                             .name_length = 6,
                                             .request_id = {4}};
    vireo_mysql_node_mkdir_report_t created;
    CHECK(vireo_mysql_node_repository_mkdir(nodes, &actor, &create, 0, &created, NULL), VIREO_OK);
    const vireo_mysql_node_remove_once_input_t input = {
        .node_id = created.node.id, .idempotency_key = {5}, .request_id = {6}};
    vireo_directory_remove_result_t applied, recovered;
    CHECK(vireo_directory_service_remove(nodes, &actor, &input, 0, &applied, NULL), VIREO_OK);
    assert(applied.outcome == VIREO_DIRECTORY_REMOVE_APPLIED && applied.repository_called &&
           applied.repository_result == VIREO_OK && applied.node_id == created.node.id &&
           applied.audit_id != 0 &&
           memcmp(applied.idempotency_key, input.idempotency_key, sizeof(input.idempotency_key)) ==
               0 &&
           applied.repository.effect == VIREO_MYSQL_NODE_REMOVE_EFFECT_APPLIED);
    CHECK(vireo_directory_service_remove(nodes, &actor, &input, 0, &recovered, NULL), VIREO_OK);
    assert(recovered.outcome == VIREO_DIRECTORY_REMOVE_RECOVERED &&
           recovered.audit_id == applied.audit_id &&
           recovered.deleted_at_ms == applied.deleted_at_ms && recovered.repository_called &&
           recovered.repository.effect == VIREO_MYSQL_NODE_REMOVE_EFFECT_RECOVERED &&
           memcmp(recovered.idempotency_key, input.idempotency_key,
                  sizeof(input.idempotency_key)) == 0);

    const vireo_mysql_node_remove_once_input_t root = {
        .node_id = registered.root_node_id, .idempotency_key = {7}, .request_id = {8}};
    vireo_directory_remove_result_t rejected;
    CHECK(vireo_directory_service_remove(nodes, &actor, &root, 0, &rejected, NULL),
          VIREO_RESULT_DATABASE);
    assert(rejected.outcome == VIREO_DIRECTORY_REMOVE_ROOT_UNDELETABLE &&
           rejected.repository_called && rejected.repository_result == VIREO_RESULT_DATABASE &&
           rejected.node_id == 0 &&
           rejected.repository.issue == VIREO_MYSQL_NODE_ROOT_UNDELETABLE &&
           rejected.repository.rollback_confirmed);

    CHECK(vireo_mysql_node_repository_destroy(&nodes, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_destroy(&users, NULL), VIREO_OK);
    bool closed = false;
    CHECK(vireo_mysql_pool_close(pool, &closed, NULL), VIREO_OK);
    assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread, &observer), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    memset(phc, 0, sizeof(phc));
    memset(password, 0, sizeof(password));
    puts("PASS real MySQL remove service APPLIED/RECOVERED/root refusal");
    return 0;
}
