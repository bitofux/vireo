/*
 * PROJECT : VIREO
 * FILE    : mysql_schema.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : v1认证、v2节点、v3审计、v4上传及v5永久块/manifest、v6节点/副本及v7下载、v8清理任务及v9目录成功回执可信DDL；精确字节属于持久迁移hash合同。
 */
#include <vireo/persistence/mysql_schema.h>

static const char users_sql[] =
    "CREATE TABLE users (\n"
    "    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
    "    username VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,\n"
    "    username_key VARBINARY(256) NOT NULL,\n"
    "    password_hash VARBINARY(127) NOT NULL,\n"
    "    status TINYINT UNSIGNED NOT NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    updated_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    last_login_at_ms BIGINT UNSIGNED NULL,\n"
    "    PRIMARY KEY (id),\n"
    "    UNIQUE KEY users_username_key_unique (username_key),\n"
    "    KEY users_status_id (status,id),\n"
    "    CONSTRAINT users_username_length CHECK (CHAR_LENGTH(username) BETWEEN 1 AND 64) ENFORCED,\n"
    "    CONSTRAINT users_username_key_length CHECK (OCTET_LENGTH(username_key) BETWEEN 1 AND 256) ENFORCED,\n"
    "    CONSTRAINT users_password_hash_length CHECK (OCTET_LENGTH(password_hash) BETWEEN 1 AND 127) ENFORCED,\n"
    "    CONSTRAINT users_status_valid CHECK (status IN (1,2)) ENFORCED,\n"
    "    CONSTRAINT users_updated_order CHECK (updated_at_ms>=created_at_ms) ENFORCED,\n"
    "    CONSTRAINT users_last_login_order CHECK (last_login_at_ms IS NULL OR last_login_at_ms>=created_at_ms) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const char sessions_sql[] =
    "CREATE TABLE sessions (\n"
    "    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
    "    user_id BIGINT UNSIGNED NOT NULL,\n"
    "    token_digest VARBINARY(32) NOT NULL,\n"
    "    status TINYINT UNSIGNED NOT NULL,\n"
    "    issued_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    expires_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    revoked_at_ms BIGINT UNSIGNED NULL,\n"
    "    last_seen_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    PRIMARY KEY (id),\n"
    "    UNIQUE KEY sessions_token_digest_unique (token_digest),\n"
    "    KEY sessions_user_status_expiry (user_id,status,expires_at_ms,id),\n"
    "    KEY sessions_status_expiry (status,expires_at_ms,id),\n"
    "    CONSTRAINT sessions_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT sessions_digest_length CHECK (OCTET_LENGTH(token_digest)=32) ENFORCED,\n"
    "    CONSTRAINT sessions_status_valid CHECK (status IN (1,2)) ENFORCED,\n"
    "    CONSTRAINT sessions_expiry_order CHECK (expires_at_ms>issued_at_ms) ENFORCED,\n"
    "    CONSTRAINT sessions_last_seen_order CHECK (last_seen_at_ms>=issued_at_ms AND last_seen_at_ms<=expires_at_ms) ENFORCED,\n"
    "    CONSTRAINT sessions_revocation_valid CHECK ((status=1 AND revoked_at_ms IS NULL) OR (status=2 AND revoked_at_ms IS NOT NULL AND revoked_at_ms>=issued_at_ms)) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const vireo_mysql_migration_step_t initial_steps[] = {
    {users_sql, sizeof(users_sql)-1},
    {sessions_sql, sizeof(sessions_sql)-1}
};

static const char objects_sql[] =
    "CREATE TABLE objects (\n"
    "    object_hash BINARY(32) NOT NULL,\n"
    "    size BIGINT UNSIGNED NOT NULL,\n"
    "    state TINYINT UNSIGNED NOT NULL,\n"
    "    ref_count BIGINT UNSIGNED NOT NULL,\n"
    "    storage_class TINYINT UNSIGNED NOT NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    updated_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    verified_at_ms BIGINT UNSIGNED NULL,\n"
    "    PRIMARY KEY (object_hash),\n"
    "    KEY objects_state_updated (state,updated_at_ms,object_hash),\n"
    "    KEY objects_refs_state (ref_count,state,object_hash),\n"
    "    CONSTRAINT objects_state_valid CHECK (state IN (1,2,3,4)) ENFORCED,\n"
    "    CONSTRAINT objects_storage_class_valid CHECK (storage_class=1) ENFORCED,\n"
    "    CONSTRAINT objects_updated_order CHECK (updated_at_ms>=created_at_ms) ENFORCED,\n"
    "    CONSTRAINT objects_verified_required CHECK (state<>2 OR verified_at_ms IS NOT NULL) ENFORCED,\n"
    "    CONSTRAINT objects_verified_order CHECK (verified_at_ms IS NULL OR (verified_at_ms>=created_at_ms AND verified_at_ms<=updated_at_ms)) ENFORCED,\n"
    "    CONSTRAINT objects_deleting_unreferenced CHECK (state<>3 OR ref_count=0) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const char file_nodes_sql[] =
    "CREATE TABLE file_nodes (\n"
    "    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
    "    owner_id BIGINT UNSIGNED NOT NULL,\n"
    "    parent_id BIGINT UNSIGNED NULL,\n"
    "    name VARBINARY(255) NOT NULL,\n"
    "    name_hash BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(name,256))) STORED,\n"
    "    node_type TINYINT UNSIGNED NOT NULL,\n"
    "    state TINYINT UNSIGNED NOT NULL,\n"
    "    object_hash BINARY(32) NULL,\n"
    "    size BIGINT UNSIGNED NOT NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    updated_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    deleted_at_ms BIGINT UNSIGNED NULL,\n"
    "    live_name VARBINARY(255) GENERATED ALWAYS AS (CASE WHEN parent_id IS NOT NULL AND state IN (1,2) THEN name ELSE NULL END) STORED,\n"
    "    active_root_owner BIGINT UNSIGNED GENERATED ALWAYS AS (CASE WHEN parent_id IS NULL AND state=2 THEN owner_id ELSE NULL END) STORED,\n"
    "    PRIMARY KEY (id),\n"
    "    UNIQUE KEY file_nodes_owner_id_unique (owner_id,id),\n"
    "    UNIQUE KEY file_nodes_live_name_unique (owner_id,parent_id,live_name),\n"
    "    UNIQUE KEY file_nodes_active_root_unique (active_root_owner),\n"
    "    KEY file_nodes_parent_state_id (owner_id,parent_id,state,id),\n"
    "    KEY file_nodes_owner_state_deleted (owner_id,state,deleted_at_ms,id),\n"
    "    KEY file_nodes_object_id (object_hash,id),\n"
    "    CONSTRAINT file_nodes_owner_fk FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT file_nodes_parent_fk FOREIGN KEY (owner_id,parent_id) REFERENCES file_nodes(owner_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT file_nodes_object_fk FOREIGN KEY (object_hash) REFERENCES objects(object_hash) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT file_nodes_type_valid CHECK (node_type IN (1,2)) ENFORCED,\n"
    "    CONSTRAINT file_nodes_state_valid CHECK (state IN (1,2,3)) ENFORCED,\n"
    "    CONSTRAINT file_nodes_location_valid CHECK ((parent_id IS NULL AND OCTET_LENGTH(name)=0 AND node_type=1 AND state=2) OR (parent_id IS NOT NULL AND OCTET_LENGTH(name) BETWEEN 1 AND 255 AND name NOT IN (X'2E',X'2E2E') AND LOCATE(X'2F',name)=0 AND LOCATE(X'00',name)=0)) ENFORCED,\n"
    "    CONSTRAINT file_nodes_payload_valid CHECK ((node_type=1 AND state IN (2,3) AND object_hash IS NULL AND size=0) OR (node_type=2 AND (state IN (1,3) OR (state=2 AND object_hash IS NOT NULL)))) ENFORCED,\n"
    "    CONSTRAINT file_nodes_updated_order CHECK (updated_at_ms>=created_at_ms) ENFORCED,\n"
    "    CONSTRAINT file_nodes_deletion_valid CHECK ((state IN (1,2) AND deleted_at_ms IS NULL) OR (state=3 AND deleted_at_ms IS NOT NULL AND deleted_at_ms>=created_at_ms AND deleted_at_ms<=updated_at_ms)) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const vireo_mysql_migration_step_t node_steps[] = {
    {objects_sql, sizeof(objects_sql)-1},
    {file_nodes_sql, sizeof(file_nodes_sql)-1}
};
static const char operation_audits_sql[] =
    "CREATE TABLE operation_audits (\n"
    "    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
    "    request_id VARBINARY(16) NOT NULL,\n"
    "    user_id BIGINT UNSIGNED NULL,\n"
    "    session_id BIGINT UNSIGNED NULL,\n"
    "    action SMALLINT UNSIGNED NOT NULL,\n"
    "    target_type TINYINT UNSIGNED NOT NULL,\n"
    "    target_id BIGINT UNSIGNED NULL,\n"
    "    target_hash VARBINARY(32) NULL,\n"
    "    status SMALLINT UNSIGNED NOT NULL,\n"
    "    latency_us BIGINT UNSIGNED NOT NULL,\n"
    "    detail VARBINARY(1024) NOT NULL,\n"
    "    occurred_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    PRIMARY KEY (id),\n"
    "    UNIQUE KEY operation_audits_request_action_unique (request_id,action),\n"
    "    KEY operation_audits_user_time (user_id,occurred_at_ms,id),\n"
    "    KEY operation_audits_action_time (action,occurred_at_ms,id),\n"
    "    KEY operation_audits_status_time (status,occurred_at_ms,id),\n"
    "    KEY operation_audits_time (occurred_at_ms,id),\n"
    "    CONSTRAINT operation_audits_request_valid CHECK (OCTET_LENGTH(request_id)=16 AND request_id<>REPEAT(X'00',16)) ENFORCED,\n"
    "    CONSTRAINT operation_audits_actor_valid CHECK ((user_id IS NULL OR user_id>0) AND (session_id IS NULL OR (session_id>0 AND user_id IS NOT NULL))) ENFORCED,\n"
    "    CONSTRAINT operation_audits_action_valid CHECK (action>0) ENFORCED,\n"
    "    CONSTRAINT operation_audits_target_valid CHECK ((target_type=0 AND target_id IS NULL AND target_hash IS NULL) OR (target_type IN (1,2,3) AND target_id IS NOT NULL AND target_id>0 AND target_hash IS NULL) OR (target_type=4 AND target_id IS NULL AND target_hash IS NOT NULL AND OCTET_LENGTH(target_hash)=32)) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const vireo_mysql_migration_step_t audit_steps[] = {
    {operation_audits_sql, sizeof(operation_audits_sql)-1}
};
static const char upload_tasks_sql[] =
    "CREATE TABLE upload_tasks (\n"
    "    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
    "    public_id VARBINARY(16) NOT NULL,\n"
    "    user_id BIGINT UNSIGNED NOT NULL,\n"
    "    file_node_id BIGINT UNSIGNED NOT NULL,\n"
    "    idempotency_key VARBINARY(16) NOT NULL,\n"
    "    expected_hash VARBINARY(32) NOT NULL,\n"
    "    size BIGINT UNSIGNED NOT NULL,\n"
    "    mode TINYINT UNSIGNED NOT NULL,\n"
    "    chunk_size INT UNSIGNED NOT NULL,\n"
    "    chunk_count BIGINT UNSIGNED NOT NULL,\n"
    "    state TINYINT UNSIGNED NOT NULL,\n"
    "    received_chunks BIGINT UNSIGNED NOT NULL,\n"
    "    received_bytes BIGINT UNSIGNED NOT NULL,\n"
    "    version BIGINT UNSIGNED NOT NULL,\n"
    "    cancel_requested TINYINT UNSIGNED NOT NULL,\n"
    "    last_status SMALLINT UNSIGNED NOT NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    updated_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    expires_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    finished_at_ms BIGINT UNSIGNED NULL,\n"
    "    PRIMARY KEY (id),\n"
    "    UNIQUE KEY upload_tasks_public_id_unique (public_id),\n"
    "    UNIQUE KEY upload_tasks_user_idempotency_unique (user_id,idempotency_key),\n"
    "    UNIQUE KEY upload_tasks_node_unique (file_node_id),\n"
    "    KEY upload_tasks_user_node (user_id,file_node_id),\n"
    "    KEY upload_tasks_user_state (user_id,state,id),\n"
    "    KEY upload_tasks_state_expiry (state,expires_at_ms,id),\n"
    "    CONSTRAINT upload_tasks_node_fk FOREIGN KEY (user_id,file_node_id) REFERENCES file_nodes(owner_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT upload_tasks_public_id_valid CHECK (OCTET_LENGTH(public_id)=16 AND public_id<>REPEAT(X'00',16)) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_idempotency_valid CHECK (OCTET_LENGTH(idempotency_key)=16 AND idempotency_key<>REPEAT(X'00',16)) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_hash_valid CHECK (OCTET_LENGTH(expected_hash)=32) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_owner_valid CHECK (user_id>0 AND file_node_id>0) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_mode_valid CHECK (mode IN (1,2)) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_state_valid CHECK (state IN (1,2,3,4,5,6,7,8,9)) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_geometry_valid CHECK ((CASE WHEN mode=2 THEN chunk_size=0 AND chunk_count=0 WHEN mode=1 AND chunk_size BETWEEN 1 AND 16777160 THEN chunk_count<=4294967296 AND chunk_count=(size DIV chunk_size)+(MOD(size,chunk_size)<>0) ELSE FALSE END)=TRUE) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_progress_valid CHECK (received_chunks<=chunk_count AND received_bytes<=size AND ((received_chunks=0 AND received_bytes=0) OR (received_chunks>0 AND received_bytes>=received_chunks)) AND (state<>1 OR (received_chunks=0 AND received_bytes=0))) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_complete_valid CHECK (mode<>1 OR state NOT IN (4,5,6) OR (received_chunks=chunk_count AND received_bytes=size)) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_fast_valid CHECK (mode<>2 OR (state=6 AND received_chunks=0 AND received_bytes=0)) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_version_valid CHECK (version>0) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_cancel_valid CHECK (cancel_requested IN (0,1)) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_updated_order CHECK (updated_at_ms>=created_at_ms) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_expiry_order CHECK (expires_at_ms>created_at_ms) ENFORCED,\n"
    "    CONSTRAINT upload_tasks_finished_valid CHECK ((state IN (1,2,3,4,5) AND finished_at_ms IS NULL) OR (state IN (6,7,8,9) AND finished_at_ms IS NOT NULL AND finished_at_ms>=created_at_ms AND finished_at_ms<=updated_at_ms)) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const char upload_chunks_sql[] =
    "CREATE TABLE upload_chunks (\n"
    "    task_id BIGINT UNSIGNED NOT NULL,\n"
    "    chunk_index INT UNSIGNED NOT NULL,\n"
    "    byte_offset BIGINT UNSIGNED NOT NULL,\n"
    "    byte_length INT UNSIGNED NOT NULL,\n"
    "    chunk_hash VARBINARY(32) NOT NULL,\n"
    "    crc32c INT UNSIGNED NOT NULL,\n"
    "    state TINYINT UNSIGNED NOT NULL,\n"
    "    received_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    PRIMARY KEY (task_id,chunk_index),\n"
    "    UNIQUE KEY upload_chunks_offset_unique (task_id,byte_offset),\n"
    "    KEY upload_chunks_task_state (task_id,state,chunk_index),\n"
    "    CONSTRAINT upload_chunks_task_fk FOREIGN KEY (task_id) REFERENCES upload_tasks(id) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT upload_chunks_task_valid CHECK (task_id>0) ENFORCED,\n"
    "    CONSTRAINT upload_chunks_hash_valid CHECK (OCTET_LENGTH(chunk_hash)=32) ENFORCED,\n"
    "    CONSTRAINT upload_chunks_length_valid CHECK (byte_length BETWEEN 1 AND 16777160) ENFORCED,\n"
    "    CONSTRAINT upload_chunks_range_valid CHECK (byte_offset<=18446744073709551615-byte_length) ENFORCED,\n"
    "    CONSTRAINT upload_chunks_state_valid CHECK (state IN (1,2)) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const vireo_mysql_migration_step_t upload_steps[] = {
    {upload_tasks_sql, sizeof(upload_tasks_sql)-1},
    {upload_chunks_sql, sizeof(upload_chunks_sql)-1}
};
static const char chunks_sql[] =
    "CREATE TABLE chunks (\n"
    "    chunk_hash VARBINARY(32) NOT NULL,\n"
    "    size INT UNSIGNED NOT NULL,\n"
    "    state TINYINT UNSIGNED NOT NULL,\n"
    "    ref_count BIGINT UNSIGNED NOT NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    updated_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    verified_at_ms BIGINT UNSIGNED NULL,\n"
    "    PRIMARY KEY (chunk_hash),\n"
    "    KEY chunks_state_updated (state,updated_at_ms,chunk_hash),\n"
    "    KEY chunks_refs_state (ref_count,state,chunk_hash),\n"
    "    CONSTRAINT chunks_hash_valid CHECK (OCTET_LENGTH(chunk_hash)=32) ENFORCED,\n"
    "    CONSTRAINT chunks_size_valid CHECK (size BETWEEN 1 AND 16777160) ENFORCED,\n"
    "    CONSTRAINT chunks_state_valid CHECK (state IN (1,2,3,4)) ENFORCED,\n"
    "    CONSTRAINT chunks_updated_order CHECK (updated_at_ms>=created_at_ms) ENFORCED,\n"
    "    CONSTRAINT chunks_verified_required CHECK (state<>2 OR verified_at_ms IS NOT NULL) ENFORCED,\n"
    "    CONSTRAINT chunks_verified_order CHECK (verified_at_ms IS NULL OR (verified_at_ms>=created_at_ms AND verified_at_ms<=updated_at_ms)) ENFORCED,\n"
    "    CONSTRAINT chunks_deleting_unreferenced CHECK (state<>3 OR ref_count=0) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const char object_chunks_sql[] =
    "CREATE TABLE object_chunks (\n"
    "    object_hash BINARY(32) NOT NULL,\n"
    "    chunk_index INT UNSIGNED NOT NULL,\n"
    "    byte_offset BIGINT UNSIGNED NOT NULL,\n"
    "    byte_length INT UNSIGNED NOT NULL,\n"
    "    chunk_hash VARBINARY(32) NOT NULL,\n"
    "    PRIMARY KEY (object_hash,chunk_index),\n"
    "    UNIQUE KEY object_chunks_offset_unique (object_hash,byte_offset),\n"
    "    KEY object_chunks_chunk (chunk_hash,object_hash,chunk_index),\n"
    "    CONSTRAINT object_chunks_object_fk FOREIGN KEY (object_hash) REFERENCES objects(object_hash) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT object_chunks_chunk_fk FOREIGN KEY (chunk_hash) REFERENCES chunks(chunk_hash) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT object_chunks_hash_valid CHECK (OCTET_LENGTH(chunk_hash)=32) ENFORCED,\n"
    "    CONSTRAINT object_chunks_length_valid CHECK (byte_length BETWEEN 1 AND 16777160) ENFORCED,\n"
    "    CONSTRAINT object_chunks_range_valid CHECK (byte_offset<=18446744073709551615-byte_length) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const vireo_mysql_migration_step_t manifest_steps[] = {
    {chunks_sql, sizeof(chunks_sql)-1},
    {object_chunks_sql, sizeof(object_chunks_sql)-1}
};
static const char storage_nodes_sql[] =
    "CREATE TABLE storage_nodes (\n"
    "    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
    "    node_uuid VARBINARY(16) NOT NULL,\n"
    "    endpoint VARBINARY(512) NOT NULL,\n"
    "    zone VARBINARY(64) NOT NULL,\n"
    "    status TINYINT UNSIGNED NOT NULL,\n"
    "    capacity_bytes BIGINT UNSIGNED NOT NULL,\n"
    "    used_bytes BIGINT UNSIGNED NOT NULL,\n"
    "    generation BIGINT UNSIGNED NOT NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    updated_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    last_heartbeat_at_ms BIGINT UNSIGNED NULL,\n"
    "    PRIMARY KEY (id),\n"
    "    UNIQUE KEY storage_nodes_uuid_unique (node_uuid),\n"
    "    KEY storage_nodes_status_zone_capacity (status,zone,capacity_bytes,id),\n"
    "    KEY storage_nodes_status_heartbeat (status,last_heartbeat_at_ms,id),\n"
    "    CONSTRAINT storage_nodes_uuid_valid CHECK (OCTET_LENGTH(node_uuid)=16) ENFORCED,\n"
    "    CONSTRAINT storage_nodes_endpoint_valid CHECK (OCTET_LENGTH(endpoint) BETWEEN 1 AND 512 AND LOCATE(X'00',endpoint)=0) ENFORCED,\n"
    "    CONSTRAINT storage_nodes_zone_valid CHECK (OCTET_LENGTH(zone) BETWEEN 1 AND 64 AND LOCATE(X'00',zone)=0) ENFORCED,\n"
    "    CONSTRAINT storage_nodes_status_valid CHECK (status IN (1,2,3,4)) ENFORCED,\n"
    "    CONSTRAINT storage_nodes_capacity_valid CHECK (used_bytes<=capacity_bytes) ENFORCED,\n"
    "    CONSTRAINT storage_nodes_generation_valid CHECK (generation>0) ENFORCED,\n"
    "    CONSTRAINT storage_nodes_updated_order CHECK (updated_at_ms>=created_at_ms) ENFORCED,\n"
    "    CONSTRAINT storage_nodes_heartbeat_required CHECK (status NOT IN (1,2) OR last_heartbeat_at_ms IS NOT NULL) ENFORCED,\n"
    "    CONSTRAINT storage_nodes_heartbeat_order CHECK (last_heartbeat_at_ms IS NULL OR (last_heartbeat_at_ms>=created_at_ms AND last_heartbeat_at_ms<=updated_at_ms)) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const char chunk_replicas_sql[] =
    "CREATE TABLE chunk_replicas (\n"
    "    chunk_hash VARBINARY(32) NOT NULL,\n"
    "    node_id BIGINT UNSIGNED NOT NULL,\n"
    "    state TINYINT UNSIGNED NOT NULL,\n"
    "    generation BIGINT UNSIGNED NOT NULL,\n"
    "    node_generation BIGINT UNSIGNED NOT NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    updated_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    verified_at_ms BIGINT UNSIGNED NULL,\n"
    "    PRIMARY KEY (chunk_hash,node_id),\n"
    "    KEY chunk_replicas_node_state (node_id,state,chunk_hash),\n"
    "    KEY chunk_replicas_chunk_state (chunk_hash,state,node_id),\n"
    "    CONSTRAINT chunk_replicas_chunk_fk FOREIGN KEY (chunk_hash) REFERENCES chunks(chunk_hash) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT chunk_replicas_node_fk FOREIGN KEY (node_id) REFERENCES storage_nodes(id) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT chunk_replicas_hash_valid CHECK (OCTET_LENGTH(chunk_hash)=32) ENFORCED,\n"
    "    CONSTRAINT chunk_replicas_state_valid CHECK (state IN (1,2,3,4,5)) ENFORCED,\n"
    "    CONSTRAINT chunk_replicas_generation_valid CHECK (generation>0) ENFORCED,\n"
    "    CONSTRAINT chunk_replicas_node_generation_valid CHECK (node_generation>0) ENFORCED,\n"
    "    CONSTRAINT chunk_replicas_updated_order CHECK (updated_at_ms>=created_at_ms) ENFORCED,\n"
    "    CONSTRAINT chunk_replicas_verified_required CHECK (state<>2 OR verified_at_ms IS NOT NULL) ENFORCED,\n"
    "    CONSTRAINT chunk_replicas_verified_order CHECK (verified_at_ms IS NULL OR (verified_at_ms>=created_at_ms AND verified_at_ms<=updated_at_ms)) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const vireo_mysql_migration_step_t replica_steps[] = {
    {storage_nodes_sql, sizeof(storage_nodes_sql)-1},
    {chunk_replicas_sql, sizeof(chunk_replicas_sql)-1}
};
static const char download_tasks_sql[] =
    "CREATE TABLE download_tasks (\n"
    "    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
    "    public_id VARBINARY(16) NOT NULL,\n"
    "    user_id BIGINT UNSIGNED NOT NULL,\n"
    "    file_node_id BIGINT UNSIGNED NOT NULL,\n"
    "    idempotency_key VARBINARY(16) NOT NULL,\n"
    "    object_hash BINARY(32) NOT NULL,\n"
    "    size BIGINT UNSIGNED NOT NULL,\n"
    "    manifest_version BIGINT UNSIGNED NOT NULL,\n"
    "    part_count BIGINT UNSIGNED NOT NULL,\n"
    "    state TINYINT UNSIGNED NOT NULL,\n"
    "    acked_bytes BIGINT UNSIGNED NOT NULL,\n"
    "    version BIGINT UNSIGNED NOT NULL,\n"
    "    cancel_requested TINYINT UNSIGNED NOT NULL,\n"
    "    last_status SMALLINT UNSIGNED NOT NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    updated_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    expires_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    finished_at_ms BIGINT UNSIGNED NULL,\n"
    "    PRIMARY KEY (id),\n"
    "    UNIQUE KEY download_tasks_public_id_unique (public_id),\n"
    "    UNIQUE KEY download_tasks_user_idempotency_unique (user_id,idempotency_key),\n"
    "    KEY download_tasks_user_node (user_id,file_node_id),\n"
    "    KEY download_tasks_user_state (user_id,state,id),\n"
    "    KEY download_tasks_state_expiry (state,expires_at_ms,id),\n"
    "    KEY download_tasks_object (object_hash,id),\n"
    "    CONSTRAINT download_tasks_node_fk FOREIGN KEY (user_id,file_node_id) REFERENCES file_nodes(owner_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT download_tasks_object_fk FOREIGN KEY (object_hash) REFERENCES objects(object_hash) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT download_tasks_public_id_valid CHECK (OCTET_LENGTH(public_id)=16 AND public_id<>REPEAT(X'00',16)) ENFORCED,\n"
    "    CONSTRAINT download_tasks_idempotency_valid CHECK (OCTET_LENGTH(idempotency_key)=16 AND idempotency_key<>REPEAT(X'00',16)) ENFORCED,\n"
    "    CONSTRAINT download_tasks_owner_valid CHECK (user_id>0 AND file_node_id>0) ENFORCED,\n"
    "    CONSTRAINT download_tasks_manifest_valid CHECK (manifest_version=1) ENFORCED,\n"
    "    CONSTRAINT download_tasks_geometry_valid CHECK ((CASE WHEN part_count<=4294967296 THEN ((size=0 AND part_count=0) OR (part_count>0 AND size>=part_count AND size<=part_count*16777160)) ELSE FALSE END)=TRUE) ENFORCED,\n"
    "    CONSTRAINT download_tasks_state_valid CHECK (state IN (1,2,3,4,5,6,7,8,9)) ENFORCED,\n"
    "    CONSTRAINT download_tasks_progress_valid CHECK (acked_bytes<=size AND (state<>1 OR acked_bytes=0)) ENFORCED,\n"
    "    CONSTRAINT download_tasks_complete_valid CHECK (state NOT IN (5,6) OR acked_bytes=size) ENFORCED,\n"
    "    CONSTRAINT download_tasks_version_valid CHECK (version>0) ENFORCED,\n"
    "    CONSTRAINT download_tasks_cancel_valid CHECK (cancel_requested IN (0,1)) ENFORCED,\n"
    "    CONSTRAINT download_tasks_updated_order CHECK (updated_at_ms>=created_at_ms) ENFORCED,\n"
    "    CONSTRAINT download_tasks_expiry_order CHECK (expires_at_ms>created_at_ms) ENFORCED,\n"
    "    CONSTRAINT download_tasks_finished_valid CHECK ((state IN (1,2,3,4,5) AND finished_at_ms IS NULL) OR (state IN (6,7,8,9) AND finished_at_ms IS NOT NULL AND finished_at_ms>=created_at_ms AND finished_at_ms<=updated_at_ms)) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const char download_parts_sql[] =
    "CREATE TABLE download_parts (\n"
    "    task_id BIGINT UNSIGNED NOT NULL,\n"
    "    part_index INT UNSIGNED NOT NULL,\n"
    "    byte_offset BIGINT UNSIGNED NOT NULL,\n"
    "    byte_length INT UNSIGNED NOT NULL,\n"
    "    chunk_hash VARBINARY(32) NOT NULL,\n"
    "    state TINYINT UNSIGNED NOT NULL,\n"
    "    acked_bytes INT UNSIGNED NOT NULL,\n"
    "    version BIGINT UNSIGNED NOT NULL,\n"
    "    source_kind TINYINT UNSIGNED NOT NULL,\n"
    "    source_node_id BIGINT UNSIGNED NULL,\n"
    "    source_node_generation BIGINT UNSIGNED NULL,\n"
    "    source_replica_generation BIGINT UNSIGNED NULL,\n"
    "    lease_id VARBINARY(16) NULL,\n"
    "    lease_issued_at_ms BIGINT UNSIGNED NULL,\n"
    "    lease_expires_at_ms BIGINT UNSIGNED NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    updated_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    PRIMARY KEY (task_id,part_index),\n"
    "    UNIQUE KEY download_parts_offset_unique (task_id,byte_offset),\n"
    "    KEY download_parts_task_state (task_id,state,part_index),\n"
    "    KEY download_parts_source_state (source_node_id,state,task_id,part_index),\n"
    "    KEY download_parts_chunk (chunk_hash,task_id,part_index),\n"
    "    CONSTRAINT download_parts_task_fk FOREIGN KEY (task_id) REFERENCES download_tasks(id) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT download_parts_chunk_fk FOREIGN KEY (chunk_hash) REFERENCES chunks(chunk_hash) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT download_parts_source_fk FOREIGN KEY (source_node_id) REFERENCES storage_nodes(id) ON DELETE RESTRICT ON UPDATE RESTRICT,\n"
    "    CONSTRAINT download_parts_task_valid CHECK (task_id>0) ENFORCED,\n"
    "    CONSTRAINT download_parts_hash_valid CHECK (OCTET_LENGTH(chunk_hash)=32) ENFORCED,\n"
    "    CONSTRAINT download_parts_length_valid CHECK (byte_length BETWEEN 1 AND 16777160) ENFORCED,\n"
    "    CONSTRAINT download_parts_range_valid CHECK (byte_offset<=18446744073709551615-byte_length) ENFORCED,\n"
    "    CONSTRAINT download_parts_state_valid CHECK (state IN (1,2,3,4,5,6)) ENFORCED,\n"
    "    CONSTRAINT download_parts_progress_valid CHECK (acked_bytes<=byte_length AND (state<>1 OR acked_bytes=0) AND (state<>4 OR acked_bytes=byte_length)) ENFORCED,\n"
    "    CONSTRAINT download_parts_version_valid CHECK (version>0) ENFORCED,\n"
    "    CONSTRAINT download_parts_source_kind_valid CHECK (source_kind IN (0,1,2) AND (state NOT IN (2,3,4) OR source_kind<>0) AND (state<>1 OR source_kind=0) AND (source_kind<>0 OR acked_bytes=0)) ENFORCED,\n"
    "    CONSTRAINT download_parts_source_valid CHECK ((source_kind IN (0,1) AND source_node_id IS NULL AND source_node_generation IS NULL AND source_replica_generation IS NULL AND lease_id IS NULL AND lease_issued_at_ms IS NULL AND lease_expires_at_ms IS NULL) OR (source_kind=2 AND source_node_id IS NOT NULL AND source_node_id>0 AND source_node_generation IS NOT NULL AND source_node_generation>0 AND source_replica_generation IS NOT NULL AND source_replica_generation>0 AND lease_id IS NOT NULL AND OCTET_LENGTH(lease_id)=16 AND lease_id<>REPEAT(X'00',16) AND lease_issued_at_ms IS NOT NULL AND lease_issued_at_ms>=created_at_ms AND lease_issued_at_ms<=updated_at_ms AND lease_expires_at_ms IS NOT NULL AND lease_expires_at_ms>lease_issued_at_ms)) ENFORCED,\n"
    "    CONSTRAINT download_parts_updated_order CHECK (updated_at_ms>=created_at_ms) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const vireo_mysql_migration_step_t download_steps[] = {
    {download_tasks_sql, sizeof(download_tasks_sql)-1},
    {download_parts_sql, sizeof(download_parts_sql)-1}
};
static const char gc_jobs_sql[] =
    "CREATE TABLE gc_jobs (\n"
    "    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
    "    resource_kind TINYINT UNSIGNED NOT NULL,\n"
    "    resource_key VARBINARY(32) NOT NULL,\n"
    "    operation TINYINT UNSIGNED NOT NULL,\n"
    "    state TINYINT UNSIGNED NOT NULL,\n"
    "    attempts INT UNSIGNED NOT NULL,\n"
    "    version BIGINT UNSIGNED NOT NULL,\n"
    "    next_run_at_ms BIGINT UNSIGNED NULL,\n"
    "    claim_id VARBINARY(16) NULL,\n"
    "    claimed_at_ms BIGINT UNSIGNED NULL,\n"
    "    lease_expires_at_ms BIGINT UNSIGNED NULL,\n"
    "    last_error SMALLINT UNSIGNED NOT NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    updated_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    finished_at_ms BIGINT UNSIGNED NULL,\n"
    "    active_slot TINYINT UNSIGNED GENERATED ALWAYS AS (CASE WHEN state IN (1,2) THEN 1 ELSE NULL END) STORED,\n"
    "    PRIMARY KEY (id),\n"
    "    UNIQUE KEY gc_jobs_active_resource_unique (resource_kind,resource_key,operation,active_slot),\n"
    "    UNIQUE KEY gc_jobs_claim_unique (claim_id),\n"
    "    KEY gc_jobs_state_next_run (state,next_run_at_ms,id),\n"
    "    KEY gc_jobs_state_lease (state,lease_expires_at_ms,id),\n"
    "    KEY gc_jobs_finished (state,finished_at_ms,id),\n"
    "    CONSTRAINT gc_jobs_resource_valid CHECK ((resource_kind IN (1,2) AND OCTET_LENGTH(resource_key)=32) OR (resource_kind=3 AND OCTET_LENGTH(resource_key)=16 AND resource_key<>REPEAT(X'00',16))) ENFORCED,\n"
    "    CONSTRAINT gc_jobs_operation_valid CHECK (operation=1) ENFORCED,\n"
    "    CONSTRAINT gc_jobs_state_valid CHECK (state IN (1,2,3,4,5)) ENFORCED,\n"
    "    CONSTRAINT gc_jobs_attempts_valid CHECK (attempts<=1000000 AND (state<>1 OR attempts<1000000) AND (state<>2 OR attempts>0)) ENFORCED,\n"
    "    CONSTRAINT gc_jobs_version_valid CHECK (version>0) ENFORCED,\n"
    "    CONSTRAINT gc_jobs_schedule_valid CHECK ((state=1 AND next_run_at_ms IS NOT NULL AND next_run_at_ms>=created_at_ms) OR (state<>1 AND next_run_at_ms IS NULL)) ENFORCED,\n"
    "    CONSTRAINT gc_jobs_claim_valid CHECK ((state=2 AND claim_id IS NOT NULL AND OCTET_LENGTH(claim_id)=16 AND claim_id<>REPEAT(X'00',16) AND claimed_at_ms IS NOT NULL AND claimed_at_ms>=created_at_ms AND claimed_at_ms<=updated_at_ms AND lease_expires_at_ms IS NOT NULL AND lease_expires_at_ms>claimed_at_ms) OR (state<>2 AND claim_id IS NULL AND claimed_at_ms IS NULL AND lease_expires_at_ms IS NULL)) ENFORCED,\n"
    "    CONSTRAINT gc_jobs_error_valid CHECK (last_error IN (0,1,2,3,4,5) AND (state<>3 OR last_error=0) AND (state<>5 OR last_error<>0)) ENFORCED,\n"
    "    CONSTRAINT gc_jobs_updated_order CHECK (updated_at_ms>=created_at_ms) ENFORCED,\n"
    "    CONSTRAINT gc_jobs_finished_valid CHECK ((state IN (1,2) AND finished_at_ms IS NULL) OR (state IN (3,4,5) AND finished_at_ms IS NOT NULL AND finished_at_ms>=created_at_ms AND finished_at_ms<=updated_at_ms)) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin";

static const vireo_mysql_migration_step_t gc_steps[] = {
    {gc_jobs_sql, sizeof(gc_jobs_sql)-1}
};
static const char directory_write_receipts_sql[] =
    "CREATE TABLE directory_write_receipts (\n"
    "    user_id BIGINT UNSIGNED NOT NULL,\n"
    "    command SMALLINT UNSIGNED NOT NULL,\n"
    "    idempotency_key VARBINARY(16) NOT NULL,\n"
    "    format_version SMALLINT UNSIGNED NOT NULL,\n"
    "    request_parent_id BIGINT UNSIGNED NOT NULL,\n"
    "    request_name VARBINARY(255) NOT NULL,\n"
    "    result_node_id BIGINT UNSIGNED NOT NULL,\n"
    "    audit_id BIGINT UNSIGNED NOT NULL,\n"
    "    created_at_ms BIGINT UNSIGNED NOT NULL,\n"
    "    PRIMARY KEY (user_id,command,idempotency_key),\n"
    "    CONSTRAINT directory_receipts_user_valid CHECK (user_id>0) ENFORCED,\n"
    "    CONSTRAINT directory_receipts_command_valid CHECK (command=1027) ENFORCED,\n"
    "    CONSTRAINT directory_receipts_key_valid CHECK (OCTET_LENGTH(idempotency_key)=16 AND idempotency_key<>REPEAT(X'00',16)) ENFORCED,\n"
    "    CONSTRAINT directory_receipts_format_valid CHECK (format_version=1) ENFORCED,\n"
    "    CONSTRAINT directory_receipts_parent_valid CHECK (request_parent_id>0) ENFORCED,\n"
    "    CONSTRAINT directory_receipts_name_valid CHECK (OCTET_LENGTH(request_name) BETWEEN 1 AND 255 AND request_name NOT IN (X'2E',X'2E2E') AND LOCATE(X'2F',request_name)=0 AND LOCATE(X'00',request_name)=0) ENFORCED,\n"
    "    CONSTRAINT directory_receipts_node_valid CHECK (result_node_id>0) ENFORCED,\n"
    "    CONSTRAINT directory_receipts_audit_valid CHECK (audit_id>0) ENFORCED\n"
    ") ENGINE=InnoDB DEFAULT CHARACTER SET=utf8mb4 COLLATE=utf8mb4_bin\n";

static const vireo_mysql_migration_step_t directory_receipt_steps[] = {
    {directory_write_receipts_sql, sizeof(directory_write_receipts_sql)-1}
};
static const vireo_mysql_migration_t catalog[] = {
    {1, initial_steps, 2},
    {2, node_steps, 2},
    {3, audit_steps, 1},
    {4, upload_steps, 2},
    {5, manifest_steps, 2},
    {6, replica_steps, 2},
    {7, download_steps, 2},
    {8, gc_steps, 1},
    {9, directory_receipt_steps, 1}
};

vireo_result_t vireo_mysql_schema_catalog(
    const vireo_mysql_migration_t **out_migrations, size_t *out_count)
{
    if (!out_migrations || !out_count) { return VIREO_RESULT_INVALID_ARGUMENT; }
    *out_migrations = catalog;
    *out_count = sizeof(catalog)/sizeof(catalog[0]);
    return VIREO_OK;
}
