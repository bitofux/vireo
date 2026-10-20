/*
 * PROJECT : VIREO
 * FILE    : mysql_schema.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 认证、对象/节点、操作审计、上传、永久块/manifest、节点/副本与下载持久结构的静态只读迁移目录。
 */
#ifndef VIREO_PERSISTENCE_MYSQL_SCHEMA_H
#define VIREO_PERSISTENCE_MYSQL_SCHEMA_H
#include <stddef.h>
#include <stdint.h>
#include <vireo/persistence/mysql_migration.h>

/** @brief 本目录要求MySQL 8.0.16+且仍限8.0系列，保证CHECK实际执行。 */
#define VIREO_MYSQL_SCHEMA_MIN_SERVER_VERSION UINT32_C(80016)
/** @brief 展示用户名最多64个Unicode字符；不是UTF-8字节数。 */
#define VIREO_MYSQL_SCHEMA_USERNAME_MAX_CHARACTERS 64
/** @brief caller统一规范化后的身份键最多256字节，逐字节唯一。 */
#define VIREO_MYSQL_SCHEMA_USERNAME_KEY_MAX_BYTES 256
/** @brief 经035验证的完整PHC最多127字节，不含C终止符。 */
#define VIREO_MYSQL_SCHEMA_PASSWORD_HASH_MAX_BYTES 127
/** @brief 036 v1摘要恰32字节；包含NUL和尾零，不存原始token。 */
#define VIREO_MYSQL_SCHEMA_TOKEN_DIGEST_BYTES 32
/** @brief 持久用户启用状态；授权还须检查Session及时间。 */
#define VIREO_MYSQL_SCHEMA_USER_ACTIVE 1
/** @brief 持久用户禁用状态；不会自动级联撤销Session。 */
#define VIREO_MYSQL_SCHEMA_USER_DISABLED 2
/** @brief 持久Session未撤销状态；不表示尚未到期。 */
#define VIREO_MYSQL_SCHEMA_SESSION_ACTIVE 1
/** @brief 持久Session已撤销状态；须有非NULL撤销时间。 */
#define VIREO_MYSQL_SCHEMA_SESSION_REVOKED 2

/** @brief BLAKE3对象身份32字节；BINARY会补零，caller绑定前须核精确长度。 */
#define VIREO_MYSQL_SCHEMA_OBJECT_HASH_BYTES 32
/** @brief DB按完整name字节计算SHA-256；不作为唯一名字身份。 */
#define VIREO_MYSQL_SCHEMA_NAME_HASH_BYTES 32
/** @brief 规范化UTF-8名字最多255字节；根空名为内部表示。 */
#define VIREO_MYSQL_SCHEMA_NODE_NAME_MAX_BYTES 255
/** @brief 对象候选状态，尚未获得可信物理内容证据。 */
#define VIREO_MYSQL_SCHEMA_OBJECT_PENDING 1
/** @brief 对象已验证状态；写入此值不能代替内容验证。 */
#define VIREO_MYSQL_SCHEMA_OBJECT_VERIFIED 2
/** @brief 对象删除中状态；引用计数须为0，仍须核实际FK引用。 */
#define VIREO_MYSQL_SCHEMA_OBJECT_DELETING 3
/** @brief 对象隔离状态；可保留历史引用及验证时间。 */
#define VIREO_MYSQL_SCHEMA_OBJECT_QUARANTINED 4
/** @brief 对象存储为本地受控数据根；表中不存磁盘路径。 */
#define VIREO_MYSQL_SCHEMA_OBJECT_STORAGE_LOCAL 1
/** @brief 目录节点；对象引用须NULL且size为0。 */
#define VIREO_MYSQL_SCHEMA_NODE_DIRECTORY 1
/** @brief 文件节点；ACTIVE须有对象引用，物理可用由caller核对。 */
#define VIREO_MYSQL_SCHEMA_NODE_FILE 2
/** @brief 上传中节点，同样占用同属主同父的完整名字。 */
#define VIREO_MYSQL_SCHEMA_NODE_UPLOADING 1
/** @brief 活动节点；不表示已通过父类型、无环或对象业务授权。 */
#define VIREO_MYSQL_SCHEMA_NODE_ACTIVE 2
/** @brief 软删除节点，须有删除时间且释放名字；可保留对象FK。 */
#define VIREO_MYSQL_SCHEMA_NODE_DELETED 3

/** @brief 可信全局执行事件身份恰16字节且非全零；不是wire sequence/业务幂等键。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_REQUEST_ID_BYTES 16
/** @brief 去敏后detail最多1024字节，空串合法；DB不验证UTF-8或去敏。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_DETAIL_MAX_BYTES 1024
/** @brief 独立审计动作正uint16域；未命名值仍须由未来writer注册。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_ACTION_MAX 65535
/** @brief 外部Vireo结果码uint16快照；不是内部result/MySQL错误。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_STATUS_MAX 65535
/** @brief 注册动作。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_ACTION_REGISTER 1
/** @brief 登录动作。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_ACTION_LOGIN 2
/** @brief 退出动作。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_ACTION_LOGOUT 3
/** @brief 恢复Session动作。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_ACTION_SESSION_RESUME 4
/** @brief 无已知目标；id/hash均NULL。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_TARGET_NONE 0
/** @brief 用户历史身份；正id且hash NULL。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_TARGET_USER 1
/** @brief Session历史身份；正id且hash NULL。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_TARGET_SESSION 2
/** @brief 节点历史身份；正id且hash NULL。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_TARGET_NODE 3
/** @brief 对象历史身份；id NULL，hash精确32字节且全零合法。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_TARGET_OBJECT 4
/** @brief 外部成功结果码快照。 */
#define VIREO_MYSQL_SCHEMA_AUDIT_STATUS_OK 0

/** @brief 对外持久UUID恰16字节非零；只在上传表内唯一，查找仍须核user。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_PUBLIC_ID_BYTES 16
/** @brief 本user初始化幂等UUID恰16字节非零；唯一不证明请求载荷相同。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_IDEMPOTENCY_KEY_BYTES 16
/** @brief 声明整文件BLAKE3恰32字节，全零可存；不是已验证对象。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_EXPECTED_HASH_BYTES 32
/** @brief 校验后块BLAKE3恰32字节；DB只验长度。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_HASH_BYTES 32
/** @brief 单个非空data硬上限；不是默认协商值或线上quota。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_DATA_MAX_BYTES 16777160
/** @brief u32索引0..MAX可编号2^32块，count必须64位。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_COUNT_MAX UINT64_C(4294967296)
/** @brief 从0起的完整u32分块索引上限。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_INDEX_MAX UINT32_MAX
/** @brief 实际接收模式；chunk_size正且count等于ceil(size/chunk_size)。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_MODE_TRANSFER 1
/** @brief 无需传输的完成任务；分块参数/接收计数全0，业务仍须验证CAS。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_MODE_FAST 2
/** @brief 独立上传持久状态NEW；DB不核迁移边，非022/wire枚举。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_NEW 1
/** @brief 独立上传持久状态RECEIVING；DB不核迁移边，非022/wire枚举。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_RECEIVING 2
/** @brief 独立上传持久状态PAUSED；DB不核迁移边，非022/wire枚举。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_PAUSED 3
/** @brief 独立上传持久状态VERIFYING；DB不核迁移边，非022/wire枚举。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_VERIFYING 4
/** @brief 独立上传持久状态COMMITTING；DB不核迁移边，非022/wire枚举。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_COMMITTING 5
/** @brief 独立上传持久状态COMPLETED；DB不核迁移边，非022/wire枚举。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_COMPLETED 6
/** @brief 独立上传持久状态FAILED；DB不核迁移边，非022/wire枚举。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_FAILED 7
/** @brief 独立上传持久状态CANCELLED；DB不核迁移边，非022/wire枚举。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_CANCELLED 8
/** @brief 独立上传持久状态EXPIRED；DB不核迁移边，非022/wire枚举。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_EXPIRED 9
/** @brief 已确认接收事实；不等永久物理耐久证明。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_RECEIVED 1
/** @brief 恢复发现失效，仍占index/offset；业务需替换及修正计数。 */
#define VIREO_MYSQL_SCHEMA_UPLOAD_CHUNK_INVALID 2

/** @brief 永久块内容BLAKE3恰32字节；VARBINARY+CHECK拒绝短输入，全零合法。 */
#define VIREO_MYSQL_SCHEMA_CHUNK_HASH_BYTES 32
/** @brief 永久非空块硬限，与v1单帧data容量一致；不承诺协商默认或线上quota。 */
#define VIREO_MYSQL_SCHEMA_CHUNK_DATA_MAX_BYTES 16777160
/** @brief 对象内从0起的完整u32索引域上限，不是块数上限。 */
#define VIREO_MYSQL_SCHEMA_MANIFEST_INDEX_MAX UINT32_MAX
/** @brief u32位置索引可编号2^32行；逻辑count需uint64，不允许据此无界分配。 */
#define VIREO_MYSQL_SCHEMA_MANIFEST_CHUNKS_MAX UINT64_C(4294967296)
/** @brief 永久块候选状态；尚无可信物理内容证据，独立于object/upload状态域。 */
#define VIREO_MYSQL_SCHEMA_CHUNK_PENDING 1
/** @brief 永久块已验证状态；须有验证时间，写状态值不能代替内容/可用性验证。 */
#define VIREO_MYSQL_SCHEMA_CHUNK_VERIFIED 2
/** @brief 永久块删除中；ref_count须0，但FK引用/读lease/物理GC仍须另核。 */
#define VIREO_MYSQL_SCHEMA_CHUNK_DELETING 3
/** @brief 永久块隔离状态，可保留旧验证时间及引用；业务须拒绝不可信读取。 */
#define VIREO_MYSQL_SCHEMA_CHUNK_QUARANTINED 4

/** @brief 稳定节点UUID恰16字节，VARBINARY+CHECK保精确长度；不是认证凭据。 */
#define VIREO_MYSQL_SCHEMA_STORAGE_NODE_UUID_BYTES 16
/** @brief 节点地址字节硬限，禁止NUL；实际地址语法/准入/TLS仍由消费者验证。 */
#define VIREO_MYSQL_SCHEMA_STORAGE_NODE_ENDPOINT_MAX_BYTES 512
/** @brief 放置域标签字节硬限，禁止NUL；不是自动故障域独立性证明。 */
#define VIREO_MYSQL_SCHEMA_STORAGE_NODE_ZONE_MAX_BYTES 64
/** @brief 节点活跃候选，必须有心跳时间；不等实时可用或写入配额。 */
#define VIREO_MYSQL_SCHEMA_STORAGE_NODE_ACTIVE 1
/** @brief 节点排空候选，必须有心跳时间；读写准入策略由后续业务定义。 */
#define VIREO_MYSQL_SCHEMA_STORAGE_NODE_DRAINING 2
/** @brief 节点离线；可保留此前心跳与副本记录。 */
#define VIREO_MYSQL_SCHEMA_STORAGE_NODE_OFFLINE 3
/** @brief 节点被管理禁用；DB不自动撤销lease或清理物理副本。 */
#define VIREO_MYSQL_SCHEMA_STORAGE_NODE_DISABLED 4
/** @brief 副本待验证，不等于全局chunk状态；不作为可信来源。 */
#define VIREO_MYSQL_SCHEMA_REPLICA_PENDING 1
/** @brief 副本有验证时间；还须核节点代际/身份/lease与真实可用性。 */
#define VIREO_MYSQL_SCHEMA_REPLICA_VERIFIED 2
/** @brief 副本删除中；物理删除和读lease收敛仍需后续协议。 */
#define VIREO_MYSQL_SCHEMA_REPLICA_DELETING 3
/** @brief 副本缺失证据，可保旧验证时间，不表示块在其他节点也丢失。 */
#define VIREO_MYSQL_SCHEMA_REPLICA_MISSING 4
/** @brief 本副本隔离，独立于全局chunks的隔离数值域。 */
#define VIREO_MYSQL_SCHEMA_REPLICA_QUARANTINED 5

/** @brief 公开下载UUID精确16字节非零，表内唯一；查询仍须核属主。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_PUBLIC_ID_BYTES 16
/** @brief 同user下载初始化UUID精确16字节非零，冲突须比较原file_node请求。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_IDEMPOTENCY_KEY_BYTES 16
/** @brief 本版布局仅1；已发布映射不可变，真多版本须追加迁移。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_MANIFEST_VERSION 1
/** @brief u32索引可编号2^32个位置；count用u64，非可无界分配的额度。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_COUNT_MAX UINT64_C(4294967296)
/** @brief 一个part对应一个非空manifest块的最大字节数。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_MAX_BYTES 16777160
/** @brief 远端授权引用身份精确16字节非零；不是bearer token或完整lease。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_LEASE_ID_BYTES 16
/** @brief 独立下载任务持久状态NEW；DB检查形状，实际转换由业务执行。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_NEW 1
/** @brief 独立下载任务持久状态READY；DB检查形状，实际转换由业务执行。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_READY 2
/** @brief 独立下载任务持久状态TRANSFERRING；DB检查形状，实际转换由业务执行。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_TRANSFERRING 3
/** @brief 独立下载任务持久状态PAUSED；DB检查形状，实际转换由业务执行。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_PAUSED 4
/** @brief 独立下载任务持久状态VERIFYING_CLIENT；DB检查形状，实际转换由业务执行。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_VERIFYING_CLIENT 5
/** @brief 独立下载任务持久状态COMPLETED；DB检查形状，实际转换由业务执行。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_COMPLETED 6
/** @brief 独立下载任务持久状态FAILED；DB检查形状，实际转换由业务执行。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_FAILED 7
/** @brief 独立下载任务持久状态CANCELLED；DB检查形状，实际转换由业务执行。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_CANCELLED 8
/** @brief 独立下载任务持久状态EXPIRED；DB检查形状，实际转换由业务执行。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_EXPIRED 9
/** @brief 独立下载part状态PENDING；不等任务状态数值域。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_PENDING 1
/** @brief 独立下载part状态READY；不等任务状态数值域。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_READY 2
/** @brief 独立下载part状态TRANSFERRING；不等任务状态数值域。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_TRANSFERRING 3
/** @brief 独立下载part状态COMPLETED；不等任务状态数值域。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_COMPLETED 4
/** @brief 独立下载part状态FAILED；不等任务状态数值域。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_FAILED 5
/** @brief 独立下载part状态CANCELLED；不等任务状态数值域。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_PART_CANCELLED 6
/** @brief 未分配来源；远端字段全NULL且ACK0。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_SOURCE_UNASSIGNED 0
/** @brief 本地CAS来源；远端字段全NULL，真实路径由可信存储层派生。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_SOURCE_LOCAL 1
/** @brief 远端副本来源；节点/双代际/lease身份与时间六字段完整，FK只保身份。 */
#define VIREO_MYSQL_SCHEMA_DOWNLOAD_SOURCE_REPLICA 2

/** @brief 本地整对象hash身份，不是远端副本。 */
#define VIREO_MYSQL_SCHEMA_GC_OBJECT 1
/** @brief 本地永久chunk hash身份。 */
#define VIREO_MYSQL_SCHEMA_GC_CHUNK 2
/** @brief 上传public UUID身份，非数据库task id/任意路径。 */
#define VIREO_MYSQL_SCHEMA_GC_UPLOAD_STAGING 3
/** @brief 唯一当前操作DELETE，路径由可信root/hash/UUID派生。 */
#define VIREO_MYSQL_SCHEMA_GC_DELETE 1
/** @brief 到期可领取，活资源唯一slot为1。 */
#define VIREO_MYSQL_SCHEMA_GC_READY 1
/** @brief 有完整claim组的执行意图，非物理删除授权。 */
#define VIREO_MYSQL_SCHEMA_GC_RUNNING 2
/** @brief 本轮已完成，错误NONE，终态释放slot。 */
#define VIREO_MYSQL_SCHEMA_GC_SUCCEEDED 3
/** @brief 本轮不再需要，终态释放slot。 */
#define VIREO_MYSQL_SCHEMA_GC_CANCELLED 4
/** @brief 本轮终止，错误非NONE，终态释放slot。 */
#define VIREO_MYSQL_SCHEMA_GC_FAILED 5
/** @brief 领取次数硬上限，READY必须小于上限。 */
#define VIREO_MYSQL_SCHEMA_GC_ATTEMPTS_MAX 1000000
/** @brief 非零领取UUID精确字节数，非秘密授权token。 */
#define VIREO_MYSQL_SCHEMA_GC_CLAIM_ID_BYTES 16
/** @brief 无错误；不写原生文本/路径/凭据。 */
#define VIREO_MYSQL_SCHEMA_GC_ERROR_NONE 0
/** @brief 实际引用或读保护仍在。 */
#define VIREO_MYSQL_SCHEMA_GC_ERROR_REFERENCED 1
/** @brief 文件系统I/O失败，不将EIO/EACCES当不存在。 */
#define VIREO_MYSQL_SCHEMA_GC_ERROR_IO 2
/** @brief 领取资格已失效。 */
#define VIREO_MYSQL_SCHEMA_GC_ERROR_LEASE_LOST 3
/** @brief 资源证据损坏需人工/恢复流程。 */
#define VIREO_MYSQL_SCHEMA_GC_ERROR_CORRUPT 4
/** @brief 其余去敏内部失败。 */
#define VIREO_MYSQL_SCHEMA_GC_ERROR_INTERNAL 5

/**
 * @brief 取得进程静态只读生产迁移目录，不执行数据库操作。
 *
 * @param[out] out_migrations
 *     必需独占输出；成功借用const目录，禁止修改或free。
 * @param[out] out_count
 *     必需独占输出；当前成功为8，各版本步数2/2/1/2/2/2/2/1；遍历完整数量。
 *
 * @retval VIREO_OK
 *     已交付完整目录；不表示数据库迁移已完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一输出NULL；两个输出均保持。
 *
 * @note 数组、步骤和精确SQL字节自进程加载至退出有效，重复返回同一地址。
 *       已部署版本字节不可改写；追加迁移须使用既有migration_apply验证历史。
 * @note 地址须存活、对齐、独占、互不覆盖且不指向errno。无分配/I/O/阻塞，
 *       不读取、保存或修改errno；独立输出thread-safe，两写非跨线程原子发布。
 * @note 本目录要求MySQL8.0.16+，时间为uint64 UTC Unix毫秒，0为合法epoch，
 *       NULL表示缺失时间。key/name规范化、PHC检查和完整业务授权由caller负责。
 * @note 目录包含v1认证与v2对象/节点。数据库限制至多一根、同属主父引用和
 *       完整binary存活名字唯一；至少一根、父为活动目录/无环、对象验证/size/
 *       引用计数一致及GC准入由后续事务负责，无自动根、触发器或时钟。
 * @note v3审计关联为历史身份快照，无活表FK；可信writer须核来源/关系，
 *       查询须允许主体已删除。唯一(request_id,action)只去重审计，不保证
 *       载荷相等或业务幂等；冲突须核旧事实，未知提交不能换id盲重放。
 *       latency_us为构造点MONOTONIC受检耗时，不含后续写入/提交/网络。
 *       detail去敏、动作注册/结果映射、保留/读权限与追加约定由业务负责；
 *       本表没有不可篡改或append-only权限保护。
 * @note v4上传关联同属主node，一node一task；不关联Session，任务可跨重连。
 *       TRANSFER按协商几何接收，FAST只存无传输完成形状；跨行几何/计数、
 *       node类型/状态、内容/hash/CRC/物理耐久、FAST对象证据、状态转换/
 *       version CAS、协作取消与保留/清理由未来业务核对，DB不自动求和。
 *       同user+key只保证一个task；完整规范化初始请求须真实RESUME前存证
 *       并比较，必要时先追加迁移，不能从可变node反推或只凭key恢复；
 *       无法证实相同则CONFLICT，未知提交不能换key盲重放。
 *       时间为显式UTC毫秒而非单调调度；version MAX可存但不得回绕。
 * @note v5永久chunks与object_chunks区分任务接收事实；ref_count的业务目标为
 *       manifest行数，同对象不同位置复用同块计多次，DB不自动求和/更新。
 *       FK只保身份存在；完整覆盖/连续索引/无重叠、跨表size、真实内容/
 *       VERIFIED可用性、状态迁移/物理耐久与GC/读lease由后续业务保证。
 *       对象内映射object_hash沿既有BINARY32，caller绑定前核精确长度；
 *       块hash为VARBINARY32+CHECK。空对象零映射，永久块禁止size0。
 *       同对象已发布manifest须稳定，不能因新协商分块而盲改；布局版本
 *       与下载恢复合同在实际消费者出现前明确，必要时追加迁移。
 *       删除映射/计数受检更新须同事务；ref_count0不能替代FK/真实引用核验。
 * @note v6节点generation是存储实例代际；副本generation是本行操作版本，
 *       node_generation是该副本登记/验证时的节点代际快照，均正且不能回绕。
 *       FK只到node_id，允许节点换代后保留旧副本；reader须核快照等当前代际，
 *       writer须受检单调CAS/防重用，结合mTLS/lease/真实内容与可用性。
 *       DB不自动执行心跳/状态迁移/复制/修复/容量求和/预留或物理GC。
 *       endpoint/zone为有界非NUL字节；语法/规范化/允许目的地由可信writer核，
 *       endpoint不唯一且不是身份，zone不证明独立故障域。副本数不改manifest引用。
 *       ACTIVE/DRAINING需心跳时间，VERIFIED需验证时间，但墙钟证据不等实时活性。
 * @note v7下载task固定原整文件node请求及object/size/manifest_version/part_count；
 *       同user+key冲突须比较原file_node和已存快照，不从当前可变node反推。
 *       本版仅整文件请求；新范围/协商参数须先持久存证再开放恢复。
 *       manifest_version仅1：同对象已发布布局不可变，真多版本须追加迁移。
 *       每part固定一个manifest位置的index/offset/length/hash；初始化同事务核
 *       完整覆盖、连续无重叠、大小/hash/状态和授权。DB不保证快照不可改。
 * @note part ACK是该位置起点后的连续已确认前缀，任务ACK目标为前缀之和；
 *       可信writer须事务核owner/状态/行version/manifest/来源，再仅加受检delta，
 *       重复/较小ACK不累加。切源保前缀并更换lease/增加part version拒绝旧ACK；
 *       无自动跨行求和、单调性、状态转换、实际校验/客户端耐久或完成证明。
 * @note 来源0未分配、1本地CAS、2远端副本。远端node/实例代际/副本行版本/
 *       lease id/签发/过期六字段齐备；本地无伪节点。lease id不是秘密token，
 *       本表不签发/验证lease。FK不绑定活replica或当前代际，旧快照可保留；
 *       实际ACK/读取须核当前节点/副本/lease与mTLS、物理可用和单调期限。
 *       task/part FK只防元数据删除，不等GC读保护；取消/到期/保留清理仍后续。
 * @note v8清理资源仅本地object/hash、chunk/hash、upload staging/public UUID；
 *       活任务完整(kind,key,operation,slot)唯一，终态slot=NULL可再入队；
 *       终态历史不复活。无资源FK，元数据删除后仍可保留待办；可信writer
 *       须同业务事务写意图、核冲突等价。未来远端副本需新迁移保存双代际。
 * @note attempts是领取次数且有硬上限；每次领取/过期抢回须受检+1并用新
 *       claim_id及version；完成/重试须核RUNNING、version、claim及未到期。
 *       last_error仅固定去敏数值分类；CHECK不约束状态边/单调性/可信身份。
 *       lease只能围栏DB回写，不能阻止迟到worker unlink；真实删除须后续
 *       资源互斥/不可复活删除态或隔离rename、引用/读lease及发布共同协议。
 *       不得只凭ref_count0或任务存在删文件；重试/调度/保留/时钟策略仍后续。
 */
vireo_result_t vireo_mysql_schema_catalog(
    const vireo_mysql_migration_t **out_migrations, size_t *out_count);
#endif
