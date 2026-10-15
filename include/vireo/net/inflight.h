/*
 * PROJECT : VIREO
 * FILE    : inflight.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : Reactor 客户身份与 task 元数据的桥接及当前客户核验
 */
#ifndef VIREO_NET_INFLIGHT_H
#define VIREO_NET_INFLIGHT_H

#include <vireo/net/tcp_server.h>
#include <vireo/thread/task.h>

/** 本层按值诊断，不拥有资源；结果类别由函数返回值提供。 */
typedef enum vireo_inflight_stage {
    VIREO_INFLIGHT_NONE = 0,           /**< 成功或基本参数拒绝。 */
    VIREO_INFLIGHT_CHECK_CLIENT = 1,   /**< 公开查询当前客户。 */
    VIREO_INFLIGHT_MAKE_ROUTE = 2,     /**< 公开构造 task 路由。 */
    VIREO_INFLIGHT_MAKE_METADATA = 3,  /**< 公开构造 task 元数据。 */
    VIREO_INFLIGHT_CHECK_METADATA = 4, /**< 公开校验输入元数据完整形态。 */
    VIREO_INFLIGHT_CHECK_SERVER = 5,   /**< 公开观测 server 停止快照。 */
    VIREO_INFLIGHT_CHECK_RECORD = 6,   /**< 查找、活跃标签冲突或容量检查。 */
    VIREO_INFLIGHT_ISSUE_INSTANCE = 7, /**< 受检实例发号或一次原子提交。 */
    VIREO_INFLIGHT_RETAIN_CANCEL = 8, /**< 公开取得一份取消强引用或缺关联。 */
    VIREO_INFLIGHT_RELEASE_CANCEL = 9, /**< 公开释放表持有的取消强引用。 */
    VIREO_INFLIGHT_CHECK_COMPLETION = 10, /**< 公开读取并验证完整完成描述。 */
    VIREO_INFLIGHT_MATCH_RECORD = 11 /**< 核对完成描述与原登记的非身份快照。 */
} vireo_inflight_stage_t;

/**
 * @brief
 *     公开核验当前客户后构造独立 task 元数据，不登记请求。
 *
 * @param[in] server
 *     非空存活资源根，只借用到返回；本入口 Reactor-only。
 * @param[in] client
 *     已初始化的完整按值客户租约；复制不保活或增加权限。
 * @param[in] request_sequence
 *     非零 uint32 请求标签，不保证唯一，不改变线协议其他规则。
 * @param[in] request_instance_id
 *     非零 uint64 实例号；caller 保证同完整客户生命期内不复用。
 * @param[in] operation
 *     非零 uint32 内部操作标签，不自动映射线协议命令。
 * @param[in] deadline_ns
 *     同域 MONOTONIC 绝对纳秒；0/MAX 均有限，允许已到期值。
 * @param[out] out_metadata
 *     必需独立可写纯值输出，允许覆盖已有值；失败保持全部字节。
 * @param[out] stage
 *     可空独立阶段输出，每可写路径覆盖；成功与基本拒绝为 NONE。
 *
 * @retval VIREO_OK
 *     完整元数据发布；不表示请求已登记、提交或仍在途。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、零标签/实例、畸形或跨拥有域客户。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零客户、空槽或旧代次。
 * @retval VIREO_RESULT_RANGE
 *     同拥有域槽号超过实际容量。
 *
 * @return
 *     其他公开依赖错误原样返回，失败阶段保留。
 *
 * @note
 *     顺序：必需地址/标签/客户形态→公开客户核验→route 构造→metadata 构造→发布。
 *     原 lease 仍是存储租约；本层不将其自动升级为异步认证或业务权限。
 *     closing 客户和已停止 server 中仍有效客户允许构造；新请求准入须另检查 OPEN。
 * @note
 *     无分配、采样、发号、登记、收发、提交、回滚或重试，不保存地址或保活客户。
 *     所有失败保持主输出及资源，成功只承诺逻辑字段，不承诺 padding/ABI。
 * @note
 *     地址存活、正确对齐、独占且彼此不重叠，也不指向输入、资源或 errno。
 *     值复制不构成跨线程发布；所有路径保持入口 errno。
 */
vireo_result_t vireo_inflight_metadata_make(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint32_t request_sequence,
    uint64_t request_instance_id, uint32_t operation, uint64_t deadline_ns,
    vireo_task_metadata_t *out_metadata, vireo_inflight_stage_t *stage);

/**
 * @brief
 *     公开核验当前客户后发一个新请求实例号并构造元数据，不登记请求。
 *
 * @param[in] server
 *     非空存活资源根，仅借至返回；同 server 全部访问仍 Reactor-only。
 * @param[in] client
 *     已初始化的完整按值客户租约；不保活，允许当前 closing 客户。
 * @param[in] request_sequence
 *     非零 uint32 协议标签，由 caller 提供，不保证历史唯一。
 * @param[in] operation
 *     非零 uint32 内部操作标签，不自动映射 wire 命令。
 * @param[in] deadline_ns
 *     同域 MONOTONIC 绝对纳秒，0/MAX 有限，允许已到期值。
 * @param[out] out_metadata
 *     必需独立可写纯值，成功可覆盖已有值，失败保持全部字节。
 * @param[out] stage
 *     可空独立诊断，每可写路径覆盖；成功/基本拒绝 NONE。
 *
 * @retval VIREO_OK
 *     发布完整 metadata 及非零新实例号；不代表登记、提交或执行成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、零标签、畸形或跨拥有域客户。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零客户、空槽或旧代次。
 * @retval VIREO_RESULT_RANGE
 *     同拥有域槽号超过实际容量。
 * @retval VIREO_RESULT_OVERFLOW
 *     本库实例已发出 UINT64_MAX；永久耗尽，不回绕或重置。
 * @retval VIREO_RESULT_BUSY
 *     单次 strong CAS 遇到其他发行提交；本调用未发号，不内部重试。
 *
 * @return
 *     其他公开桥接依赖错误原样返回并保留原阶段。
 *
 * @note
 *     顺序：基本参数及全部公开桥接检查→受检下一值→一次 CAS→发布。
 *     已停止 server 中仍有效客户允许构造；新请求准入由登记层检查 OPEN。
 *     发号成功后无可失败步骤；以后登记或提交失败不退号。
 * @note
 *     本库实例进程内统一从 1 发到 MAX，不依赖表/客户生命周期。
 *     只保证本入口发出值不重复；同客户须统一编号来源，不能与碰撞手工编号混用。
 *     不保证跨进程、多库副本、卸载重载或 fork 继承唯一，不用于持久或安全认证。
 * @note
 *     无动态申请、登记、采样、提交或内部循环重试；不保存输入/输出地址。
 *     原子只同步编号，不发布对象/metadata 或授予同 server 并发访问权。
 *     不承诺 C11 原子必 lock-free、固定耗时或硬实时。
 * @note
 *     所有失败保持主输出及本调用资源义务；其他合法发行者进度不冻结。
 *     地址须存活、对齐、独占且不重叠输入/资源/其他输出/errno。
 *     成功只承诺逻辑字段，所有路径保持入口 errno。
 */
vireo_result_t vireo_inflight_metadata_make_next(vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint32_t request_sequence,
    uint32_t operation, uint64_t deadline_ns, vireo_task_metadata_t *out_metadata,
    vireo_inflight_stage_t *stage);

/**
 * @brief
 *     从有效元数据核验当前客户并发布关闭阶段，不核验请求是否仍在途。
 *
 * @param[in] server
 *     非空存活资源根，只借用到返回；本入口 Reactor-only。
 * @param[in] metadata
 *     已初始化的完整按值元数据；其关联真实性和实例不复用由 caller 保证。
 * @param[out] out_close_state
 *     必需独立可写纯值；成功 OPEN/DRAINING/READY，失败保持全部字节。
 * @param[out] stage
 *     可空独立诊断，每可写路径覆盖；成功/基本拒绝 NONE。
 *
 * @retval VIREO_OK
 *     此查询时点客户仍有效；不保证请求活跃、允许新提交或允许回写。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、metadata 形态无效（含全零），或跨拥有域身份。
 * @retval VIREO_RESULT_NOT_FOUND
 *     元数据对应客户为空槽或旧代次。
 * @retval VIREO_RESULT_RANGE
 *     同拥有域槽号超过实际容量。
 * @retval VIREO_RESULT_INTERNAL
 *     公开客户快照违反关闭阶段合同；不修复资源。
 *
 * @return
 *     其他公开依赖错误原样返回。
 *
 * @note
 *     顺序：必需地址→公开metadata完整形态检查→公开客户核验→发布关闭阶段。
 *     允许 closing 和已停止 server 中仍有效客户；不采样或判断 deadline。
 *     请求已结束但客户仍有效时可成功；后续在途记录层必须另核验请求。
 * @note
 *     无分配、内部指针输出、登记、回滚或重试；失败主输出及资源保持。
 *     地址存活、正确对齐、独占且不重叠资源/输入/其他输出，也不得指向 errno。
 *     值与快照不保活；全部路径保持入口 errno。
 */
vireo_result_t vireo_inflight_check_client(vireo_tcp_server_t const *server,
    vireo_task_metadata_t metadata, vireo_connection_close_state_t *out_close_state,
    vireo_inflight_stage_t *stage);

#endif
