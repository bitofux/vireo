/*
 * PROJECT : VIREO
 * FILE    : async_admission_pressure.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 手动异步准入的真实容量压力及一次监听READ同步
 */
#ifndef VIREO_NET_ASYNC_ADMISSION_PRESSURE_H
#define VIREO_NET_ASYNC_ADMISSION_PRESSURE_H
#include <vireo/net/tcp_server.h>

/** 独立刷新阶段，不重排原server或接入枚举。 */
typedef enum vireo_async_admission_pressure_stage {
    VIREO_ASYNC_ADMISSION_PRESSURE_NONE = 0,
    VIREO_ASYNC_ADMISSION_PRESSURE_VALIDATE_OPTIONS = 1,
    VIREO_ASYNC_ADMISSION_PRESSURE_CHECK_SERVER = 2,
    VIREO_ASYNC_ADMISSION_PRESSURE_CHECK_CAPACITY = 3,
    VIREO_ASYNC_ADMISSION_PRESSURE_UPDATE_READ = 4
} vireo_async_admission_pressure_stage_t;

/** 当次容量快照和真实开关进度；数值副本不保活或同步资源。 */
typedef struct vireo_async_admission_pressure_report {
    vireo_async_admission_pressure_stage_t stage; /**< 主因步骤；基本拒绝/成功NONE。 */
    bool server_inspected; /**< 原inspect已成功，read_before/after有快照来源。 */
    size_t pair_bytes; /**< 原connection完整数值校验后发布的固定双容量，字节。 */
    size_t available_connections; /**< 账及全池额度通过后发布的客户名额。 */
    size_t available_buffer_bytes; /**< 账及全池额度通过后的固定容量余量，非未读字节。 */
    bool pressure_calculated; /**< 两类压力和desired已计算，非资源同步屏障。 */
    bool connection_limited; /**< calculated时为无新客户名额。 */
    bool buffer_limited; /**< calculated时为余量不足pair，恰够不限制。 */
    bool read_desired; /**< calculated时为两种限制均无，非已经提交。 */
    bool read_before; /**< inspect成功时原实际READ开关，不是当前就绪。 */
    bool update_called; /**< 仅开关与desired不同时尝试一次公开set。 */
    bool read_after; /**< 初为before，仅set OK后为desired；错误不虚报更新。 */
    vireo_tcp_server_listener_error_t listener_error; /**< 原set诊断，未调用逻辑零。 */
} vireo_async_admission_pressure_report_t;

/**
 * @brief
 *     显式按真实名额和固定buffer额度刷新手动监听READ，变化时只MOD一次。
 *
 * @param[in,out] server
 *     必需存活网络根，原run之外Reactor串行安全点，已拥有且绑定监听。
 * @param[in] connection_options
 *     必需下一批接入使用的原三字节选项，入口复制，不保存；caller保证与033-04一致。
 * @param[out] report
 *     必需独立报告，每可写路径发布；失败也保存计算及真实前后开关。
 *
 * @retval VIREO_OK
 *     刷新完成或同值省MOD；不足资源正常暂停，不接入或释放客户。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL，资源保持。
 * @retval VIREO_RESULT_OVERFLOW
 *     read+write不可表示，优先原数值硬限。
 * @retval VIREO_RESULT_RANGE
 *     原connection零数值/公开上限/预算非法，或pair超过全池固定buffer额度。
 * @retval VIREO_RESULT_BUSY
 *     六有限在途/running或旧自动准入enabled，不能混用或隐式disable。
 * @retval VIREO_RESULT_CANCELLED
 *     成功观察后已停止，保持开关，不解除永久停止。
 * @retval VIREO_RESULT_NOT_FOUND
 *     无自有绑定监听；其他依赖分类原样返回。
 * @retval VIREO_RESULT_INTERNAL
 *     公开名额/固定容量账不一致；其他依赖分类原样返回。
 *
 * @note
 *     顺序为基本地址、受检原connection、inspect、在途、stop、旧auto、监听、账、全池额度、计算及set。
 *     六有限指processing/driving/scheduling/serving/shutdown/closing；running另拒绝。
 *     set失败保原实际开关/资源和完整诊断，不重试/关闭/回滚，所有路径保持入口errno。
 * @note
 *     名额由available_connections、固定额度由max_buffer_bytes-buffer_capacity_bytes判定。
 *     consume/send/EOF/关闭意图不退款；仅原实际消费release（含消费型IO）退款，再由caller显式刷新。
 *     无迟滞或自动触发，不accept/wait/驱动/管理task；历史listener_last_events不作为当前就绪。
 * @note
 *     全调用禁POSIX取消；对象发布/寿命由caller负责，地址有效独立对齐不重叠。
 *     观察stop不是跨线程屏障，晚stop不抢占本调用；恢复READ也不能恢复loop运行。
 *     本层无申请/长期配置；报告只表示当次时点，未calculated的压力字段无策略意义。
 */
vireo_result_t vireo_async_admission_pressure_refresh(vireo_tcp_server_t *server,
    vireo_connection_options_t const *connection_options, vireo_async_admission_pressure_report_t *report);
#endif
