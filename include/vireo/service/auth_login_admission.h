/* PROJECT : VIREO
 * FILE : auth_login_admission.h
 * DATE : 2026-10-19
 * BRIEF : LOGIN三维频率准入，设备标签只作自报辅助。
 */
#ifndef VIREO_SERVICE_AUTH_LOGIN_ADMISSION_H
#define VIREO_SERVICE_AUTH_LOGIN_ADMISSION_H
#include <stddef.h>
#include <stdint.h>
#include <vireo/security/rate_limiter.h>

/** @brief 客户端设备标签固定字节数；不是秘密、可信硬件身份或认证凭据。 */
#define VIREO_AUTH_LOGIN_DEVICE_BYTES 16
/** @brief 本合同固定IP标签；与AF_INET等平台常量没有数值关系。 */
#define VIREO_AUTH_LOGIN_PEER_IPV4 UINT8_C(4)
#define VIREO_AUTH_LOGIN_PEER_IPV6 UINT8_C(6)

/** @brief Reactor从真实socket取得的二进制对端IP快照，不含端口或fd。 */
typedef struct vireo_auth_login_peer {
    uint8_t family; /**< 仅本合同4或6；不是客户端声明的IP或平台AF_*。 */
    unsigned char address[16]; /**< 网络序；IPv4用前4字节且尾12字节必须零。 */
} vireo_auth_login_peer_t;

/** @brief 一个尝试频率桶的不可变配置，不是KDF并发或失败锁号。 */
typedef struct vireo_auth_login_quota {
    uint32_t burst_tokens; /**< 初始/最大请求数，1..037的MAX_BURST_TOKENS。 */
    vireo_duration_ns_t refill_interval_ns; /**< 每补1次的正纳秒，至多1小时。 */
} vireo_auth_login_quota_t;

/** @brief 构造时复制，专用于LOGIN；不自动用于注册、恢复或其他命令。 */
typedef struct vireo_auth_login_admission_options {
    size_t max_keys; /**< 037总记录容量，1..4096；三个维度共享，不是连接数。 */
    size_t max_memory_bytes; /**< 037容器请求预算，1..1MiB，不含wrapper/allocator/RSS。 */
    vireo_auth_login_quota_t peer; /**< 真实IP，每个完整LOGIN请求消耗1。 */
    vireo_auth_login_quota_t account; /**< 041-01小写账号key；存在与否不影响扣费。 */
    vireo_auth_login_quota_t device; /**< 客户端16字节标签，辅助维度，不作为可信身份。 */
} vireo_auth_login_admission_options_t;

/** @brief 开发起始值：IP20/每3秒补1，账号5/每30秒补1，设备10/每6秒补1。 */
#define VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT \
    {(size_t)4096, (size_t)1048576, {UINT32_C(20), UINT64_C(3000000000)}, \
     {UINT32_C(5), UINT64_C(30000000000)}, {UINT32_C(10), UINT64_C(6000000000)}}

/** @brief 唯一owner，内部独占一个037对象；check/destroy为Reactor串行调用。 */
typedef struct vireo_auth_login_admission vireo_auth_login_admission_t;

/**
 * @brief 完整验证配置并构造专用三政策限流器，复制配置且最后发布owner。
 * @param[in] options 必需合法配置，只借至返回；没有隐式读取config/环境变量。
 * @param[in] now 同一单调域的起始时间，0和UINT64_MAX合法。
 * @param[in,out] out 必需独占owner地址，*out须NULL；成功由destroy消费。
 * @retval VIREO_OK 已发布空表及专用政策IP=1/账号=2/设备=3，不能接入其他037用途。
 * @retval VIREO_RESULT_INVALID_ARGUMENT NULL、非空owner、零容量/预算或零频率参数。
 * @retval VIREO_RESULT_OVERFLOW 037资源乘加无法表示，优先于资源硬限。
 * @retval VIREO_RESULT_RANGE 配置超037上限或实际容器申请超过预算。
 * @retval VIREO_RESULT_NO_MEMORY wrapper或037分配失败，全部回滚，out保持。
 * @note 在启动/允许分配线程创建；无I/O/采时/KDF/SQL/线程创建。保持errno。
 *       输入与owner/errno不得重叠，创建发布由装配者同步；不热改或自动重建。
 */
vireo_result_t vireo_auth_login_admission_create(
    vireo_auth_login_admission_options_t const *options, vireo_monotonic_ns_t now,
    vireo_auth_login_admission_t **out);

/**
 * @brief 确定性生成三身份键，调用一次037同时判定/扣费，适用于完整合法LOGIN尝试。
 * @param[in,out] admission 必需存活对象，当前Reactor独占；不与其他入口并发。
 * @param[in] now 同域非递减时间；调用方在本次串行准入前采样，禁止worker提前采样后乱序提交。
 * @param[in] peer 必需可信对端IP；IPv4尾12字节须零，IPv4-mapped IPv6归并到IPv4。
 * @param[in] username 必需原账号字节；调用041-01生成统一小写key，不查账号存在性。
 * @param[in] username_length 精确3..32字节；ASCII字母/数字/下划线，规则同041-01。
 * @param[in] device 必需可读16字节客户端标签；全部位模式合法，不按C字符串解释。
 * @param[out] decision 必需独占037按值结果；成功需检查outcome，不等于密码认证。
 * @retval VIREO_OK 已判定；ADMITTED才完整扣3维度各1，THROTTLED/CAPACITY均不部分扣。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需指针NULL、非法family/IPv4尾字节，或037时间倒退。
 * @retval VIREO_RESULT_RANGE 用户名长度越界；先于内容检查，不读取越界长度输入。
 * @retval VIREO_RESULT_PROTOCOL 用户名包含不合法ASCII字节。
 * @note 顺序：全部指针→用户名长度→peer形态→用户名字符→构键→一次037check。
 *       非OK保持对象及整个decision；合法拒绝仍推进037时间。所有路径保持errno。
 *       固定key编码：IP[family||address||零尾]，账号[小写ASCII||零尾]，
 *       设备[16原字节||16零]，靠专用policy分域；不是摘要/匿名化或wire布局。
 * @note Reactor串行，无分配/采时/I/O/锁/KDF/DB；输入借至返回且不得修改，输出/对象/输入
 *       及errno互不重叠。037固定容量线性扫描，无硬实时承诺。没有内部重试/refund/reset。
 * @note 账号存在/错密/禁用/成功都按尝试收费；后续DB/KDF/队列失败也不退款。device可伪造
 *       或轮换，不能绕过独立IP/账号桶。返回值不得直接强转为wire状态。
 *       未经验证的网络帧/密码、TLS状态仍由上游检查；本接口不证明这些前置或真实IP来源。
 */
vireo_result_t vireo_auth_login_admission_check(vireo_auth_login_admission_t *admission,
    vireo_monotonic_ns_t now, vireo_auth_login_peer_t const *peer,
    char const *username, size_t username_length,
    unsigned char const device[VIREO_AUTH_LOGIN_DEVICE_BYTES],
    vireo_rate_limit_decision_t *decision);

/**
 * @brief 全部访问退出后释放wrapper及其独占037对象，清唯一owner。
 * @param[in,out] owner 必需独占owner地址，*owner可NULL；不与errno/自有资源重叠。
 * @retval VIREO_OK 已释放或空owner，*owner为NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT owner地址NULL。
 * @note Reactor排他，无在途借用后调用；别名不保活对象。无SQL/KDF/I/O，保持errno。
 *       不提供重置欠额接口；进程重启会失去限额历史，不承诺跨进程总量。
 */
vireo_result_t vireo_auth_login_admission_destroy(vireo_auth_login_admission_t **owner);
#endif
