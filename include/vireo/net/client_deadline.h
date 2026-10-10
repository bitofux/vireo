/*
 * PROJECT : VIREO
 * FILE    : client_deadline.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 完整客户与 timer 的当前核验及历史身份匹配
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#ifndef VIREO_NET_CLIENT_DEADLINE_H
#define VIREO_NET_CLIENT_DEADLINE_H

#include <vireo/net/tcp_server.h>
#include <vireo/timer/wheel_advance.h>

/** 普通数值副本，不拥有或保活资源，不作为 wire ABI。
 * 全零为空；非空须双方 pool/owner 和 generation 均非零，半空或畸形无效。
 * slot 的形态允许整个 size_t 范围，当前容量由公开依赖检查。 */
typedef struct vireo_client_deadline_binding {
    vireo_connection_pool_lease_t client; /**< 完整客户存储租约，不是 fd 或异步任务身份。 */
    vireo_timer_handle_t timer; /**< 完整 timer 身份；通知领取后用于历史匹配。 */
} vireo_client_deadline_binding_t;

/** 独立诊断，无资源所有权，不是超时或关闭策略。 */
typedef enum vireo_client_deadline_stage {
    VIREO_CLIENT_DEADLINE_NONE = 0,         /**< 成功或本层基本参数／空身份拒绝。 */
    VIREO_CLIENT_DEADLINE_CHECK_CLIENT = 1, /**< 公开客户当前性观测拒绝。 */
    VIREO_CLIENT_DEADLINE_CHECK_TIMER = 2,  /**< 构造时公开 timer 当前性查询拒绝。 */
    VIREO_CLIENT_DEADLINE_MATCH_TIMER = 3,  /**< 历史 timer 完整身份不匹配。 */
    VIREO_CLIENT_DEADLINE_REGISTER_TIMER = 4, /**< 公开 timer 登记拒绝。 */
    VIREO_CLIENT_DEADLINE_CANCEL_TIMER = 5,   /**< 公开 timer 取消拒绝，绑定保持。 */
    VIREO_CLIENT_DEADLINE_REARM_TIMER = 6,    /**< 公开 timer 重排拒绝，原期限保持。 */
    VIREO_CLIENT_DEADLINE_REQUEST_CLOSE_CLIENT = 7, /**< 公开客户关闭拒绝，意图可能已提交。 */
    VIREO_CLIENT_DEADLINE_CHECK_READY_CLIENT = 8, /**< 当前客户尚未 READY，未尝试归还。 */
    VIREO_CLIENT_DEADLINE_RELEASE_CLIENT = 9, /**< 归还失败，须同时查看消费事实。 */
    VIREO_CLIENT_DEADLINE_CHECK_IDLE_STATE = 10, /**< 传输空闲策略要求当前 OPEN。 */
    VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME = 11 /**< 空闲样本、原期限或受检加法拒绝。 */
} vireo_client_deadline_stage_t;

/** 独立数值诊断，不保存资源指针；所有路径发布，不作为事务或 wire ABI。 */
typedef struct vireo_client_deadline_close_error {
    vireo_client_deadline_stage_t stage; /**< 本层失败阶段，成功为 NONE。 */
    bool close_called; /**< 是否调用过公开关闭入口；不证明意图提交、同步或归还。 */
    vireo_tcp_server_client_error_t client_error; /**< 关闭调用的完整原诊断，其余路径逻辑零。 */
} vireo_client_deadline_close_error_t;

/** 独立数值报告；错误分类与消费事实不同，不拥有或保活资源。 */
typedef struct vireo_client_deadline_release_report {
    vireo_client_deadline_stage_t stage; /**< 成功 NONE，否则原检查或新 READY／归还阶段。 */
    bool release_called; /**< 是否调用归还依赖，不保证消费或成功。 */
    bool client_consumed; /**< 返回租约已全零，旧客户所有权已消费；不证明 close 成功。 */
    vireo_tcp_server_client_error_t client_error; /**< 归还完整原诊断，其余路径逻辑零。 */
} vireo_client_deadline_release_report_t;

/**
 * @brief 依次公开核验当前客户及 timer 后，提交两种完整数值身份
 *
 * @param[in] server
 *     非空存活 server，只短借到返回；不获取 connection 或内部 loop 指针。
 * @param[in] wheel
 *     非空存活轮，只短借到返回；已 prepare、仍活跃的 timer 才能通过。
 * @param[in] client
 *     完整公开客户租约；closing 客户仍允许核验。
 * @param[in] timer
 *     完整公开 timer 身份；停止轮内仍活跃的登记允许核验。
 * @param[out] out_binding
 *     必需独立数值输出，入口可为任意值；全成功才覆盖，不自动处置旧关联。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖；成功 NONE，依赖失败定位对应检查。
 *
 * @retval VIREO_OK
 *     当前双方已通过公开观测，完整提交 binding。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，任一身份畸形；依赖跨 owner 等拒绝原分类返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     任一身份全零、客户已归还／旧代或 timer 已注销／旧代；未 prepare 亦沿依赖返回。
 * @retval VIREO_RESULT_RANGE
 *     同 owner 槽越界，沿依赖原分类返回；其他依赖拒绝同样原样返回。
 *
 * @note
 *     基本地址及双方形态先于空身份检查；随后先客户、再 timer，失败整个主输出及资源保持。
 * @note
 *     caller 保证此 timer 正确关联此客户；核验当前性不证明因果关系、授权或将来存活。
 * @note
 *     不登记、取消、重排、采样、推进、关闭或归还；无申请、无回调、O(1)。
 * @note
 *     同 Reactor 访问两对象；所有地址独立、存活、正确对齐、不重叠、不在自有资源内、非 errno。
 *     地址只短借到返回，不保存资源指针。所有路径保持入口 errno。
 */
vireo_result_t vireo_client_deadline_make(vireo_tcp_server_t const *server,
                                          vireo_timer_wheel_t const *wheel,
                                          vireo_connection_pool_lease_t client,
                                          vireo_timer_handle_t timer,
                                          vireo_client_deadline_binding_t *out_binding,
                                          vireo_client_deadline_stage_t *out_stage);

/**
 * @brief 匹配历史 timer 身份后，公开核验当前客户并提交完整客户快照
 *
 * @param[in] server
 *     非空存活 server，只短借到返回。
 * @param[in] binding
 *     caller 保管的完整数值关联；全零为空，半空或畸形无效，不消费或清除。
 * @param[in] expired
 *     必需未篡改的公开 take_expired／dispatch 通知，地址只借到返回，可用保存的值副本。
 * @param[out] out_client_info
 *     必需独立公开客户快照；无资源借用，失败保持整个输出。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖；匹配失败 MATCH_TIMER，客户拒绝 CHECK_CLIENT，成功 NONE。
 *
 * @retval VIREO_OK
 *     完整历史 timer 相等且客户仍当前，提交公开客户快照；closing 也允许。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、binding 半空／畸形或通知 handle 畸形；依赖错误原分类返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     binding 全零、通知 handle 全零、历史 timer 不等或客户已归还／旧代。
 * @retval VIREO_RESULT_RANGE
 *     客户同 owner 槽越界；跨 owner 等其他依赖错误原分类返回。
 *
 * @note
 *     基本地址及全部形态先于空身份检查；先匹配 timer 三字段，再检查客户当前性。
 *     领取通知已注销 timer，故不再 wheel_get；期限快照不用于身份比较或动作策略。
 * @note
 *     caller 保证关联及通知来源；数值比较不认证来源、不反查绑定表、不防止错误业务关联。
 * @note
 *     同一历史通知可再次核验，不提供一次性交付、自动重试、期限选择、关闭或清理。
 * @note
 *     只读、无申请／回调、O(1)，失败保持资源及主输出；快照不保活客户。
 *     同 Reactor；存储独立存活对齐、不重叠、不在自有资源内、非 errno。所有路径保持入口 errno。
 */
vireo_result_t vireo_client_deadline_check_expired(vireo_tcp_server_t const *server,
                                                   vireo_client_deadline_binding_t binding,
                                                   vireo_timer_wheel_expired_t const *expired,
                                                   vireo_tcp_server_client_info_t *out_client_info,
                                                   vireo_client_deadline_stage_t *out_stage);

/**
 * @brief 核验当前客户、登记未来 timer，最后保存完整数值关联
 *
 * @param[in] server
 *     非空存活 server，只短借到返回；当前 closing 客户也允许登记。
 * @param[in,out] wheel
 *     非空存活轮，已 prepare；保留所有权，使用其原固定容量与预算。
 * @param[in] client
 *     完整当前客户租约，由公开准入取得；不是 fd 或异步任务身份。
 * @param[in] now_ns
 *     caller 提供的同域新鲜单调纳秒，至少为轮 origin；不隐式采样。
 * @param[in] deadline_ns
 *     同域有限纳秒期限，须严格大于 now；0 和 UINT64_MAX 均不是哨兵。
 * @param[in,out] binding
 *     必需独立 caller 记录，入口两个完整身份均逻辑全零；成功保存，失败保持全部字节。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖；客户失败 CHECK_CLIENT、登记失败 REGISTER_TIMER、成功 NONE。
 *
 * @retval VIREO_OK
 *     timer 已登记且完整 client／timer 关联已保存；没有登记后可失败步骤。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、binding 非空或客户形态畸形；其他依赖拒绝原分类返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     客户全空／已归还／旧代，或轮未 prepare，按 stage 区分。
 * @retval VIREO_RESULT_RANGE
 *     客户同 pool 槽越界或 now 早于 origin；跨 pool 等依赖错误原分类返回。
 * @retval VIREO_RESULT_TIMEOUT
 *     deadline 不晚于 now，不登记或执行到期动作。
 * @retval VIREO_RESULT_OVERFLOW
 *     量化边界不可表示或 timer 发序耗尽，不回绕或截限。
 * @retval VIREO_RESULT_BUSY
 *     期限合法且发序未耗尽，但轮登记表已满。
 * @retval VIREO_RESULT_CANCELLED
 *     轮已永久停止；仍沿轮原参数、准备、停止、时间和发序检查顺序。
 *
 * @note
 *     本层基本校验和空客户检查先于 public client_inspect，再 public wheel_register；
 *     所有可失败检查在保存之前，轮成功后只做数值提交，不再 make／get 或取消回滚。
 * @note
 *     caller 保管关联和通知反查；无新表、申请或容量，不限制同客户的不同 binding。
 *     不选择 idle／请求总期限、推进、重排或自动关闭；复制记录不保活资源。
 * @note
 *     失败资源及主输出保持，无自动重试；全路径保持入口 errno，成功不承诺 padding。
 *     同 Reactor；地址短借、独立存活对齐、不重叠、不在自有资源内、非 errno。
 */
vireo_result_t vireo_client_deadline_register(vireo_tcp_server_t const *server,
                                              vireo_timer_wheel_t *wheel,
                                              vireo_connection_pool_lease_t client,
                                              vireo_monotonic_ns_t now_ns,
                                              vireo_monotonic_ns_t deadline_ns,
                                              vireo_client_deadline_binding_t *binding,
                                              vireo_client_deadline_stage_t *out_stage);

/**
 * @brief 仅按 timer 身份取消登记，成功后清空 caller 的完整绑定记录
 *
 * @param[in,out] wheel
 *     非空存活所属轮，只短借；停止后仍允许取消活跃 timer。
 * @param[in,out] binding
 *     必需独立普通数值记录；客户可已归还，入口仍须双方形态完整，成功清空。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖；依赖拒绝 CANCEL_TIMER、成功或基本拒绝 NONE。
 *
 * @retval VIREO_OK
 *     公开取消成功，timer 全部旧副本失效，binding 两种身份逻辑全零。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、binding 半空／畸形或已准备轮的跨 owner timer。
 * @retval VIREO_RESULT_RANGE
 *     已准备且同 owner 的 timer 槽越界；其他依赖错误原分类返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     binding 全空、轮未 prepare、timer 已注销或旧代；不是重复成功，整个记录保持。
 *
 * @note
 *     不查询客户当前性、server 或时间；客户归还不妨碍取消仍活跃的 timer。
 *     复制局部 timer 调公开 cancel，只有 OK 才清记录；不手工摘链或补偿轮状态。
 * @note
 *     已领取的通知使 timer 注销，随后取消 NF 仍保留历史绑定；不盲清或重试。
 *     可信通知处理后的数值账由 caller／后续消费项负责，清零值本身不取消 timer。
 * @note
 *     无新申请、回调、网络关闭或业务清理；失败主输出及资源保持，全路径保持入口 errno。
 *     同 Reactor；地址短借、独立存活对齐、不重叠、不在自有资源内、非 errno。
 */
vireo_result_t vireo_client_deadline_cancel(vireo_timer_wheel_t *wheel,
                                            vireo_client_deadline_binding_t *binding,
                                            vireo_client_deadline_stage_t *out_stage);

/**
 * @brief 核验当前客户后显式重排活跃 timer，保持完整绑定身份
 *
 * @param[in] server
 *     非空存活 server，只短借到返回；当前 closing 客户也允许核验。
 * @param[in,out] wheel
 *     非空存活所属轮，只短借到返回；须已 prepare 且未停止。
 * @param[in] binding
 *     caller 保管的完整关联，按值传入，不要求保存于记录表，不拥有或保活资源。
 * @param[in] now_ns
 *     caller 提供同 CLOCK_MONOTONIC 域的新鲜纳秒，至少为轮 origin；本入口不采样。
 * @param[in] deadline_ns
 *     同域有限新期限，严格晚于 now，受检向上量化；0 与 UINT64_MAX 无哨兵含义。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖；客户拒绝 CHECK_CLIENT，重排拒绝 REARM_TIMER，成功 NONE。
 *
 * @retval VIREO_OK
 *     活跃 timer 已重排；client、timer 完整身份及任何数值记录表保持，无新发序。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、绑定半空／畸形；跨 pool／owner 等依赖拒绝原分类返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     绑定全空、客户已归还／旧代、轮未 prepare 或 timer 已取消／领取／旧代。
 * @retval VIREO_RESULT_RANGE
 *     依赖同 owner 槽越界或 now 早于 origin；其他依赖拒绝原样返回。
 * @retval VIREO_RESULT_CANCELLED
 *     客户和 timer 身份有效，但轮已永久停止；判定先于时间运算。
 * @retval VIREO_RESULT_TIMEOUT
 *     新期限不晚于 now；不执行到期动作。
 * @retval VIREO_RESULT_OVERFLOW
 *     新期限量化边界不可表示；不回绕、截限或改动原期限。
 *
 * @note
 *     本层基本形态及空检查后先 public client_inspect，再沿 wheel_rearm 的身份、停止、时间顺序。
 *     所有失败保持轮原期限、链位及身份；本入口不写 binding 或记录表，全路径保持入口 errno。
 * @note
 *     原期限已过或已发现但未领取的 ready 仍活跃，合法 future 重排可撤回 ready 通知。
 *     领取或取消使身份失效，历史绑定不能复活 timer；重排不推进轮的时间游标。
 * @note
 *     caller 保证关联及时间来源，并决定是否允许晚活动续期；不选择 idle／请求总期限策略。
 *     无申请、回调、表操作、自动取消、关闭、清理或重试；成功后无可失败步骤，O(1)。
 * @note
 *     同 Reactor；借用地址独立存活对齐、不重叠、不在自有资源内、非 errno，不保存任何地址。
 */
vireo_result_t vireo_client_deadline_rearm(vireo_tcp_server_t const *server,
                                           vireo_timer_wheel_t *wheel,
                                           vireo_client_deadline_binding_t binding,
                                           vireo_monotonic_ns_t now_ns,
                                           vireo_monotonic_ns_t deadline_ns,
                                           vireo_client_deadline_stage_t *out_stage);

/**
 * @brief 核验历史到期身份及当前客户后，一次显式请求关闭
 *
 * @param[in,out] server
 *     非空存活 server，同 Reactor 仅借到返回，不保存地址或改变所有权。
 * @param[in] binding
 *     caller 保管的完整关联值，不清空；历史 timer 已注销，不再要求其当前活跃。
 * @param[in] expired
 *     必需未篡改的公开 take_expired／dispatch 通知或其值副本，只借到返回。
 * @param[in] mode
 *     显式 DRAIN 或 IMMEDIATE，无默认；沿旧关闭合同允许重复、升级及反向 BUSY。
 * @param[in] reason
 *     既有六个非 NONE 理由之一，无默认；首次合法理由永久保持，到期可由 caller 选 APPLICATION。
 * @param[out] out_error
 *     可空独立诊断，每路径覆盖全部逻辑字段，不承诺 padding；成功 NONE／true／原零诊断。
 *
 * @retval VIREO_OK
 *     当前客户的关闭请求成功；不保证发送、归还、fd 关闭或业务事务完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     server／通知 NULL、mode／reason 非法或身份畸形；其他依赖原分类返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空身份、历史 timer 不匹配、客户已归还／旧代；不将旧通知当新客户的控制权。
 * @retval VIREO_RESULT_RANGE
 *     客户同 pool 槽越界；跨 pool 等依赖错误原样返回。
 * @retval VIREO_RESULT_BUSY
 *     关闭依赖在途或 IMMEDIATE 反向请求 DRAIN，沿原分类返回。
 * @retval VIREO_RESULT_IO
 *     关闭关注同步失败，意图和新逻辑阶段可能已提交，不能当作无副作用。
 * @retval 其他非OK结果
 *     公开检查或关闭依赖原分类返回，无自动重试、清理或回滚。
 *
 * @note
 *     基本地址及 mode／reason 先验，再沿 check_expired 的完整形态、空身份、历史匹配、客户当前顺序。
 *     检查失败未调用关闭：close_called=false，原检查 stage，client_error 逻辑零；资源保持。
 * @note
 *     关闭调用时 close_called=true，仅记录调用事实；失败 stage 为 REQUEST_CLOSE_CLIENT。
 *     原 server 诊断完整保留；IO 可能已提交关闭意图／新阶段，旧关注仍保持。
 *     caller 可公开观测／refresh，不能假装恢复 OPEN。
 * @note
 *     DRAIN 仅后续发送既有队列，无排空期限；IMMEDIATE 逻辑 READY 但资源和名额仍待 release_client。
 *     不自动查表、领取、采样、排队、发送、refresh、归还或取消其他 timer，不改变期限策略。
 * @note
 *     本入口不写 binding／通知／表；外层已领取通知和转出记录不回滚，caller 保留值及诊断处理。
 *     可信历史可重复核验，不提供动作恰一次或来源认证；成功关闭后无可失败后置步骤。
 * @note
 *     无新申请，O(1) 有界公开操作，关闭依赖至多一次必要 MOD；不保证内核耗时或对端收到。
 *     地址独立存活对齐、不重叠、不在自有资源内、非 errno；全部路径保持入口 errno。
 */
vireo_result_t vireo_client_deadline_request_close_expired(
    vireo_tcp_server_t *server, vireo_client_deadline_binding_t binding,
    vireo_timer_wheel_expired_t const *expired, vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_client_deadline_close_error_t *out_error);

/**
 * @brief 核验历史到期和当前客户，仅 READY 时尝试一次归还并报告消费事实
 *
 * @param[in,out] server
 *     非空存活 server，同 Reactor 短借，全部客户字节借用已经结束。
 * @param[in,out] binding
 *     必需独立完整关联地址；消费后全清，未消费失败保持，不保存地址。
 * @param[in] expired
 *     必需未篡改公开通知或值副本，只借到返回；DRAIN 期间 caller 自行保留。
 * @param[out] out_report
 *     必需独立报告，每路径覆盖全部逻辑字段，不承诺 padding；NULL 不执行操作。
 *
 * @retval VIREO_OK
 *     客户归还成功，绑定全清，报告 NONE／true／true／原零诊断。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或身份畸形；跨 pool 等依赖拒绝原样返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空身份、历史不匹配或旧客户，不自动当成功或清空旧记录。
 * @retval VIREO_RESULT_RANGE
 *     客户同 pool 槽越界，沿公开核验原分类返回。
 * @retval VIREO_RESULT_BUSY
 *     客户 OPEN／DRAINING 尚非 READY，或归还依赖在途／拒绝；阶段区分来源。
 * @retval VIREO_RESULT_IO
 *     DEL 失败未消费，或关闭失败已消费；依返回租约清零事实报告并处理 binding。
 * @retval 其他非OK结果
 *     依赖原分类透传，不能只看分类判断是否消费或部分状态。
 *
 * @note
 *     基本地址先验，再沿 check_expired 完整形态、空、历史匹配及客户当前顺序，最后 READY 门槛。
 *     核验或 READY 拒绝未调用归还，两个 bool 为 false，原嵌套诊断逻辑零。
 * @note
 *     在局部客户租约上调用一次 release_client，返回租约全零则 client_consumed=true，绑定全清。
 *     包括消费型 IO；原分类及完整诊断不改，旧租约副本和字节借用失效，不 retry close。
 * @note
 *     未消费保 binding，但客户可能已经 DEL 成功而解绑；不 ADD 回滚、自动重试或保证全失败保持。
 *     caller 保留需要的原值做审计；报告只说明本次事实，不认证来源、保活或保证动作恰一次。
 * @note
 *     不 request_close、send、refresh、schedule、查表、取消其他 timer 或扫描全池，无新申请。
 *     已取记录不放回；单项 O(1) 可能 DEL／close／free，不承诺内核耗时；成功后无可失败步骤。
 * @note
 *     所有地址独立存活对齐、不重叠、不在自有资源内、非 errno；只短借，全部路径保持入口 errno。
 */
vireo_result_t vireo_client_deadline_release_ready_expired(
    vireo_tcp_server_t *server, vireo_client_deadline_binding_t *binding,
    vireo_timer_wheel_expired_t const *expired, vireo_client_deadline_release_report_t *out_report);

#endif /* VIREO_NET_CLIENT_DEADLINE_H */
