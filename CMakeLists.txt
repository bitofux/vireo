# 声明vireo要求的最低cmake版本为3.20
cmake_minimum_required(VERSION 3.20)

project(
    # 项目名称 vireo 
    vireo
    # 初始版本
    VERSION 0.1.0
    # 项目简单描述
    DESCRIPTION "An event-driven object storage and virtual file service"
    # C language
    LANGUAGES C
)

# 设置C11标准
set(CMAKE_C_STANDARD 11)
# 编译器必须支持C11
set(CMAKE_C_STANDARD_REQUIRED ON)
# 使用标准C11，而不是gnu11
set(CMAKE_C_EXTENSIONS OFF)

# CTest测试
include(CTest)

# 加载 vireo target 的统一严格警告
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/vireo_warnings.cmake")

# 加载 vireo target 的 sanitizer 配置
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/vireo_sanitizers.cmake")

# vireo_result 静态库
add_library(
    vireo_result
    STATIC
    src/base/result.c
)

# vireo_result 的公共头文件根目录
target_include_directories(
    vireo_result
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 为 vireo_result 启用统一严格警告
vireo_target_enable_warnings(vireo_result)

# 为 vireo_result 应用当前 sanitizer 配置
vireo_target_enable_sanitizers(vireo_result)

# vireo_checked 静态库
add_library (
    vireo_checked
    STATIC
    src/base/checked.c
)

# vireo_checked 依赖vireo_result，并继承公共 include 根
target_link_libraries(
    vireo_checked
    PUBLIC
        vireo_result
)

# 为 vireo_checked 启用统一严格警告
vireo_target_enable_warnings(vireo_checked)

# 为 vireo_checked 应用当前 sanitizer 配置
vireo_target_enable_sanitizers(vireo_checked)

# 单调采集与期限数学：公共值合同独立于 Linux/POSIX 原生类型
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(vireo_clock STATIC src/base/clock.c src/base/clock_deadline.c src/base/clock_wait.c)
    target_link_libraries(vireo_clock PUBLIC vireo_result PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_clock)
    vireo_target_enable_sanitizers(vireo_clock)
    if(BUILD_TESTING)
        add_executable(vireo_clock_monotonic_test tests/base/test_clock_monotonic.c)
        target_include_directories(vireo_clock_monotonic_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_clock_monotonic_test PRIVATE vireo_clock)
        vireo_target_enable_warnings(vireo_clock_monotonic_test)
        vireo_target_enable_sanitizers(vireo_clock_monotonic_test)
        add_test(NAME vireo_clock_monotonic_test COMMAND vireo_clock_monotonic_test)
        set_tests_properties(vireo_clock_monotonic_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_clock_deadline_test tests/base/test_clock_deadline.c)
        target_link_libraries(vireo_clock_deadline_test PRIVATE vireo_clock)
        vireo_target_enable_warnings(vireo_clock_deadline_test)
        vireo_target_enable_sanitizers(vireo_clock_deadline_test)
        add_test(NAME vireo_clock_deadline_test COMMAND vireo_clock_deadline_test)
        set_tests_properties(vireo_clock_deadline_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_clock_wait_test tests/base/test_clock_wait.c)
        target_link_libraries(vireo_clock_wait_test PRIVATE vireo_clock)
        vireo_target_enable_warnings(vireo_clock_wait_test)
        vireo_target_enable_sanitizers(vireo_clock_wait_test)
        add_test(NAME vireo_clock_wait_test COMMAND vireo_clock_wait_test)
        set_tests_properties(vireo_clock_wait_test PROPERTIES TIMEOUT 30)
    endif()
endif()

# timer 数值身份及固定 owner 登记：不执行时间轮动作
add_library(vireo_timer_handle STATIC src/timer/handle.c src/timer/handle_owner.c)
target_link_libraries(vireo_timer_handle PUBLIC vireo_result PRIVATE vireo_checked)
vireo_target_enable_warnings(vireo_timer_handle)
vireo_target_enable_sanitizers(vireo_timer_handle)
if(BUILD_TESTING)
    add_executable(vireo_timer_handle_values_test tests/timer/test_handle_values.c)
    target_link_libraries(vireo_timer_handle_values_test PRIVATE vireo_timer_handle)
    vireo_target_enable_warnings(vireo_timer_handle_values_test)
    vireo_target_enable_sanitizers(vireo_timer_handle_values_test)
    add_test(NAME vireo_timer_handle_values_test COMMAND vireo_timer_handle_values_test)
    set_tests_properties(vireo_timer_handle_values_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_timer_handle_owner_test tests/timer/test_handle_owner.c)
    target_include_directories(vireo_timer_handle_owner_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_timer_handle_owner_test PRIVATE vireo_timer_handle Threads::Threads)
    vireo_target_enable_warnings(vireo_timer_handle_owner_test)
    vireo_target_enable_sanitizers(vireo_timer_handle_owner_test)
    add_test(NAME vireo_timer_handle_owner_test COMMAND vireo_timer_handle_owner_test)
    set_tests_properties(vireo_timer_handle_owner_test PROPERTIES TIMEOUT 30)
endif()

# 时间轮几何、固定资源、真实登记与有界到期发现，不执行业务动作
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(vireo_timer_wheel STATIC src/timer/wheel_time.c src/timer/wheel.c src/timer/wheel_registry.c src/timer/wheel_advance.c src/timer/wheel_shutdown.c)
    target_link_libraries(vireo_timer_wheel PUBLIC vireo_clock vireo_timer_handle PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_timer_wheel)
    vireo_target_enable_sanitizers(vireo_timer_wheel)
    if(BUILD_TESTING)
        add_executable(vireo_timer_wheel_time_test tests/timer/test_wheel_time.c)
        target_link_libraries(vireo_timer_wheel_time_test PRIVATE vireo_timer_wheel)
        vireo_target_enable_warnings(vireo_timer_wheel_time_test)
        vireo_target_enable_sanitizers(vireo_timer_wheel_time_test)
        add_test(NAME vireo_timer_wheel_time_test COMMAND vireo_timer_wheel_time_test)
        set_tests_properties(vireo_timer_wheel_time_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_timer_wheel_lifecycle_test tests/timer/test_wheel_lifecycle.c)
        target_include_directories(vireo_timer_wheel_lifecycle_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_timer_wheel_lifecycle_test PRIVATE vireo_timer_wheel)
        vireo_target_enable_warnings(vireo_timer_wheel_lifecycle_test)
        vireo_target_enable_sanitizers(vireo_timer_wheel_lifecycle_test)
        add_test(NAME vireo_timer_wheel_lifecycle_test COMMAND vireo_timer_wheel_lifecycle_test)
        set_tests_properties(vireo_timer_wheel_lifecycle_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_timer_wheel_registry_test tests/timer/test_wheel_registry.c)
        target_include_directories(vireo_timer_wheel_registry_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_timer_wheel_registry_test PRIVATE vireo_timer_wheel)
        vireo_target_enable_warnings(vireo_timer_wheel_registry_test)
        vireo_target_enable_sanitizers(vireo_timer_wheel_registry_test)
        add_test(NAME vireo_timer_wheel_registry_test COMMAND vireo_timer_wheel_registry_test)
        set_tests_properties(vireo_timer_wheel_registry_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_timer_wheel_advance_test tests/timer/test_wheel_advance.c)
        target_include_directories(vireo_timer_wheel_advance_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_timer_wheel_advance_test PRIVATE vireo_timer_wheel)
        vireo_target_enable_warnings(vireo_timer_wheel_advance_test)
        vireo_target_enable_sanitizers(vireo_timer_wheel_advance_test)
        add_test(NAME vireo_timer_wheel_advance_test COMMAND vireo_timer_wheel_advance_test)
        set_tests_properties(vireo_timer_wheel_advance_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_timer_wheel_shutdown_test tests/timer/test_wheel_shutdown.c)
        target_include_directories(vireo_timer_wheel_shutdown_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_timer_wheel_shutdown_test PRIVATE vireo_timer_wheel)
        vireo_target_enable_warnings(vireo_timer_wheel_shutdown_test)
        vireo_target_enable_sanitizers(vireo_timer_wheel_shutdown_test)
        add_test(NAME vireo_timer_wheel_shutdown_test COMMAND vireo_timer_wheel_shutdown_test)
        set_tests_properties(vireo_timer_wheel_shutdown_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_timer_wheel_integration_test tests/timer/test_wheel_integration.c)
        target_link_libraries(vireo_timer_wheel_integration_test PRIVATE vireo_timer_wheel)
        vireo_target_enable_warnings(vireo_timer_wheel_integration_test)
        vireo_target_enable_sanitizers(vireo_timer_wheel_integration_test)
        add_test(NAME vireo_timer_wheel_integration_test COMMAND vireo_timer_wheel_integration_test)
        set_tests_properties(vireo_timer_wheel_integration_test PROPERTIES TIMEOUT 30)
    endif()
endif()

# vireo protocol 静态库
add_library(
    vireo_protocol
    STATIC
    src/protocol/protocol.c
)

target_include_directories(
    vireo_protocol
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 为 vireo_protocol 启用统一严格警告
vireo_target_enable_warnings(vireo_protocol)

# 为 vireo_protocol 应用当前 sanitizer 配置
vireo_target_enable_sanitizers(vireo_protocol)

# vireo config 静态库
add_library(
    vireo_config
    STATIC
    src/base/config.c
)

# vireo_config 的公共头文件根目录
target_include_directories(
    vireo_config
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 公共接口使用 result；实现内部使用 checked arithmetic
target_link_libraries(
    vireo_config
    PUBLIC
        vireo_result
    PRIVATE
        vireo_checked
)

# 为 vireo_config 启用统一严格警告
vireo_target_enable_warnings(vireo_config)

# 为 vireo_config 应用当前 sanitizer 配置
vireo_target_enable_sanitizers(vireo_config)

# vireo protocol codec 静态库
add_library(
    vireo_protocol_codec
    STATIC
    src/protocol/codec.c
)
# vireo_protocol_codec 的公共接口依赖 protocol 定义和内部返回值类型
target_link_libraries(
    vireo_protocol_codec
    PUBLIC
        vireo_result
        vireo_protocol
)
# 为 vireo_protocol_codec 启用统一严格警告
vireo_target_enable_warnings(vireo_protocol_codec)
# 为 vireo_protocol_codec 应用当前 sanitizer 配置
vireo_target_enable_sanitizers(vireo_protocol_codec)

# vireo TLV 静态库
add_library(
    vireo_tlv
    STATIC
    src/protocol/tlv.c
)

target_include_directories(
    vireo_tlv
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 公共头文件使用 result；实现内部使用 checked
target_link_libraries(
    vireo_tlv
    PUBLIC
        vireo_result
    PRIVATE
        vireo_checked
)

vireo_target_enable_warnings(vireo_tlv)
vireo_target_enable_sanitizers(vireo_tlv)

# vireo chunk 静态库
add_library(
    vireo_chunk
    STATIC
    src/protocol/chunk.c
)

target_include_directories(
    vireo_chunk
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 公共接口依赖 result 和 protocol；实现内部使用 checked
target_link_libraries(
    vireo_chunk
    PUBLIC
        vireo_result
        vireo_protocol
    PRIVATE
        vireo_checked
)

# 为 chunk 库启用统一严格警告和 sanitizer
vireo_target_enable_warnings(vireo_chunk)
vireo_target_enable_sanitizers(vireo_chunk)

# 日志公共库：纯格式化、资源生命周期、同步 emit/flush 与单归档轮转
find_package(Threads REQUIRED)
add_library(vireo_log STATIC src/base/log.c)
target_link_libraries(vireo_log PUBLIC vireo_result PRIVATE vireo_checked Threads::Threads)
vireo_target_enable_warnings(vireo_log)
vireo_target_enable_sanitizers(vireo_log)

# buffer：生命周期、字节进度与显式整理/尾部预留/回缩
add_library(vireo_buffer STATIC src/base/buffer.c)
target_link_libraries(vireo_buffer PUBLIC vireo_result PRIVATE vireo_checked)
vireo_target_enable_warnings(vireo_buffer)
vireo_target_enable_sanitizers(vireo_buffer)

# pool：受检槽位布局、有界生命周期与数值租约
add_library(vireo_pool STATIC src/base/pool.c)
target_link_libraries(vireo_pool PUBLIC vireo_result PRIVATE vireo_checked)
vireo_target_enable_warnings(vireo_pool)
vireo_target_enable_sanitizers(vireo_pool)

# Linux epoll：实例生命周期、固定批次工作区、LT 注册及有界等待
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(vireo_epoll STATIC src/net/epoll.c)
    target_link_libraries(vireo_epoll PUBLIC vireo_result PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_epoll)
    vireo_target_enable_sanitizers(vireo_epoll)

    # event loop：独占 epoll、固定工作区/注册表、有效身份与一轮分发
    add_library(vireo_event_loop STATIC src/net/event_loop.c)
    target_link_libraries(vireo_event_loop PUBLIC vireo_result vireo_epoll PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_event_loop)
    vireo_target_enable_sanitizers(vireo_event_loop)

    # connection：固定双 buffer、独占 socket、有界接收与只读帧识别
    add_library(vireo_connection STATIC src/net/connection.c)
    target_link_libraries(vireo_connection
        PUBLIC vireo_result vireo_buffer vireo_protocol_codec vireo_event_loop PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_connection)
    vireo_target_enable_sanitizers(vireo_connection)

    # connection pool：固定管理槽、连接所有权与有界总容量
    add_library(vireo_connection_pool STATIC src/net/connection_pool.c)
    target_link_libraries(vireo_connection_pool
        PUBLIC vireo_result vireo_connection PRIVATE vireo_pool vireo_checked)
    vireo_target_enable_warnings(vireo_connection_pool)
    vireo_target_enable_sanitizers(vireo_connection_pool)

    # acceptor：监听 fd 唯一所有权、资源生命周期与有界客户端接入
    add_library(vireo_acceptor STATIC src/net/acceptor.c)
    target_link_libraries(vireo_acceptor PUBLIC vireo_result vireo_event_loop)
    vireo_target_enable_warnings(vireo_acceptor)
    vireo_target_enable_sanitizers(vireo_acceptor)

    # tcp server：空资源根、公开 loop/pool 装配与统一容器预算
    add_library(vireo_tcp_server STATIC src/net/tcp_server.c src/net/sync_commands.c)
    target_link_libraries(vireo_tcp_server
        PUBLIC vireo_result vireo_event_loop vireo_connection_pool vireo_acceptor
        PRIVATE vireo_checked vireo_tlv)
    vireo_target_enable_warnings(vireo_tcp_server)
    vireo_target_enable_sanitizers(vireo_tcp_server)
endif()

# BUILD_TESTING 由 include(CTest) 提供，默认开启
if (BUILD_TESTING)
    if(TARGET vireo_tcp_server)
        add_executable(vireo_tcp_server_lifecycle_test tests/net/test_tcp_server_lifecycle.c)
        target_include_directories(vireo_tcp_server_lifecycle_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_lifecycle_test PRIVATE vireo_tcp_server)
        vireo_target_enable_warnings(vireo_tcp_server_lifecycle_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_lifecycle_test)
        add_test(NAME vireo_tcp_server_lifecycle_test COMMAND vireo_tcp_server_lifecycle_test)
        set_tests_properties(vireo_tcp_server_lifecycle_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_tcp_server_listener_test tests/net/test_tcp_server_listener.c)
        target_include_directories(vireo_tcp_server_listener_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_listener_test PRIVATE vireo_tcp_server)
        vireo_target_enable_warnings(vireo_tcp_server_listener_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_listener_test)
        add_test(NAME vireo_tcp_server_listener_test COMMAND vireo_tcp_server_listener_test)
        set_tests_properties(vireo_tcp_server_listener_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_tcp_server_admission_test tests/net/test_tcp_server_admission.c)
        target_include_directories(vireo_tcp_server_admission_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_admission_test PRIVATE vireo_tcp_server)
        vireo_target_enable_warnings(vireo_tcp_server_admission_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_admission_test)
        add_test(NAME vireo_tcp_server_admission_test COMMAND vireo_tcp_server_admission_test)
        set_tests_properties(vireo_tcp_server_admission_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_client_io_test tests/net/test_tcp_server_client_io.c)
        target_include_directories(vireo_tcp_server_client_io_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_client_io_test PRIVATE vireo_tcp_server)
        vireo_target_enable_warnings(vireo_tcp_server_client_io_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_client_io_test)
        add_test(NAME vireo_tcp_server_client_io_test COMMAND vireo_tcp_server_client_io_test)
        set_tests_properties(vireo_tcp_server_client_io_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_client_framing_test tests/net/test_tcp_server_client_framing.c)
        target_include_directories(vireo_tcp_server_client_framing_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_client_framing_test PRIVATE vireo_tcp_server)
        vireo_target_enable_warnings(vireo_tcp_server_client_framing_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_client_framing_test)
        add_test(NAME vireo_tcp_server_client_framing_test COMMAND vireo_tcp_server_client_framing_test)
        set_tests_properties(vireo_tcp_server_client_framing_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_sync_handler_test tests/net/test_tcp_server_sync_handler.c)
        target_include_directories(vireo_tcp_server_sync_handler_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_sync_handler_test PRIVATE vireo_tcp_server)
        vireo_target_enable_warnings(vireo_tcp_server_sync_handler_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_sync_handler_test)
        add_test(NAME vireo_tcp_server_sync_handler_test COMMAND vireo_tcp_server_sync_handler_test)
        set_tests_properties(vireo_tcp_server_sync_handler_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_client_policy_test tests/net/test_tcp_server_client_policy.c)
        target_include_directories(vireo_tcp_server_client_policy_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_client_policy_test PRIVATE vireo_tcp_server)
        vireo_target_enable_warnings(vireo_tcp_server_client_policy_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_client_policy_test)
        add_test(NAME vireo_tcp_server_client_policy_test COMMAND vireo_tcp_server_client_policy_test)
        set_tests_properties(vireo_tcp_server_client_policy_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_client_drive_test tests/net/test_tcp_server_client_drive.c)
        target_include_directories(vireo_tcp_server_client_drive_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_client_drive_test PRIVATE vireo_tcp_server)
        vireo_target_enable_warnings(vireo_tcp_server_client_drive_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_client_drive_test)
        add_test(NAME vireo_tcp_server_client_drive_test COMMAND vireo_tcp_server_client_drive_test)
        set_tests_properties(vireo_tcp_server_client_drive_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_scheduling_test tests/net/test_tcp_server_scheduling.c)
        target_include_directories(vireo_tcp_server_scheduling_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_scheduling_test PRIVATE vireo_tcp_server)
        vireo_target_enable_warnings(vireo_tcp_server_scheduling_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_scheduling_test)
        add_test(NAME vireo_tcp_server_scheduling_test COMMAND vireo_tcp_server_scheduling_test)
        set_tests_properties(vireo_tcp_server_scheduling_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_auto_admission_test tests/net/test_tcp_server_auto_admission.c)
        target_link_libraries(vireo_tcp_server_auto_admission_test PRIVATE vireo_tcp_server)
        target_include_directories(vireo_tcp_server_auto_admission_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        vireo_target_enable_warnings(vireo_tcp_server_auto_admission_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_auto_admission_test)
        add_test(NAME vireo_tcp_server_auto_admission_test COMMAND vireo_tcp_server_auto_admission_test)
        set_tests_properties(vireo_tcp_server_auto_admission_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_run_stop_test tests/net/test_tcp_server_run_stop.c)
        target_link_libraries(vireo_tcp_server_run_stop_test PRIVATE vireo_tcp_server Threads::Threads)
        target_include_directories(vireo_tcp_server_run_stop_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        vireo_target_enable_warnings(vireo_tcp_server_run_stop_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_run_stop_test)
        add_test(NAME vireo_tcp_server_run_stop_test COMMAND vireo_tcp_server_run_stop_test)
        set_tests_properties(vireo_tcp_server_run_stop_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_shutdown_test tests/net/test_tcp_server_shutdown.c)
        target_link_libraries(vireo_tcp_server_shutdown_test PRIVATE vireo_tcp_server)
        target_include_directories(vireo_tcp_server_shutdown_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        vireo_target_enable_warnings(vireo_tcp_server_shutdown_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_shutdown_test)
        add_test(NAME vireo_tcp_server_shutdown_test COMMAND vireo_tcp_server_shutdown_test)
        set_tests_properties(vireo_tcp_server_shutdown_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_ready_release_test tests/net/test_tcp_server_ready_release.c)
        target_link_libraries(vireo_tcp_server_ready_release_test PRIVATE vireo_tcp_server)
        target_include_directories(vireo_tcp_server_ready_release_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        vireo_target_enable_warnings(vireo_tcp_server_ready_release_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_ready_release_test)
        add_test(NAME vireo_tcp_server_ready_release_test COMMAND vireo_tcp_server_ready_release_test)
        set_tests_properties(vireo_tcp_server_ready_release_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_close_policy_test tests/net/test_tcp_server_close_policy.c)
        target_link_libraries(vireo_tcp_server_close_policy_test PRIVATE vireo_tcp_server)
        target_include_directories(vireo_tcp_server_close_policy_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        vireo_target_enable_warnings(vireo_tcp_server_close_policy_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_close_policy_test)
        add_test(NAME vireo_tcp_server_close_policy_test COMMAND vireo_tcp_server_close_policy_test)
        set_tests_properties(vireo_tcp_server_close_policy_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_close_batch_test tests/net/test_tcp_server_close_batch.c)
        target_link_libraries(vireo_tcp_server_close_batch_test PRIVATE vireo_tcp_server)
        target_include_directories(vireo_tcp_server_close_batch_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        vireo_target_enable_warnings(vireo_tcp_server_close_batch_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_close_batch_test)
        add_test(NAME vireo_tcp_server_close_batch_test COMMAND vireo_tcp_server_close_batch_test)
        set_tests_properties(vireo_tcp_server_close_batch_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_tcp_server_sync_commands_test tests/net/test_tcp_server_sync_commands.c)
        target_link_libraries(vireo_tcp_server_sync_commands_test PRIVATE vireo_tcp_server vireo_tlv)
        vireo_target_enable_warnings(vireo_tcp_server_sync_commands_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_sync_commands_test)
        add_test(NAME vireo_tcp_server_sync_commands_test COMMAND vireo_tcp_server_sync_commands_test)
        set_tests_properties(vireo_tcp_server_sync_commands_test PROPERTIES TIMEOUT 30)
        # 阶段4同步网络组合验证：真实TCP、预算公平、背压和生命周期。
        add_executable(vireo_tcp_server_integration_test tests/net/test_tcp_server_integration.c)
        target_include_directories(vireo_tcp_server_integration_test PRIVATE ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_integration_test PRIVATE vireo_tcp_server vireo_tlv)
        vireo_target_enable_warnings(vireo_tcp_server_integration_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_integration_test)
        add_test(NAME vireo_tcp_server_integration_test COMMAND vireo_tcp_server_integration_test)
        set_tests_properties(vireo_tcp_server_integration_test PROPERTIES TIMEOUT 30)
    endif()
    if(TARGET vireo_acceptor)
        add_executable(vireo_acceptor_lifecycle_test tests/net/test_acceptor_lifecycle.c)
        target_include_directories(vireo_acceptor_lifecycle_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_acceptor_lifecycle_test PRIVATE vireo_acceptor)
        vireo_target_enable_warnings(vireo_acceptor_lifecycle_test)
        vireo_target_enable_sanitizers(vireo_acceptor_lifecycle_test)
        add_test(NAME vireo_acceptor_lifecycle_test COMMAND vireo_acceptor_lifecycle_test)
        set_tests_properties(vireo_acceptor_lifecycle_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_acceptor_accept_test tests/net/test_acceptor_accept.c)
        target_include_directories(vireo_acceptor_accept_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_acceptor_accept_test PRIVATE vireo_acceptor)
        vireo_target_enable_warnings(vireo_acceptor_accept_test)
        vireo_target_enable_sanitizers(vireo_acceptor_accept_test)
        add_test(NAME vireo_acceptor_accept_test COMMAND vireo_acceptor_accept_test)
        set_tests_properties(vireo_acceptor_accept_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_acceptor_loop_binding_test tests/net/test_acceptor_loop_binding.c)
        target_include_directories(vireo_acceptor_loop_binding_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_acceptor_loop_binding_test PRIVATE vireo_acceptor)
        vireo_target_enable_warnings(vireo_acceptor_loop_binding_test)
        vireo_target_enable_sanitizers(vireo_acceptor_loop_binding_test)
        add_test(NAME vireo_acceptor_loop_binding_test COMMAND vireo_acceptor_loop_binding_test)
        set_tests_properties(vireo_acceptor_loop_binding_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_acceptor_integration_test tests/net/test_acceptor_integration.c)
        target_link_libraries(vireo_acceptor_integration_test
            PRIVATE vireo_acceptor vireo_connection_pool)
        vireo_target_enable_warnings(vireo_acceptor_integration_test)
        vireo_target_enable_sanitizers(vireo_acceptor_integration_test)
        add_test(NAME vireo_acceptor_integration_test COMMAND vireo_acceptor_integration_test)
        set_tests_properties(vireo_acceptor_integration_test PROPERTIES TIMEOUT 30)
    endif()
    if(TARGET vireo_connection_pool)
        add_executable(vireo_connection_pool_lifecycle_test
            tests/net/test_connection_pool_lifecycle.c)
        target_include_directories(vireo_connection_pool_lifecycle_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_connection_pool_lifecycle_test PRIVATE vireo_connection_pool)
        vireo_target_enable_warnings(vireo_connection_pool_lifecycle_test)
        vireo_target_enable_sanitizers(vireo_connection_pool_lifecycle_test)
        add_test(NAME vireo_connection_pool_lifecycle_test
            COMMAND vireo_connection_pool_lifecycle_test)
        set_tests_properties(vireo_connection_pool_lifecycle_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_connection_pool_ownership_test
            tests/net/test_connection_pool_ownership.c)
        target_include_directories(vireo_connection_pool_ownership_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_connection_pool_ownership_test PRIVATE vireo_connection_pool)
        vireo_target_enable_warnings(vireo_connection_pool_ownership_test)
        vireo_target_enable_sanitizers(vireo_connection_pool_ownership_test)
        add_test(NAME vireo_connection_pool_ownership_test
            COMMAND vireo_connection_pool_ownership_test)
        set_tests_properties(vireo_connection_pool_ownership_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_connection_pool_integration_test
            tests/net/test_connection_pool_integration.c)
        target_link_libraries(vireo_connection_pool_integration_test PRIVATE vireo_connection_pool)
        vireo_target_enable_warnings(vireo_connection_pool_integration_test)
        vireo_target_enable_sanitizers(vireo_connection_pool_integration_test)
        add_test(NAME vireo_connection_pool_integration_test
            COMMAND vireo_connection_pool_integration_test)
        set_tests_properties(vireo_connection_pool_integration_test PROPERTIES TIMEOUT 30)
    endif()
    if(TARGET vireo_connection)
        add_executable(vireo_connection_lifecycle_test tests/net/test_connection_lifecycle.c)
        target_include_directories(vireo_connection_lifecycle_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_connection_lifecycle_test PRIVATE vireo_connection)
        vireo_target_enable_warnings(vireo_connection_lifecycle_test)
        vireo_target_enable_sanitizers(vireo_connection_lifecycle_test)
        add_test(NAME vireo_connection_lifecycle_test COMMAND vireo_connection_lifecycle_test)
        set_tests_properties(vireo_connection_lifecycle_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_connection_receive_test tests/net/test_connection_receive.c)
        target_include_directories(vireo_connection_receive_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_connection_receive_test PRIVATE vireo_connection)
        vireo_target_enable_warnings(vireo_connection_receive_test)
        vireo_target_enable_sanitizers(vireo_connection_receive_test)
        add_test(NAME vireo_connection_receive_test COMMAND vireo_connection_receive_test)
        set_tests_properties(vireo_connection_receive_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_connection_framing_test tests/net/test_connection_framing.c)
        target_link_libraries(vireo_connection_framing_test PRIVATE vireo_connection)
        vireo_target_enable_warnings(vireo_connection_framing_test)
        vireo_target_enable_sanitizers(vireo_connection_framing_test)
        add_test(NAME vireo_connection_framing_test COMMAND vireo_connection_framing_test)
        set_tests_properties(vireo_connection_framing_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_connection_loop_binding_test tests/net/test_connection_loop_binding.c)
        target_include_directories(vireo_connection_loop_binding_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_connection_loop_binding_test PRIVATE vireo_connection)
        vireo_target_enable_warnings(vireo_connection_loop_binding_test)
        vireo_target_enable_sanitizers(vireo_connection_loop_binding_test)
        add_test(NAME vireo_connection_loop_binding_test COMMAND vireo_connection_loop_binding_test)
        set_tests_properties(vireo_connection_loop_binding_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_connection_flow_test tests/net/test_connection_flow.c)
        target_include_directories(vireo_connection_flow_test PRIVATE ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(vireo_connection_flow_test PRIVATE vireo_connection)
        vireo_target_enable_warnings(vireo_connection_flow_test)
        vireo_target_enable_sanitizers(vireo_connection_flow_test)
        add_test(NAME vireo_connection_flow_test COMMAND vireo_connection_flow_test)
        set_tests_properties(vireo_connection_flow_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_connection_close_test tests/net/test_connection_close.c)
        target_include_directories(vireo_connection_close_test PRIVATE ${PROJECT_SOURCE_DIR}/src)
        target_link_libraries(vireo_connection_close_test PRIVATE vireo_connection)
        vireo_target_enable_warnings(vireo_connection_close_test)
        vireo_target_enable_sanitizers(vireo_connection_close_test)
        add_test(NAME vireo_connection_close_test COMMAND vireo_connection_close_test)
        set_tests_properties(vireo_connection_close_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_connection_send_test tests/net/test_connection_send.c)
        target_include_directories(vireo_connection_send_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_connection_send_test PRIVATE vireo_connection)
        vireo_target_enable_warnings(vireo_connection_send_test)
        vireo_target_enable_sanitizers(vireo_connection_send_test)
        add_test(NAME vireo_connection_send_test COMMAND vireo_connection_send_test)
        set_tests_properties(vireo_connection_send_test PROPERTIES TIMEOUT 30)
    endif()

    if(TARGET vireo_epoll)
        add_executable(vireo_epoll_lifecycle_test tests/net/test_epoll_lifecycle.c)
        target_include_directories(vireo_epoll_lifecycle_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_epoll_lifecycle_test PRIVATE vireo_epoll)
        vireo_target_enable_warnings(vireo_epoll_lifecycle_test)
        vireo_target_enable_sanitizers(vireo_epoll_lifecycle_test)
        add_test(NAME vireo_epoll_lifecycle_test COMMAND vireo_epoll_lifecycle_test)
        set_tests_properties(vireo_epoll_lifecycle_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_epoll_registration_test tests/net/test_epoll_registration.c)
        target_include_directories(vireo_epoll_registration_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_epoll_registration_test PRIVATE vireo_epoll)
        vireo_target_enable_warnings(vireo_epoll_registration_test)
        vireo_target_enable_sanitizers(vireo_epoll_registration_test)
        add_test(NAME vireo_epoll_registration_test COMMAND vireo_epoll_registration_test)
        set_tests_properties(vireo_epoll_registration_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_epoll_wait_test tests/net/test_epoll_wait.c)
        target_include_directories(vireo_epoll_wait_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_epoll_wait_test PRIVATE vireo_epoll)
        vireo_target_enable_warnings(vireo_epoll_wait_test)
        vireo_target_enable_sanitizers(vireo_epoll_wait_test)
        add_test(NAME vireo_epoll_wait_test COMMAND vireo_epoll_wait_test)
        set_tests_properties(vireo_epoll_wait_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_event_loop_lifecycle_test tests/net/test_event_loop_lifecycle.c)
        target_include_directories(vireo_event_loop_lifecycle_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_event_loop_lifecycle_test PRIVATE vireo_event_loop)
        vireo_target_enable_warnings(vireo_event_loop_lifecycle_test)
        vireo_target_enable_sanitizers(vireo_event_loop_lifecycle_test)
        add_test(NAME vireo_event_loop_lifecycle_test COMMAND vireo_event_loop_lifecycle_test)
        set_tests_properties(vireo_event_loop_lifecycle_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_event_loop_registration_test tests/net/test_event_loop_registration.c)
        target_include_directories(vireo_event_loop_registration_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_event_loop_registration_test PRIVATE vireo_event_loop Threads::Threads)
        vireo_target_enable_warnings(vireo_event_loop_registration_test)
        vireo_target_enable_sanitizers(vireo_event_loop_registration_test)
        add_test(NAME vireo_event_loop_registration_test COMMAND vireo_event_loop_registration_test)
        set_tests_properties(vireo_event_loop_registration_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_event_loop_dispatch_test tests/net/test_event_loop_dispatch.c)
        target_include_directories(vireo_event_loop_dispatch_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_event_loop_dispatch_test PRIVATE vireo_event_loop)
        vireo_target_enable_warnings(vireo_event_loop_dispatch_test)
        vireo_target_enable_sanitizers(vireo_event_loop_dispatch_test)
        add_test(NAME vireo_event_loop_dispatch_test COMMAND vireo_event_loop_dispatch_test)
        set_tests_properties(vireo_event_loop_dispatch_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_event_loop_run_stop_test tests/net/test_event_loop_run_stop.c)
        target_include_directories(vireo_event_loop_run_stop_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_event_loop_run_stop_test PRIVATE vireo_event_loop Threads::Threads)
        vireo_target_enable_warnings(vireo_event_loop_run_stop_test)
        vireo_target_enable_sanitizers(vireo_event_loop_run_stop_test)
        add_test(NAME vireo_event_loop_run_stop_test COMMAND vireo_event_loop_run_stop_test)
        set_tests_properties(vireo_event_loop_run_stop_test PROPERTIES TIMEOUT 30)
    endif()

    add_executable(vireo_pool_leases_test tests/base/test_pool_leases.c)
    target_include_directories(vireo_pool_leases_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_pool_leases_test PRIVATE vireo_pool Threads::Threads)
    vireo_target_enable_warnings(vireo_pool_leases_test)
    vireo_target_enable_sanitizers(vireo_pool_leases_test)
    add_test(NAME vireo_pool_leases_test COMMAND vireo_pool_leases_test)
    set_tests_properties(vireo_pool_leases_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_pool_lifecycle_test tests/base/test_pool_lifecycle.c)
    target_include_directories(vireo_pool_lifecycle_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_pool_lifecycle_test PRIVATE vireo_pool)
    vireo_target_enable_warnings(vireo_pool_lifecycle_test)
    vireo_target_enable_sanitizers(vireo_pool_lifecycle_test)
    add_test(NAME vireo_pool_lifecycle_test COMMAND vireo_pool_lifecycle_test)
    set_tests_properties(vireo_pool_lifecycle_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_pool_layout_test tests/base/test_pool_layout.c)
    target_link_libraries(vireo_pool_layout_test PRIVATE vireo_pool)
    vireo_target_enable_warnings(vireo_pool_layout_test)
    vireo_target_enable_sanitizers(vireo_pool_layout_test)
    add_test(NAME vireo_pool_layout_test COMMAND vireo_pool_layout_test)
    set_tests_properties(vireo_pool_layout_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_buffer_test tests/base/test_buffer.c)
    target_include_directories(vireo_buffer_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_buffer_test PRIVATE vireo_buffer)
    vireo_target_enable_warnings(vireo_buffer_test)
    vireo_target_enable_sanitizers(vireo_buffer_test)
    add_test(NAME vireo_buffer_test COMMAND vireo_buffer_test)
    set_tests_properties(vireo_buffer_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_buffer_storage_test tests/base/test_buffer_storage.c)
    target_include_directories(vireo_buffer_storage_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_buffer_storage_test PRIVATE vireo_buffer)
    vireo_target_enable_warnings(vireo_buffer_storage_test)
    vireo_target_enable_sanitizers(vireo_buffer_storage_test)
    add_test(NAME vireo_buffer_storage_test COMMAND vireo_buffer_storage_test)
    set_tests_properties(vireo_buffer_storage_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_buffer_reuse_test tests/base/test_buffer_reuse.c)
    target_include_directories(vireo_buffer_reuse_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_buffer_reuse_test PRIVATE vireo_buffer)
    vireo_target_enable_warnings(vireo_buffer_reuse_test)
    vireo_target_enable_sanitizers(vireo_buffer_reuse_test)
    add_test(NAME vireo_buffer_reuse_test COMMAND vireo_buffer_reuse_test)
    set_tests_properties(vireo_buffer_reuse_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_log_test tests/base/test_log.c)
    target_link_libraries(vireo_log_test PRIVATE vireo_log)
    vireo_target_enable_warnings(vireo_log_test)
    vireo_target_enable_sanitizers(vireo_log_test)
    add_test(NAME vireo_log_test COMMAND vireo_log_test)

    # 资源/emit 测试各自显式取得实现私有 seam；不扩大公共 include 根。
    add_executable(vireo_log_lifecycle_test tests/base/test_log_lifecycle.c)
    target_include_directories(vireo_log_lifecycle_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_log_lifecycle_test PRIVATE vireo_log vireo_config)
    vireo_target_enable_warnings(vireo_log_lifecycle_test)
    vireo_target_enable_sanitizers(vireo_log_lifecycle_test)
    add_test(NAME vireo_log_lifecycle_test COMMAND vireo_log_lifecycle_test)
    set_tests_properties(vireo_log_lifecycle_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_log_emit_test tests/base/test_log_emit.c)
    target_include_directories(vireo_log_emit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_log_emit_test PRIVATE vireo_log Threads::Threads)
    vireo_target_enable_warnings(vireo_log_emit_test)
    vireo_target_enable_sanitizers(vireo_log_emit_test)
    add_test(NAME vireo_log_emit_test COMMAND vireo_log_emit_test)
    set_tests_properties(vireo_log_emit_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_log_rotation_test tests/base/test_log_rotation.c)
    target_include_directories(vireo_log_rotation_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_log_rotation_test PRIVATE vireo_log Threads::Threads)
    vireo_target_enable_warnings(vireo_log_rotation_test)
    vireo_target_enable_sanitizers(vireo_log_rotation_test)
    add_test(NAME vireo_log_rotation_test COMMAND vireo_log_rotation_test)
    set_tests_properties(vireo_log_rotation_test PROPERTIES TIMEOUT 30)

    # vireo_result 单元测试可执行文件
    add_executable(
        vireo_result_test
        tests/base/test_result.c
    )

    # 测试程序链接被测库
    target_link_libraries(
        vireo_result_test
        PRIVATE
            vireo_result
    )

    # 为 vireo_result_test 启用统一严格警告
    vireo_target_enable_warnings(vireo_result_test)

    # 为 vireo_result_test 应用当前 sanitizer 配置
    vireo_target_enable_sanitizers(vireo_result_test)

    # 把可测试文件注册到CTest
    add_test(
        NAME vireo_result_test
        COMMAND vireo_result_test
    )

    # vireo_checked 单元测试可执行文件
    add_executable(
        vireo_checked_test
        tests/base/test_checked.c
    )

    # 测试程序链接被测试的库
    target_link_libraries(
        vireo_checked_test
        PRIVATE
            vireo_checked
    )

    # 为 vireo_checked_test 启用统一严格警告
    vireo_target_enable_warnings(vireo_checked_test)

    # 为 vireo_checked_test 应用当前 sanitizer 配置
    vireo_target_enable_sanitizers(vireo_checked_test)

    # 注册到CTest
    add_test(
        NAME vireo_checked_test
        COMMAND vireo_checked_test
    )

        # vireo_config 单元测试可执行文件
    add_executable(
        vireo_config_test
        tests/base/test_config.c
    )

    # 测试程序链接被测试的配置库
    target_link_libraries(
        vireo_config_test
        PRIVATE
            vireo_config
    )

    # 为 vireo_config_test 启用统一严格警告
    vireo_target_enable_warnings(vireo_config_test)

    # 为 vireo_config_test 应用当前 sanitizer 配置
    vireo_target_enable_sanitizers(vireo_config_test)

    # 注册到 CTest
    add_test(
        NAME vireo_config_test
        COMMAND vireo_config_test
    )

    # vireo_protocol 单元测试可执行文件
    add_executable(
        vireo_protocol_test
        tests/protocol/test_protocol.c
    )

    # 单元测试程序链接被测试的库
    target_link_libraries(
        vireo_protocol_test
        PRIVATE
            vireo_protocol
    )

    # 为vireo_protocol_test 启用统一严格警告
    vireo_target_enable_warnings(vireo_protocol_test)

    # 为 vireo_protocol_test 应用当前 sanitizer 配置
    vireo_target_enable_sanitizers(vireo_protocol_test)

    # 注册到CTest
    add_test(
        NAME vireo_protocol_test
        COMMAND vireo_protocol_test
    )

    # vireo_protocol_codec 单元测试可执行文件
    add_executable(
        vireo_protocol_codec_test
        tests/protocol/test_codec.c
    )
    # 测试程序链接被测试的 codec 库
    target_link_libraries(
        vireo_protocol_codec_test
        PRIVATE
            vireo_protocol_codec
    )
    # 为 vireo_protocol_codec_test 启用统一严格警告
    vireo_target_enable_warnings(vireo_protocol_codec_test)

    # 为 vireo_protocol_codec_test 应用当前 sanitizer 配置
    vireo_target_enable_sanitizers(vireo_protocol_codec_test)

    # 注册到CTest
    add_test(
        NAME vireo_protocol_codec_test
        COMMAND vireo_protocol_codec_test
    )

    add_executable(
        vireo_tlv_test
        tests/protocol/test_tlv.c
    )

    target_link_libraries(
        vireo_tlv_test
        PRIVATE
            vireo_tlv
    )

    vireo_target_enable_warnings(vireo_tlv_test)
    vireo_target_enable_sanitizers(vireo_tlv_test)

    add_test(
        NAME vireo_tlv_test
        COMMAND vireo_tlv_test
    )
    # vireo chunk 单元测试可执行文件
    add_executable(
        vireo_chunk_test
        tests/protocol/test_chunk.c
    )

    target_link_libraries(
        vireo_chunk_test
        PRIVATE
            vireo_chunk
    )

    # 为测试程序启用统一严格警告和 sanitizer
    vireo_target_enable_warnings(vireo_chunk_test)
    vireo_target_enable_sanitizers(vireo_chunk_test)

    # 注册到 CTest
    add_test(
        NAME vireo_chunk_test
        COMMAND vireo_chunk_test
    )
endif()
