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

# notifier：Linux eventfd 生命周期与一次通知/计数消费，不接 queue 或网络
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(vireo_notifier STATIC src/thread/notifier.c)
    target_link_libraries(vireo_notifier PUBLIC vireo_result)
    vireo_target_enable_warnings(vireo_notifier)
    vireo_target_enable_sanitizers(vireo_notifier)
    if(BUILD_TESTING)
        add_executable(vireo_notifier_lifecycle_test tests/thread/test_notifier_lifecycle.c)
        target_include_directories(vireo_notifier_lifecycle_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_notifier_lifecycle_test PRIVATE vireo_notifier Threads::Threads)
        vireo_target_enable_warnings(vireo_notifier_lifecycle_test)
        vireo_target_enable_sanitizers(vireo_notifier_lifecycle_test)
        add_test(NAME vireo_notifier_lifecycle_test COMMAND vireo_notifier_lifecycle_test)
        set_tests_properties(vireo_notifier_lifecycle_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_notifier_notify_consume_test tests/thread/test_notifier_notify_consume.c)
        target_include_directories(vireo_notifier_notify_consume_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_notifier_notify_consume_test PRIVATE vireo_notifier Threads::Threads)
        vireo_target_enable_warnings(vireo_notifier_notify_consume_test)
        vireo_target_enable_sanitizers(vireo_notifier_notify_consume_test)
        add_test(NAME vireo_notifier_notify_consume_test COMMAND vireo_notifier_notify_consume_test)
        set_tests_properties(vireo_notifier_notify_consume_test PROPERTIES TIMEOUT 30)
        # 公开完成队列/pool 与 notifier 的协作；不增加生产依赖或网络接线
        add_executable(vireo_notifier_queue_cooperation_test tests/thread/test_notifier_queue_cooperation.c)
        target_include_directories(vireo_notifier_queue_cooperation_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_notifier_queue_cooperation_test PRIVATE
            vireo_notifier vireo_completion_queue vireo_thread_pool Threads::Threads)
        vireo_target_enable_warnings(vireo_notifier_queue_cooperation_test)
        vireo_target_enable_sanitizers(vireo_notifier_queue_cooperation_test)
        add_test(NAME vireo_notifier_queue_cooperation_test COMMAND vireo_notifier_queue_cooperation_test)
        set_tests_properties(vireo_notifier_queue_cooperation_test PROPERTIES TIMEOUT 30)

        # 六组件公开链路：协作取消/期限结果、乱序身份及配对收尾
        add_executable(vireo_async_components_integration_test tests/thread/test_async_components_integration.c)
        target_link_libraries(vireo_async_components_integration_test PRIVATE
            vireo_notifier vireo_completion_queue vireo_thread_pool Threads::Threads)
        vireo_target_enable_warnings(vireo_async_components_integration_test)
        vireo_target_enable_sanitizers(vireo_async_components_integration_test)
        add_test(NAME vireo_async_components_integration_test COMMAND vireo_async_components_integration_test)
        set_tests_properties(vireo_async_components_integration_test PROPERTIES TIMEOUT 30)
    endif()
endif()

# task 路由、元数据、拥有型输入与独立取消：只依公开下层合同
add_library(vireo_task STATIC src/thread/task_route.c src/thread/task_metadata.c src/thread/task.c
    src/thread/task_cancel.c)
target_link_libraries(vireo_task PUBLIC vireo_result PRIVATE vireo_checked)
vireo_target_enable_warnings(vireo_task)
vireo_target_enable_sanitizers(vireo_task)
if(BUILD_TESTING)
    add_executable(vireo_task_route_test tests/thread/test_task_route.c)
    target_link_libraries(vireo_task_route_test PRIVATE vireo_task)
    vireo_target_enable_warnings(vireo_task_route_test)
    vireo_target_enable_sanitizers(vireo_task_route_test)
    add_test(NAME vireo_task_route_test COMMAND vireo_task_route_test)
    set_tests_properties(vireo_task_route_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_task_metadata_test tests/thread/test_task_metadata.c)
    target_link_libraries(vireo_task_metadata_test PRIVATE vireo_task)
    vireo_target_enable_warnings(vireo_task_metadata_test)
    vireo_target_enable_sanitizers(vireo_task_metadata_test)
    add_test(NAME vireo_task_metadata_test COMMAND vireo_task_metadata_test)
    set_tests_properties(vireo_task_metadata_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_task_owned_input_test tests/thread/test_task_owned_input.c)
    target_include_directories(vireo_task_owned_input_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_task_owned_input_test PRIVATE vireo_task)
    vireo_target_enable_warnings(vireo_task_owned_input_test)
    vireo_target_enable_sanitizers(vireo_task_owned_input_test)
    add_test(NAME vireo_task_owned_input_test COMMAND vireo_task_owned_input_test)
    set_tests_properties(vireo_task_owned_input_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_task_cancel_test tests/thread/test_task_cancel.c)
    target_include_directories(vireo_task_cancel_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_task_cancel_test PRIVATE vireo_task Threads::Threads)
    vireo_target_enable_warnings(vireo_task_cancel_test)
    vireo_target_enable_sanitizers(vireo_task_cancel_test)
    add_test(NAME vireo_task_cancel_test COMMAND vireo_task_cancel_test)
    set_tests_properties(vireo_task_cancel_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_task_cancel_attachment_test tests/thread/test_task_cancel_attachment.c)
    target_include_directories(vireo_task_cancel_attachment_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_task_cancel_attachment_test PRIVATE vireo_task Threads::Threads)
    vireo_target_enable_warnings(vireo_task_cancel_attachment_test)
    vireo_target_enable_sanitizers(vireo_task_cancel_attachment_test)
    add_test(NAME vireo_task_cancel_attachment_test COMMAND vireo_task_cancel_attachment_test)
    set_tests_properties(vireo_task_cancel_attachment_test PROPERTIES TIMEOUT 30)
endif()

# 固定MPMC task queue：try交接、显式worker等待与关闭唤醒，不创建线程池
add_library(vireo_task_queue STATIC src/thread/task_queue.c)
target_link_libraries(vireo_task_queue PUBLIC vireo_task PRIVATE vireo_checked Threads::Threads)
vireo_target_enable_warnings(vireo_task_queue)
vireo_target_enable_sanitizers(vireo_task_queue)
if(BUILD_TESTING)
    add_executable(vireo_task_queue_lifecycle_test tests/thread/test_task_queue_lifecycle.c)
    target_include_directories(vireo_task_queue_lifecycle_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_task_queue_lifecycle_test PRIVATE vireo_task_queue)
    vireo_target_enable_warnings(vireo_task_queue_lifecycle_test)
    vireo_target_enable_sanitizers(vireo_task_queue_lifecycle_test)
    add_test(NAME vireo_task_queue_lifecycle_test COMMAND vireo_task_queue_lifecycle_test)
    set_tests_properties(vireo_task_queue_lifecycle_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_task_queue_transfer_test tests/thread/test_task_queue_transfer.c)
    target_include_directories(vireo_task_queue_transfer_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_task_queue_transfer_test PRIVATE vireo_task_queue Threads::Threads)
    vireo_target_enable_warnings(vireo_task_queue_transfer_test)
    vireo_target_enable_sanitizers(vireo_task_queue_transfer_test)
    add_test(NAME vireo_task_queue_transfer_test COMMAND vireo_task_queue_transfer_test)
    set_tests_properties(vireo_task_queue_transfer_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_task_queue_close_test tests/thread/test_task_queue_close.c)
    target_include_directories(vireo_task_queue_close_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_task_queue_close_test PRIVATE vireo_task_queue Threads::Threads)
    vireo_target_enable_warnings(vireo_task_queue_close_test)
    vireo_target_enable_sanitizers(vireo_task_queue_close_test)
    add_test(NAME vireo_task_queue_close_test COMMAND vireo_task_queue_close_test)
    set_tests_properties(vireo_task_queue_close_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_task_queue_wait_test tests/thread/test_task_queue_wait.c)
    target_include_directories(vireo_task_queue_wait_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_task_queue_wait_test PRIVATE vireo_task_queue Threads::Threads)
    vireo_target_enable_warnings(vireo_task_queue_wait_test)
    vireo_target_enable_sanitizers(vireo_task_queue_wait_test)
    add_test(NAME vireo_task_queue_wait_test COMMAND vireo_task_queue_wait_test)
    set_tests_properties(vireo_task_queue_wait_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_task_queue_metrics_test tests/thread/test_task_queue_metrics.c)
    target_include_directories(vireo_task_queue_metrics_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_task_queue_metrics_test PRIVATE vireo_task_queue Threads::Threads)
    vireo_target_enable_warnings(vireo_task_queue_metrics_test)
    vireo_target_enable_sanitizers(vireo_task_queue_metrics_test)
    add_test(NAME vireo_task_queue_metrics_test COMMAND vireo_task_queue_metrics_test)
    set_tests_properties(vireo_task_queue_metrics_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_task_queue_integration_test tests/thread/test_task_queue_integration.c)
    target_link_libraries(vireo_task_queue_integration_test PRIVATE vireo_task_queue Threads::Threads)
    vireo_target_enable_warnings(vireo_task_queue_integration_test)
    vireo_target_enable_sanitizers(vireo_task_queue_integration_test)
    add_test(NAME vireo_task_queue_integration_test COMMAND vireo_task_queue_integration_test)
    set_tests_properties(vireo_task_queue_integration_test PROPERTIES TIMEOUT 30)
endif()

# 固定 worker 槽、停驻启动、显式任务执行及 join 后首错观测。
add_library(vireo_thread_pool STATIC src/thread/thread_pool.c)
target_link_libraries(vireo_thread_pool PUBLIC vireo_result vireo_task_queue PRIVATE vireo_checked Threads::Threads)
vireo_target_enable_warnings(vireo_thread_pool)
vireo_target_enable_sanitizers(vireo_thread_pool)
if(BUILD_TESTING)
    add_executable(vireo_thread_pool_lifecycle_test tests/thread/test_thread_pool_lifecycle.c)
    target_include_directories(vireo_thread_pool_lifecycle_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_thread_pool_lifecycle_test PRIVATE vireo_thread_pool)
    vireo_target_enable_warnings(vireo_thread_pool_lifecycle_test)
    vireo_target_enable_sanitizers(vireo_thread_pool_lifecycle_test)
    add_test(NAME vireo_thread_pool_lifecycle_test COMMAND vireo_thread_pool_lifecycle_test)
    set_tests_properties(vireo_thread_pool_lifecycle_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_thread_pool_configuration_test tests/thread/test_thread_pool_configuration.c)
    target_include_directories(vireo_thread_pool_configuration_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_thread_pool_configuration_test PRIVATE vireo_thread_pool)
    vireo_target_enable_warnings(vireo_thread_pool_configuration_test)
    vireo_target_enable_sanitizers(vireo_thread_pool_configuration_test)
    add_test(NAME vireo_thread_pool_configuration_test COMMAND vireo_thread_pool_configuration_test)

    add_executable(vireo_thread_pool_startup_test tests/thread/test_thread_pool_startup.c)
    target_include_directories(vireo_thread_pool_startup_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/thread)
    target_link_libraries(vireo_thread_pool_startup_test PRIVATE vireo_thread_pool Threads::Threads)
    vireo_target_enable_warnings(vireo_thread_pool_startup_test)
    vireo_target_enable_sanitizers(vireo_thread_pool_startup_test)
    add_test(NAME vireo_thread_pool_startup_test COMMAND vireo_thread_pool_startup_test)
    set_tests_properties(vireo_thread_pool_startup_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_thread_pool_execution_test tests/thread/test_thread_pool_execution.c)
    target_include_directories(vireo_thread_pool_execution_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/thread)
    target_link_libraries(vireo_thread_pool_execution_test PRIVATE vireo_thread_pool Threads::Threads)
    vireo_target_enable_warnings(vireo_thread_pool_execution_test)
    vireo_target_enable_sanitizers(vireo_thread_pool_execution_test)
    add_test(NAME vireo_thread_pool_execution_test COMMAND vireo_thread_pool_execution_test)
    set_tests_properties(vireo_thread_pool_execution_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_thread_pool_submit_test tests/thread/test_thread_pool_submit.c)
    target_include_directories(vireo_thread_pool_submit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/thread)
    target_link_libraries(vireo_thread_pool_submit_test PRIVATE vireo_thread_pool Threads::Threads)
    vireo_target_enable_warnings(vireo_thread_pool_submit_test)
    vireo_target_enable_sanitizers(vireo_thread_pool_submit_test)
    add_test(NAME vireo_thread_pool_submit_test COMMAND vireo_thread_pool_submit_test)
    set_tests_properties(vireo_thread_pool_submit_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_thread_pool_shutdown_test tests/thread/test_thread_pool_shutdown.c)
    target_include_directories(vireo_thread_pool_shutdown_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/thread)
    target_link_libraries(vireo_thread_pool_shutdown_test PRIVATE vireo_thread_pool Threads::Threads)
    vireo_target_enable_warnings(vireo_thread_pool_shutdown_test)
    vireo_target_enable_sanitizers(vireo_thread_pool_shutdown_test)
    add_test(NAME vireo_thread_pool_shutdown_test COMMAND vireo_thread_pool_shutdown_test)
    set_tests_properties(vireo_thread_pool_shutdown_test PROPERTIES TIMEOUT 30)
    add_executable(vireo_thread_pool_integration_test tests/thread/test_thread_pool_integration.c)
    target_link_libraries(vireo_thread_pool_integration_test PRIVATE vireo_thread_pool Threads::Threads)
    vireo_target_enable_warnings(vireo_thread_pool_integration_test)
    vireo_target_enable_sanitizers(vireo_thread_pool_integration_test)
    add_test(NAME vireo_thread_pool_integration_test COMMAND vireo_thread_pool_integration_test)
    set_tests_properties(vireo_thread_pool_integration_test PROPERTIES TIMEOUT 30)
    set_tests_properties(vireo_thread_pool_configuration_test PROPERTIES TIMEOUT 30)
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

# Reactor 时间协作：等待规划、双采样单轮与有界值交付，向下只依公开合同。
if(TARGET vireo_timer_wheel)
    add_library(vireo_timer_loop STATIC src/net/timer_loop_wait.c src/net/timer_loop_run.c src/net/timer_loop_dispatch.c)
    target_link_libraries(vireo_timer_loop PUBLIC vireo_timer_wheel vireo_event_loop PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_timer_loop)
    vireo_target_enable_sanitizers(vireo_timer_loop)
    if(BUILD_TESTING)
        add_executable(vireo_timer_loop_wait_test tests/net/test_timer_loop_wait.c)
        target_link_libraries(vireo_timer_loop_wait_test PRIVATE vireo_timer_loop)
        vireo_target_enable_warnings(vireo_timer_loop_wait_test)
        vireo_target_enable_sanitizers(vireo_timer_loop_wait_test)
        add_test(NAME vireo_timer_loop_wait_test COMMAND vireo_timer_loop_wait_test)
        set_tests_properties(vireo_timer_loop_wait_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_timer_loop_run_test tests/net/test_timer_loop_run.c)
        target_include_directories(vireo_timer_loop_run_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_timer_loop_run_test PRIVATE vireo_timer_loop)
        vireo_target_enable_warnings(vireo_timer_loop_run_test)
        vireo_target_enable_sanitizers(vireo_timer_loop_run_test)
        add_test(NAME vireo_timer_loop_run_test COMMAND vireo_timer_loop_run_test)
        set_tests_properties(vireo_timer_loop_run_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_timer_loop_dispatch_test tests/net/test_timer_loop_dispatch.c)
        target_include_directories(vireo_timer_loop_dispatch_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_timer_loop_dispatch_test PRIVATE vireo_timer_loop)
        vireo_target_enable_warnings(vireo_timer_loop_dispatch_test)
        vireo_target_enable_sanitizers(vireo_timer_loop_dispatch_test)
        add_test(NAME vireo_timer_loop_dispatch_test COMMAND vireo_timer_loop_dispatch_test)
        set_tests_properties(vireo_timer_loop_dispatch_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_timer_loop_integration_test tests/net/test_timer_loop_integration.c)
        target_include_directories(vireo_timer_loop_integration_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_timer_loop_integration_test PRIVATE vireo_timer_loop)
        vireo_target_enable_warnings(vireo_timer_loop_integration_test)
        vireo_target_enable_sanitizers(vireo_timer_loop_integration_test)
        add_test(NAME vireo_timer_loop_integration_test COMMAND vireo_timer_loop_integration_test)
        set_tests_properties(vireo_timer_loop_integration_test PROPERTIES TIMEOUT 30)
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

# completion 独立描述与响应字节：公开值合同及受检申请预算
add_library(vireo_completion STATIC src/thread/completion_metadata.c src/thread/completion.c)
target_link_libraries(vireo_completion PUBLIC vireo_task vireo_result vireo_protocol PRIVATE vireo_checked)
vireo_target_enable_warnings(vireo_completion)
vireo_target_enable_sanitizers(vireo_completion)
if(BUILD_TESTING)
    add_executable(vireo_completion_metadata_test tests/thread/test_completion_metadata.c)
    target_link_libraries(vireo_completion_metadata_test PRIVATE vireo_completion)
    vireo_target_enable_warnings(vireo_completion_metadata_test)
    vireo_target_enable_sanitizers(vireo_completion_metadata_test)
    add_test(NAME vireo_completion_metadata_test COMMAND vireo_completion_metadata_test)
    set_tests_properties(vireo_completion_metadata_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_completion_owned_output_test tests/thread/test_completion_owned_output.c)
    target_include_directories(vireo_completion_owned_output_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_completion_owned_output_test PRIVATE vireo_completion)
    vireo_target_enable_warnings(vireo_completion_owned_output_test)
    vireo_target_enable_sanitizers(vireo_completion_owned_output_test)
    add_test(NAME vireo_completion_owned_output_test COMMAND vireo_completion_owned_output_test)
    set_tests_properties(vireo_completion_owned_output_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_completion_integration_test tests/thread/test_completion_integration.c)
    target_link_libraries(vireo_completion_integration_test PRIVATE vireo_completion vireo_thread_pool Threads::Threads)
    vireo_target_enable_warnings(vireo_completion_integration_test)
    vireo_target_enable_sanitizers(vireo_completion_integration_test)
    add_test(NAME vireo_completion_integration_test COMMAND vireo_completion_integration_test)
    set_tests_properties(vireo_completion_integration_test PROPERTIES TIMEOUT 30)
endif()

# 固定有界 MPSC 完成队列，支持 worker 生产等待及公开回投集成验证。
add_library(vireo_completion_queue STATIC src/thread/completion_queue.c)
target_link_libraries(vireo_completion_queue PUBLIC vireo_completion PRIVATE vireo_checked Threads::Threads)
vireo_target_enable_warnings(vireo_completion_queue)
vireo_target_enable_sanitizers(vireo_completion_queue)
if(BUILD_TESTING)
    add_executable(vireo_completion_queue_lifecycle_test tests/thread/test_completion_queue_lifecycle.c)
    target_include_directories(vireo_completion_queue_lifecycle_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_completion_queue_lifecycle_test PRIVATE vireo_completion_queue)
    vireo_target_enable_warnings(vireo_completion_queue_lifecycle_test)
    vireo_target_enable_sanitizers(vireo_completion_queue_lifecycle_test)
    add_test(NAME vireo_completion_queue_lifecycle_test COMMAND vireo_completion_queue_lifecycle_test)
    set_tests_properties(vireo_completion_queue_lifecycle_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_completion_queue_transfer_test tests/thread/test_completion_queue_transfer.c)
    target_include_directories(vireo_completion_queue_transfer_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_completion_queue_transfer_test PRIVATE vireo_completion_queue Threads::Threads)
    vireo_target_enable_warnings(vireo_completion_queue_transfer_test)
    vireo_target_enable_sanitizers(vireo_completion_queue_transfer_test)
    add_test(NAME vireo_completion_queue_transfer_test COMMAND vireo_completion_queue_transfer_test)
    set_tests_properties(vireo_completion_queue_transfer_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_completion_queue_close_test tests/thread/test_completion_queue_close.c)
    target_include_directories(vireo_completion_queue_close_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_completion_queue_close_test PRIVATE vireo_completion_queue Threads::Threads)
    vireo_target_enable_warnings(vireo_completion_queue_close_test)
    vireo_target_enable_sanitizers(vireo_completion_queue_close_test)
    add_test(NAME vireo_completion_queue_close_test COMMAND vireo_completion_queue_close_test)
    set_tests_properties(vireo_completion_queue_close_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_completion_queue_wait_test tests/thread/test_completion_queue_wait.c)
    target_include_directories(vireo_completion_queue_wait_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_completion_queue_wait_test PRIVATE vireo_completion_queue Threads::Threads)
    vireo_target_enable_warnings(vireo_completion_queue_wait_test)
    vireo_target_enable_sanitizers(vireo_completion_queue_wait_test)
    add_test(NAME vireo_completion_queue_wait_test COMMAND vireo_completion_queue_wait_test)
    set_tests_properties(vireo_completion_queue_wait_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_completion_queue_metrics_test tests/thread/test_completion_queue_metrics.c)
    target_include_directories(vireo_completion_queue_metrics_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(vireo_completion_queue_metrics_test PRIVATE vireo_completion_queue Threads::Threads)
    vireo_target_enable_warnings(vireo_completion_queue_metrics_test)
    vireo_target_enable_sanitizers(vireo_completion_queue_metrics_test)
    add_test(NAME vireo_completion_queue_metrics_test COMMAND vireo_completion_queue_metrics_test)
    set_tests_properties(vireo_completion_queue_metrics_test PROPERTIES TIMEOUT 30)

    add_executable(vireo_completion_queue_integration_test tests/thread/test_completion_queue_integration.c)
    target_link_libraries(vireo_completion_queue_integration_test PRIVATE vireo_completion_queue vireo_thread_pool Threads::Threads)
    vireo_target_enable_warnings(vireo_completion_queue_integration_test)
    vireo_target_enable_sanitizers(vireo_completion_queue_integration_test)
    add_test(NAME vireo_completion_queue_integration_test COMMAND vireo_completion_queue_integration_test)
    set_tests_properties(vireo_completion_queue_integration_test PROPERTIES TIMEOUT 30)
endif()

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

    # TLS context：服务器 TLS1.3 资源根，OpenSSL 类型仅在实现及 own 测试出现
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
    if(NOT OPENSSL_VERSION VERSION_LESS "4.0")
        message(FATAL_ERROR "vireo_tls_context requires OpenSSL 3.x")
    endif()
    add_library(vireo_tls_context STATIC src/net/tls_context.c src/net/tls_connection.c src/net/tls_io.c src/net/tls_close.c)
    target_link_libraries(vireo_tls_context PUBLIC vireo_result vireo_clock vireo_buffer PRIVATE vireo_checked OpenSSL::SSL OpenSSL::Crypto)
    vireo_target_enable_warnings(vireo_tls_context)
    vireo_target_enable_sanitizers(vireo_tls_context)
    if(BUILD_TESTING)
        add_executable(vireo_tls_context_test tests/net/test_tls_context.c)
        target_include_directories(vireo_tls_context_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/net)
        target_link_libraries(vireo_tls_context_test PRIVATE vireo_tls_context OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tls_context_test)
        vireo_target_enable_sanitizers(vireo_tls_context_test)
        add_test(NAME vireo_tls_context_test COMMAND vireo_tls_context_test)
        set_tests_properties(vireo_tls_context_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tls_connection_test tests/net/test_tls_connection.c)
        target_include_directories(vireo_tls_connection_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/net)
        target_link_libraries(vireo_tls_connection_test PRIVATE vireo_tls_context OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tls_connection_test)
        vireo_target_enable_sanitizers(vireo_tls_connection_test)
        add_test(NAME vireo_tls_connection_test COMMAND vireo_tls_connection_test)
        set_tests_properties(vireo_tls_connection_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tls_io_test tests/net/test_tls_io.c)
        target_include_directories(vireo_tls_io_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/net)
        target_link_libraries(vireo_tls_io_test PRIVATE vireo_tls_context OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tls_io_test)
        vireo_target_enable_sanitizers(vireo_tls_io_test)
        add_test(NAME vireo_tls_io_test COMMAND vireo_tls_io_test)
        set_tests_properties(vireo_tls_io_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tls_io_prepare_test tests/net/test_tls_io_prepare.c)
        target_include_directories(vireo_tls_io_prepare_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/net)
        target_link_libraries(vireo_tls_io_prepare_test PRIVATE vireo_tls_context OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tls_io_prepare_test)
        vireo_target_enable_sanitizers(vireo_tls_io_prepare_test)
        add_test(NAME vireo_tls_io_prepare_test COMMAND vireo_tls_io_prepare_test)
        set_tests_properties(vireo_tls_io_prepare_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tls_handshake_test tests/net/test_tls_handshake.c)
        target_include_directories(vireo_tls_handshake_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/net)
        target_link_libraries(vireo_tls_handshake_test PRIVATE vireo_tls_context OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tls_handshake_test)
        vireo_target_enable_sanitizers(vireo_tls_handshake_test)
        add_test(NAME vireo_tls_handshake_test COMMAND vireo_tls_handshake_test)
        set_tests_properties(vireo_tls_handshake_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tls_close_test tests/net/test_tls_close.c)
        target_include_directories(vireo_tls_close_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/net)
        target_link_libraries(vireo_tls_close_test PRIVATE vireo_tls_context OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tls_close_test)
        vireo_target_enable_sanitizers(vireo_tls_close_test)
        add_test(NAME vireo_tls_close_test COMMAND vireo_tls_close_test)
        set_tests_properties(vireo_tls_close_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tls_handshake_deadline_test tests/net/test_tls_handshake_deadline.c)
        target_include_directories(vireo_tls_handshake_deadline_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/net)
        target_link_libraries(vireo_tls_handshake_deadline_test PRIVATE vireo_tls_context OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tls_handshake_deadline_test)
        vireo_target_enable_sanitizers(vireo_tls_handshake_deadline_test)
        add_test(NAME vireo_tls_handshake_deadline_test COMMAND vireo_tls_handshake_deadline_test)
        set_tests_properties(vireo_tls_handshake_deadline_test PROPERTIES TIMEOUT 30)
    endif()

    # connection：固定双 buffer、独占 socket、有界接收与只读帧识别
    add_library(vireo_connection STATIC src/net/connection.c)
    target_link_libraries(vireo_connection
        PUBLIC vireo_result vireo_buffer vireo_protocol_codec vireo_event_loop vireo_tls_context PRIVATE vireo_checked)
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
        PRIVATE vireo_checked vireo_tlv vireo_clock)
    vireo_target_enable_warnings(vireo_tcp_server)
    vireo_target_enable_sanitizers(vireo_tcp_server)

    # Reactor 身份桥接与固定有界请求记录表；尚不提交 task
    add_library(vireo_inflight STATIC src/net/inflight.c src/net/inflight_store.c
        src/net/inflight_store_records.c src/net/inflight_instance.c src/net/inflight_client_cleanup.c)
    target_link_libraries(vireo_inflight PUBLIC vireo_tcp_server vireo_task PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_inflight)
    vireo_target_enable_sanitizers(vireo_inflight)
    if(BUILD_TESTING)
        add_executable(vireo_inflight_foundation_test tests/net/test_inflight_foundation.c)
        target_link_libraries(vireo_inflight_foundation_test PRIVATE vireo_inflight)
        vireo_target_enable_warnings(vireo_inflight_foundation_test)
        vireo_target_enable_sanitizers(vireo_inflight_foundation_test)
        add_test(NAME vireo_inflight_foundation_test COMMAND vireo_inflight_foundation_test)
        set_tests_properties(vireo_inflight_foundation_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_inflight_store_lifecycle_test tests/net/test_inflight_store_lifecycle.c)
        target_include_directories(vireo_inflight_store_lifecycle_test PRIVATE src)
        target_link_libraries(vireo_inflight_store_lifecycle_test PRIVATE vireo_inflight)
        vireo_target_enable_warnings(vireo_inflight_store_lifecycle_test)
        vireo_target_enable_sanitizers(vireo_inflight_store_lifecycle_test)
        add_test(NAME vireo_inflight_store_lifecycle_test COMMAND vireo_inflight_store_lifecycle_test)
        set_tests_properties(vireo_inflight_store_lifecycle_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_inflight_store_records_test tests/net/test_inflight_store_records.c)
        target_link_libraries(vireo_inflight_store_records_test PRIVATE vireo_inflight)
        vireo_target_enable_warnings(vireo_inflight_store_records_test)
        vireo_target_enable_sanitizers(vireo_inflight_store_records_test)
        add_test(NAME vireo_inflight_store_records_test COMMAND vireo_inflight_store_records_test)
        set_tests_properties(vireo_inflight_store_records_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_inflight_store_client_limits_test tests/net/test_inflight_store_client_limits.c)
        target_link_libraries(vireo_inflight_store_client_limits_test PRIVATE vireo_inflight)
        vireo_target_enable_warnings(vireo_inflight_store_client_limits_test)
        vireo_target_enable_sanitizers(vireo_inflight_store_client_limits_test)
        add_test(NAME vireo_inflight_store_client_limits_test COMMAND vireo_inflight_store_client_limits_test)
        set_tests_properties(vireo_inflight_store_client_limits_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_inflight_instance_test tests/net/test_inflight_instance.c)
        target_include_directories(vireo_inflight_instance_test PRIVATE src)
        target_link_libraries(vireo_inflight_instance_test PRIVATE vireo_inflight Threads::Threads)
        vireo_target_enable_warnings(vireo_inflight_instance_test)
        vireo_target_enable_sanitizers(vireo_inflight_instance_test)
        add_test(NAME vireo_inflight_instance_test COMMAND vireo_inflight_instance_test)
        set_tests_properties(vireo_inflight_instance_test PROPERTIES TIMEOUT 30)
    endif()

    # notifier 经server公开单辅助READ入口登记，不借出server loop
    add_library(vireo_notifier_server STATIC src/net/notifier_server.c)
    target_link_libraries(vireo_notifier_server PUBLIC vireo_tcp_server vireo_notifier)
    vireo_target_enable_warnings(vireo_notifier_server)
    vireo_target_enable_sanitizers(vireo_notifier_server)
    if(BUILD_TESTING)
        add_executable(vireo_notifier_server_registration_test tests/net/test_notifier_server_registration.c)
        target_include_directories(vireo_notifier_server_registration_test PRIVATE src/net)
        target_link_libraries(vireo_notifier_server_registration_test PRIVATE vireo_notifier_server)
        vireo_target_enable_warnings(vireo_notifier_server_registration_test)
        vireo_target_enable_sanitizers(vireo_notifier_server_registration_test)
        add_test(NAME vireo_notifier_server_registration_test COMMAND vireo_notifier_server_registration_test)
        set_tests_properties(vireo_notifier_server_registration_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_tcp_server_auxiliary_readiness_test tests/net/test_tcp_server_auxiliary_readiness.c)
        target_include_directories(vireo_tcp_server_auxiliary_readiness_test PRIVATE src)
        target_link_libraries(vireo_tcp_server_auxiliary_readiness_test PRIVATE vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_tcp_server_auxiliary_readiness_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_auxiliary_readiness_test)
        add_test(NAME vireo_tcp_server_auxiliary_readiness_test COMMAND vireo_tcp_server_auxiliary_readiness_test)
        set_tests_properties(vireo_tcp_server_auxiliary_readiness_test PROPERTIES TIMEOUT 30)
    endif()

    # Reactor 已构造 task 的限额登记与一次非阻塞 pool 交接
    add_library(vireo_inflight_submit STATIC src/net/inflight_submit.c)
    target_link_libraries(vireo_inflight_submit PUBLIC vireo_inflight vireo_thread_pool)
    vireo_target_enable_warnings(vireo_inflight_submit)
    vireo_target_enable_sanitizers(vireo_inflight_submit)
    if(BUILD_TESTING)
        add_executable(vireo_inflight_submission_test tests/net/test_inflight_submission.c)
        target_include_directories(vireo_inflight_submission_test PRIVATE src)
        target_link_libraries(vireo_inflight_submission_test PRIVATE vireo_inflight_submit Threads::Threads)
        vireo_target_enable_warnings(vireo_inflight_submission_test)
        vireo_target_enable_sanitizers(vireo_inflight_submission_test)
        add_test(NAME vireo_inflight_submission_test COMMAND vireo_inflight_submission_test)
        set_tests_properties(vireo_inflight_submission_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_inflight_cancellation_test tests/net/test_inflight_cancellation.c)
        target_include_directories(vireo_inflight_cancellation_test PRIVATE src)
        target_link_libraries(vireo_inflight_cancellation_test PRIVATE vireo_inflight_submit Threads::Threads)
        vireo_target_enable_warnings(vireo_inflight_cancellation_test)
        vireo_target_enable_sanitizers(vireo_inflight_cancellation_test)
        add_test(NAME vireo_inflight_cancellation_test COMMAND vireo_inflight_cancellation_test)
        set_tests_properties(vireo_inflight_cancellation_test PROPERTIES TIMEOUT 30)
    endif()

    # Reactor 只读匹配完成结果、当前客户与在途请求快照
    add_library(vireo_inflight_completion STATIC src/net/inflight_completion.c
        src/net/inflight_completion_consume.c)
    target_link_libraries(vireo_inflight_completion PUBLIC vireo_inflight vireo_completion)
    vireo_target_enable_warnings(vireo_inflight_completion)
    vireo_target_enable_sanitizers(vireo_inflight_completion)
    if(BUILD_TESTING)
        add_executable(vireo_inflight_completion_test tests/net/test_inflight_completion.c)
        target_link_libraries(vireo_inflight_completion_test
            PRIVATE vireo_inflight_completion vireo_inflight_submit vireo_completion_queue Threads::Threads)
        vireo_target_enable_warnings(vireo_inflight_completion_test)
        vireo_target_enable_sanitizers(vireo_inflight_completion_test)
        add_test(NAME vireo_inflight_completion_test COMMAND vireo_inflight_completion_test)
        set_tests_properties(vireo_inflight_completion_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_inflight_completion_consume_test tests/net/test_inflight_completion_consume.c)
        target_link_libraries(vireo_inflight_completion_consume_test
            PRIVATE vireo_inflight_completion vireo_inflight_submit vireo_completion_queue Threads::Threads)
        vireo_target_enable_warnings(vireo_inflight_completion_consume_test)
        vireo_target_enable_sanitizers(vireo_inflight_completion_consume_test)
        add_test(NAME vireo_inflight_completion_consume_test COMMAND vireo_inflight_completion_consume_test)
        set_tests_properties(vireo_inflight_completion_consume_test PROPERTIES TIMEOUT 30)
    endif()

    # 历史客户有界取消清退，复用028原表且不等待worker
    if(BUILD_TESTING)
        add_executable(vireo_inflight_client_cleanup_test tests/net/test_inflight_client_cleanup.c)
        target_include_directories(vireo_inflight_client_cleanup_test PRIVATE src)
        target_link_libraries(vireo_inflight_client_cleanup_test
            PRIVATE vireo_inflight_completion vireo_thread_pool Threads::Threads)
        vireo_target_enable_warnings(vireo_inflight_client_cleanup_test)
        vireo_target_enable_sanitizers(vireo_inflight_client_cleanup_test)
        add_test(NAME vireo_inflight_client_cleanup_test COMMAND vireo_inflight_client_cleanup_test)
        set_tests_properties(vireo_inflight_client_cleanup_test PROPERTIES TIMEOUT 30)
    endif()

    # Reactor 按显式条数预算排空完成队列，失败交还残留 owner
    add_library(vireo_inflight_completion_drain STATIC src/net/inflight_completion_drain.c)
    target_link_libraries(vireo_inflight_completion_drain
        PUBLIC vireo_inflight_completion vireo_completion_queue)
    vireo_target_enable_warnings(vireo_inflight_completion_drain)
    vireo_target_enable_sanitizers(vireo_inflight_completion_drain)
    if(BUILD_TESTING)
        add_executable(vireo_inflight_completion_drain_test tests/net/test_inflight_completion_drain.c)
        target_include_directories(vireo_inflight_completion_drain_test PRIVATE src/net)
        target_link_libraries(vireo_inflight_completion_drain_test
            PRIVATE vireo_inflight_completion_drain Threads::Threads)
        vireo_target_enable_warnings(vireo_inflight_completion_drain_test)
        vireo_target_enable_sanitizers(vireo_inflight_completion_drain_test)
        add_test(NAME vireo_inflight_completion_drain_test COMMAND vireo_inflight_completion_drain_test)
        set_tests_properties(vireo_inflight_completion_drain_test PROPERTIES TIMEOUT 30)
    endif()

    # 独立 notifier 的公开 LT READ 注册与借用注销
    add_library(vireo_notifier_loop STATIC src/net/notifier_loop.c)
    target_link_libraries(vireo_notifier_loop PUBLIC vireo_event_loop vireo_notifier)
    vireo_target_enable_warnings(vireo_notifier_loop)
    vireo_target_enable_sanitizers(vireo_notifier_loop)
    if(BUILD_TESTING)
        add_executable(vireo_notifier_loop_registration_test tests/net/test_notifier_loop_registration.c)
        target_include_directories(vireo_notifier_loop_registration_test PRIVATE src/net)
        target_link_libraries(vireo_notifier_loop_registration_test PRIVATE vireo_notifier_loop Threads::Threads)
        vireo_target_enable_warnings(vireo_notifier_loop_registration_test)
        vireo_target_enable_sanitizers(vireo_notifier_loop_registration_test)
        add_test(NAME vireo_notifier_loop_registration_test COMMAND vireo_notifier_loop_registration_test)
        set_tests_properties(vireo_notifier_loop_registration_test PROPERTIES TIMEOUT 30)
    endif()

    # 提示消费、有界完成排空与一次续通知，保真实前缀/残留 owner
    add_library(vireo_notifier_completion STATIC src/net/notifier_completion.c)
    target_link_libraries(vireo_notifier_completion PUBLIC vireo_notifier vireo_inflight_completion_drain)
    vireo_target_enable_warnings(vireo_notifier_completion)
    vireo_target_enable_sanitizers(vireo_notifier_completion)
    if(BUILD_TESTING)
        add_executable(vireo_notifier_completion_dispatch_test tests/net/test_notifier_completion_dispatch.c)
        target_include_directories(vireo_notifier_completion_dispatch_test PRIVATE src/net)
        target_link_libraries(vireo_notifier_completion_dispatch_test
            PRIVATE vireo_notifier_completion vireo_notifier_loop Threads::Threads)
        vireo_target_enable_warnings(vireo_notifier_completion_dispatch_test)
        vireo_target_enable_sanitizers(vireo_notifier_completion_dispatch_test)
        add_test(NAME vireo_notifier_completion_dispatch_test COMMAND vireo_notifier_completion_dispatch_test)
        set_tests_properties(vireo_notifier_completion_dispatch_test PROPERTIES TIMEOUT 30)
    endif()

    # 服务安全点取辅助就绪并复用有界完成消费
    add_library(vireo_notifier_server_dispatch STATIC src/net/notifier_server_dispatch.c)
    target_link_libraries(vireo_notifier_server_dispatch PUBLIC vireo_notifier_completion)
    vireo_target_enable_warnings(vireo_notifier_server_dispatch)
    vireo_target_enable_sanitizers(vireo_notifier_server_dispatch)
    if(BUILD_TESTING)
        add_executable(vireo_notifier_server_dispatch_test tests/net/test_notifier_server_dispatch.c)
        target_include_directories(vireo_notifier_server_dispatch_test PRIVATE src/net)
        target_link_libraries(vireo_notifier_server_dispatch_test
            PRIVATE vireo_notifier_server_dispatch vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_notifier_server_dispatch_test)
        vireo_target_enable_sanitizers(vireo_notifier_server_dispatch_test)
        add_test(NAME vireo_notifier_server_dispatch_test COMMAND vireo_notifier_server_dispatch_test)
        set_tests_properties(vireo_notifier_server_dispatch_test PROPERTIES TIMEOUT 30)
    endif()

    # 单帧完成响应编码、完整入队及公开关注刷新
    add_library(vireo_completion_response STATIC src/net/completion_response.c)
    target_link_libraries(vireo_completion_response
        PUBLIC vireo_inflight_completion vireo_protocol_codec PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_completion_response)
    vireo_target_enable_sanitizers(vireo_completion_response)
    if(BUILD_TESTING)
        add_executable(vireo_completion_response_enqueue_test tests/net/test_completion_response_enqueue.c)
        target_include_directories(vireo_completion_response_enqueue_test PRIVATE src/net)
        target_link_libraries(vireo_completion_response_enqueue_test
            PRIVATE vireo_completion_response vireo_notifier_server_dispatch vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_completion_response_enqueue_test)
        vireo_target_enable_sanitizers(vireo_completion_response_enqueue_test)
        add_test(NAME vireo_completion_response_enqueue_test COMMAND vireo_completion_response_enqueue_test)
        set_tests_properties(vireo_completion_response_enqueue_test PROPERTIES TIMEOUT 30)
    endif()

    if(BUILD_TESTING)
        add_executable(vireo_completion_response_tls_test tests/net/test_completion_response_tls.c)
        target_include_directories(vireo_completion_response_tls_test PRIVATE src/net)
        target_link_libraries(vireo_completion_response_tls_test PRIVATE vireo_completion_response
            vireo_async_request_head vireo_completion_publish vireo_notifier_server_dispatch vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_completion_response_tls_test)
        vireo_target_enable_sanitizers(vireo_completion_response_tls_test)
        add_test(NAME vireo_completion_response_tls_test COMMAND vireo_completion_response_tls_test)
        set_tests_properties(vireo_completion_response_tls_test PROPERTIES TIMEOUT 30)
    endif()

    # 完成响应分发：公开就绪消费与单帧助手，消费前保守条数/字节预算
    add_library(vireo_completion_response_dispatch STATIC src/net/completion_response_dispatch.c src/net/completion_response_dispatch_tls.c)
    target_link_libraries(vireo_completion_response_dispatch
        PUBLIC vireo_notifier_server_dispatch vireo_completion_response PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_completion_response_dispatch)
    vireo_target_enable_sanitizers(vireo_completion_response_dispatch)
    if(BUILD_TESTING)
        add_executable(vireo_completion_response_dispatch_test tests/net/test_completion_response_dispatch.c)
        target_include_directories(vireo_completion_response_dispatch_test PRIVATE src/net)
        target_link_libraries(vireo_completion_response_dispatch_test
            PRIVATE vireo_completion_response_dispatch vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_completion_response_dispatch_test)
        vireo_target_enable_sanitizers(vireo_completion_response_dispatch_test)
        add_test(NAME vireo_completion_response_dispatch_test COMMAND vireo_completion_response_dispatch_test)
        set_tests_properties(vireo_completion_response_dispatch_test PROPERTIES TIMEOUT 30)
    endif()

    # 异步请求输入：单帧 wire 验证、独立任务复制与一次限额提交
    add_library(vireo_async_request STATIC src/net/async_request.c)
    target_link_libraries(vireo_async_request PUBLIC vireo_inflight_submit vireo_protocol_codec PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_async_request)
    vireo_target_enable_sanitizers(vireo_async_request)
    if(BUILD_TESTING)
        add_executable(vireo_async_request_copy_submit_test tests/net/test_async_request_copy_submit.c)
        target_include_directories(vireo_async_request_copy_submit_test PRIVATE src/net)
        target_link_libraries(vireo_async_request_copy_submit_test PRIVATE vireo_async_request Threads::Threads)
        vireo_target_enable_warnings(vireo_async_request_copy_submit_test)
        vireo_target_enable_sanitizers(vireo_async_request_copy_submit_test)
        add_test(NAME vireo_async_request_copy_submit_test COMMAND vireo_async_request_copy_submit_test)
        set_tests_properties(vireo_async_request_copy_submit_test PROPERTIES TIMEOUT 30)
    endif()

    # 异步首帧移交后消费：caller pending保持消费义务及仅恢复消费
    add_library(vireo_async_request_head STATIC src/net/async_request_head.c)
    target_link_libraries(vireo_async_request_head PUBLIC vireo_async_request)
    vireo_target_enable_warnings(vireo_async_request_head)
    vireo_target_enable_sanitizers(vireo_async_request_head)
    if(BUILD_TESTING)
        add_executable(vireo_async_request_head_consume_test tests/net/test_async_request_head_consume.c)
        target_include_directories(vireo_async_request_head_consume_test PRIVATE src/net)
        target_link_libraries(vireo_async_request_head_consume_test PRIVATE vireo_async_request_head Threads::Threads)
        vireo_target_enable_warnings(vireo_async_request_head_consume_test)
        vireo_target_enable_sanitizers(vireo_async_request_head_consume_test)
        add_test(NAME vireo_async_request_head_consume_test COMMAND vireo_async_request_head_consume_test)
        set_tests_properties(vireo_async_request_head_consume_test PROPERTIES TIMEOUT 30)
    endif()

    # 独立完成回投：显式响应复制、worker等待及真实交接后一次提示
    add_library(vireo_completion_publish STATIC src/thread/completion_publish.c)
    target_link_libraries(vireo_completion_publish PUBLIC vireo_completion_queue vireo_notifier)
    vireo_target_enable_warnings(vireo_completion_publish)
    vireo_target_enable_sanitizers(vireo_completion_publish)
    if(BUILD_TESTING)
        add_executable(vireo_completion_copy_publish_test tests/thread/test_completion_copy_publish.c)
        target_include_directories(vireo_completion_copy_publish_test PRIVATE src/thread)
        target_link_libraries(vireo_completion_copy_publish_test PRIVATE vireo_completion_publish vireo_async_request_head Threads::Threads)
        vireo_target_enable_warnings(vireo_completion_copy_publish_test)
        vireo_target_enable_sanitizers(vireo_completion_copy_publish_test)
        add_test(NAME vireo_completion_copy_publish_test COMMAND vireo_completion_copy_publish_test)
        set_tests_properties(vireo_completion_copy_publish_test PROPERTIES TIMEOUT 30)
    endif()

    # 显式无业务异步闭环：仅公开请求／回投／有界响应链的集成CTest
    if(BUILD_TESTING)
        add_executable(vireo_async_request_roundtrip_test tests/net/test_async_request_roundtrip.c)
        target_link_libraries(vireo_async_request_roundtrip_test PRIVATE vireo_async_request_head vireo_completion_publish vireo_completion_response_dispatch vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_async_request_roundtrip_test)
        vireo_target_enable_sanitizers(vireo_async_request_roundtrip_test)
        add_test(NAME vireo_async_request_roundtrip_test COMMAND vireo_async_request_roundtrip_test)
        set_tests_properties(vireo_async_request_roundtrip_test PROPERTIES TIMEOUT 30)
    endif()

    # 安全窗口：server机械等待与有界客户待办取出，真实公开异步提交回归
    if(BUILD_TESTING)
        add_executable(vireo_tcp_server_poll_ready_test tests/net/test_tcp_server_poll_ready.c)
        target_include_directories(vireo_tcp_server_poll_ready_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_poll_ready_test PRIVATE vireo_async_request_head vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_tcp_server_poll_ready_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_poll_ready_test)
        add_test(NAME vireo_tcp_server_poll_ready_test COMMAND vireo_tcp_server_poll_ready_test)
        set_tests_properties(vireo_tcp_server_poll_ready_test PROPERTIES TIMEOUT 30)
    endif()

    # 单客户单首帧异步驱动：公开安全点、真实移交与末同步责任
    add_library(vireo_async_client_drive STATIC src/net/async_client_drive.c src/net/async_client_drive_tls.c)
    target_link_libraries(vireo_async_client_drive PUBLIC vireo_async_request_head)
    vireo_target_enable_warnings(vireo_async_client_drive)
    vireo_target_enable_sanitizers(vireo_async_client_drive)
    if(BUILD_TESTING)
        add_executable(vireo_async_client_drive_test tests/net/test_async_client_drive.c)
        target_include_directories(vireo_async_client_drive_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_async_client_drive_test PRIVATE vireo_async_client_drive vireo_completion_publish vireo_completion_response_dispatch vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_async_client_drive_test)
        vireo_target_enable_sanitizers(vireo_async_client_drive_test)
        add_test(NAME vireo_async_client_drive_test COMMAND vireo_async_client_drive_test)
        set_tests_properties(vireo_async_client_drive_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_async_client_drive_tls_test tests/net/test_async_client_drive_tls.c)
        target_include_directories(vireo_async_client_drive_tls_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/net)
        target_link_libraries(vireo_async_client_drive_tls_test PRIVATE vireo_async_client_drive vireo_completion_publish vireo_completion_response vireo_notifier_server_dispatch vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_async_client_drive_tls_test)
        vireo_target_enable_sanitizers(vireo_async_client_drive_tls_test)
        add_test(NAME vireo_async_client_drive_tls_test COMMAND vireo_async_client_drive_tls_test)
        set_tests_properties(vireo_async_client_drive_tls_test PROPERTIES TIMEOUT 30)
    endif()

    # 有界异步轮次：逐项原请求关联与失败后缀交还
    add_library(vireo_async_round STATIC src/net/async_round.c src/net/async_round_tls.c)
    target_link_libraries(vireo_async_round PUBLIC vireo_async_client_drive)
    vireo_target_enable_warnings(vireo_async_round)
    vireo_target_enable_sanitizers(vireo_async_round)
    if(BUILD_TESTING)
        add_executable(vireo_async_round_test tests/net/test_async_round.c)
        target_include_directories(vireo_async_round_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_async_round_test PRIVATE vireo_async_round vireo_completion_publish vireo_completion_response_dispatch vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_async_round_test)
        vireo_target_enable_sanitizers(vireo_async_round_test)
        add_test(NAME vireo_async_round_test COMMAND vireo_async_round_test)
        set_tests_properties(vireo_async_round_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_async_round_tls_test tests/net/test_async_round_tls.c)
        target_include_directories(vireo_async_round_tls_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/net)
        target_link_libraries(vireo_async_round_tls_test PRIVATE vireo_async_round vireo_completion_publish vireo_completion_response vireo_notifier_server_dispatch vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_async_round_tls_test)
        vireo_target_enable_sanitizers(vireo_async_round_tls_test)
        add_test(NAME vireo_async_round_tls_test COMMAND vireo_async_round_tls_test)
        set_tests_properties(vireo_async_round_tls_test PROPERTIES TIMEOUT 30)
    endif()

    # 异步接入准备：固定双预算、流控/FIFO与失败后缀
    add_library(vireo_async_admission STATIC src/net/async_admission.c)
    target_link_libraries(vireo_async_admission PUBLIC vireo_tcp_server PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_async_admission)
    vireo_target_enable_sanitizers(vireo_async_admission)
    if(BUILD_TESTING)
        add_executable(vireo_async_admission_test tests/net/test_async_admission.c)
        target_include_directories(vireo_async_admission_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_async_admission_test PRIVATE vireo_async_admission vireo_async_round vireo_completion_publish vireo_completion_response_dispatch vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_async_admission_test)
        vireo_target_enable_sanitizers(vireo_async_admission_test)
        add_test(NAME vireo_async_admission_test COMMAND vireo_async_admission_test)
        set_tests_properties(vireo_async_admission_test PROPERTIES TIMEOUT 30)
    endif()

    # 异步监听压力：真实固定额度与一次公开READ同步
    add_library(vireo_async_admission_pressure STATIC src/net/async_admission_pressure.c)
    target_include_directories(vireo_async_admission_pressure PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(vireo_async_admission_pressure PUBLIC vireo_tcp_server PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_async_admission_pressure)
    vireo_target_enable_sanitizers(vireo_async_admission_pressure)
    if(BUILD_TESTING)
        add_executable(vireo_async_admission_pressure_test tests/net/test_async_admission_pressure.c)
        target_include_directories(vireo_async_admission_pressure_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_async_admission_pressure_test PRIVATE vireo_async_admission_pressure vireo_async_admission Threads::Threads)
        vireo_target_enable_warnings(vireo_async_admission_pressure_test)
        vireo_target_enable_sanitizers(vireo_async_admission_pressure_test)
        add_test(NAME vireo_async_admission_pressure_test COMMAND vireo_async_admission_pressure_test)
        set_tests_properties(vireo_async_admission_pressure_test PROPERTIES TIMEOUT 30)
    endif()

    # 同次监听等待：原FIFO报告与安全窗口有界接入
    if(BUILD_TESTING)
        add_executable(vireo_tcp_server_listener_poll_test tests/net/test_tcp_server_listener_poll.c)
        target_include_directories(vireo_tcp_server_listener_poll_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_listener_poll_test PRIVATE vireo_tcp_server vireo_async_admission vireo_async_admission_pressure Threads::Threads)
        vireo_target_enable_warnings(vireo_tcp_server_listener_poll_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_listener_poll_test)
        add_test(NAME vireo_tcp_server_listener_poll_test COMMAND vireo_tcp_server_listener_poll_test)
        set_tests_properties(vireo_tcp_server_listener_poll_test PROPERTIES TIMEOUT 30)
    endif()

    # 033-07：有界异步服务轮组合，仅公开依赖
    add_library(vireo_async_service STATIC src/net/async_service.c src/net/async_service_tls.c)
    target_link_libraries(vireo_async_service PUBLIC vireo_async_round vireo_async_admission vireo_async_admission_pressure vireo_completion_response_dispatch PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_async_service)
    vireo_target_enable_sanitizers(vireo_async_service)
    if(BUILD_TESTING)
        add_executable(vireo_async_service_test tests/net/test_async_service.c)
        target_include_directories(vireo_async_service_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_async_service_test PRIVATE vireo_async_service vireo_completion_publish vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_async_service_test)
        vireo_target_enable_sanitizers(vireo_async_service_test)
        add_test(NAME vireo_async_service_test COMMAND vireo_async_service_test)
        set_tests_properties(vireo_async_service_test PROPERTIES TIMEOUT 30)
    endif()

    if(BUILD_TESTING)
        add_executable(vireo_async_service_tls_test tests/net/test_async_service_tls.c)
        target_include_directories(vireo_async_service_tls_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/net)
        target_link_libraries(vireo_async_service_tls_test PRIVATE vireo_async_service vireo_completion_publish vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_async_service_tls_test)
        vireo_target_enable_sanitizers(vireo_async_service_tls_test)
        add_test(NAME vireo_async_service_tls_test COMMAND vireo_async_service_tls_test)
        set_tests_properties(vireo_async_service_tls_test PROPERTIES TIMEOUT 30)
    endif()

    # 033-08：客户后缀显式有界重新排队
    add_library(vireo_async_ready_recovery STATIC src/net/async_ready_recovery.c)
    target_link_libraries(vireo_async_ready_recovery PUBLIC vireo_tcp_server)
    vireo_target_enable_warnings(vireo_async_ready_recovery)
    vireo_target_enable_sanitizers(vireo_async_ready_recovery)
    if(BUILD_TESTING)
        add_executable(vireo_async_ready_recovery_test tests/net/test_async_ready_recovery.c)
        target_include_directories(vireo_async_ready_recovery_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_async_ready_recovery_test PRIVATE vireo_async_ready_recovery vireo_async_service vireo_notifier_server Threads::Threads)
        vireo_target_enable_warnings(vireo_async_ready_recovery_test)
        vireo_target_enable_sanitizers(vireo_async_ready_recovery_test)
        add_test(NAME vireo_async_ready_recovery_test COMMAND vireo_async_ready_recovery_test)
        set_tests_properties(vireo_async_ready_recovery_test PROPERTIES TIMEOUT 30)
    endif()

    # 033-09：pending消费、流控刷新与排队的显式续接
    add_library(vireo_async_pending_recovery STATIC src/net/async_pending_recovery.c)
    target_link_libraries(vireo_async_pending_recovery PUBLIC vireo_async_request_head vireo_tcp_server)
    vireo_target_enable_warnings(vireo_async_pending_recovery)
    vireo_target_enable_sanitizers(vireo_async_pending_recovery)
    if(BUILD_TESTING)
        add_executable(vireo_async_pending_recovery_test tests/net/test_async_pending_recovery.c)
        target_include_directories(vireo_async_pending_recovery_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_async_pending_recovery_test PRIVATE vireo_async_pending_recovery vireo_async_admission Threads::Threads)
        vireo_target_enable_warnings(vireo_async_pending_recovery_test)
        vireo_target_enable_sanitizers(vireo_async_pending_recovery_test)
        add_test(NAME vireo_async_pending_recovery_test COMMAND vireo_async_pending_recovery_test)
        set_tests_properties(vireo_async_pending_recovery_test PROPERTIES TIMEOUT 30)
    endif()

    # 033-10：未移交task的显式放弃与残留登记撤销
    add_library(vireo_async_task_recovery STATIC src/net/async_task_recovery.c)
    target_link_libraries(vireo_async_task_recovery PUBLIC vireo_inflight)
    vireo_target_enable_warnings(vireo_async_task_recovery)
    vireo_target_enable_sanitizers(vireo_async_task_recovery)
    if(BUILD_TESTING)
        add_executable(vireo_async_task_recovery_test tests/net/test_async_task_recovery.c)
        target_include_directories(vireo_async_task_recovery_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_async_task_recovery_test PRIVATE vireo_async_task_recovery vireo_async_request Threads::Threads)
        vireo_target_enable_warnings(vireo_async_task_recovery_test)
        vireo_target_enable_sanitizers(vireo_async_task_recovery_test)
        add_test(NAME vireo_async_task_recovery_test COMMAND vireo_async_task_recovery_test)
        set_tests_properties(vireo_async_task_recovery_test PROPERTIES TIMEOUT 30)
    endif()

    # 033-11：响应已入队后的刷新与completion释放
    add_library(vireo_async_completion_recovery STATIC src/net/async_completion_recovery.c)
    target_link_libraries(vireo_async_completion_recovery PUBLIC vireo_tcp_server vireo_completion)
    vireo_target_enable_warnings(vireo_async_completion_recovery)
    vireo_target_enable_sanitizers(vireo_async_completion_recovery)
    if(BUILD_TESTING)
        add_executable(vireo_async_completion_recovery_test tests/net/test_async_completion_recovery.c)
        target_include_directories(vireo_async_completion_recovery_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_async_completion_recovery_test PRIVATE vireo_async_completion_recovery vireo_completion_response Threads::Threads)
        vireo_target_enable_warnings(vireo_async_completion_recovery_test)
        vireo_target_enable_sanitizers(vireo_async_completion_recovery_test)
        add_test(NAME vireo_async_completion_recovery_test COMMAND vireo_async_completion_recovery_test)
        set_tests_properties(vireo_async_completion_recovery_test PROPERTIES TIMEOUT 30)
    endif()

    # 显式客户终止：原公开关闭/归还与028历史登记预算清退
    add_library(vireo_async_client_termination STATIC src/net/async_client_termination.c)
    target_link_libraries(vireo_async_client_termination PUBLIC vireo_tcp_server vireo_inflight)
    vireo_target_enable_warnings(vireo_async_client_termination)
    vireo_target_enable_sanitizers(vireo_async_client_termination)
    if(BUILD_TESTING)
        add_executable(vireo_async_client_termination_test tests/net/test_async_client_termination.c)
        target_include_directories(vireo_async_client_termination_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_async_client_termination_test PRIVATE vireo_async_client_termination vireo_inflight_completion vireo_thread_pool Threads::Threads)
        vireo_target_enable_warnings(vireo_async_client_termination_test)
        vireo_target_enable_sanitizers(vireo_async_client_termination_test)
        add_test(NAME vireo_async_client_termination_test COMMAND vireo_async_client_termination_test)
        set_tests_properties(vireo_async_client_termination_test PROPERTIES TIMEOUT 30)
    endif()

    # 异步驱动主错误的纯值分类，实际终止仍由caller显式执行
    add_library(vireo_async_client_termination_policy STATIC src/net/async_client_termination_policy.c)
    target_link_libraries(vireo_async_client_termination_policy PUBLIC vireo_async_client_drive)
    vireo_target_enable_warnings(vireo_async_client_termination_policy)
    vireo_target_enable_sanitizers(vireo_async_client_termination_policy)
    if(BUILD_TESTING)
        add_executable(vireo_async_client_termination_policy_test tests/net/test_async_client_termination_policy.c)
        target_link_libraries(vireo_async_client_termination_policy_test PRIVATE vireo_async_client_termination_policy vireo_async_client_termination vireo_inflight_completion)
        vireo_target_enable_warnings(vireo_async_client_termination_policy_test)
        vireo_target_enable_sanitizers(vireo_async_client_termination_policy_test)
        add_test(NAME vireo_async_client_termination_policy_test COMMAND vireo_async_client_termination_policy_test)
        set_tests_properties(vireo_async_client_termination_policy_test PROPERTIES TIMEOUT 30)
    endif()

    # EOF后保留异步响应义务，显式有界DRAIN/READY再归还的公开集成验证
    if(BUILD_TESTING)
        add_executable(vireo_async_eof_finish_test tests/net/test_async_eof_finish.c)
        target_link_libraries(vireo_async_eof_finish_test PRIVATE vireo_async_client_drive vireo_completion_publish vireo_completion_response Threads::Threads)
        vireo_target_enable_warnings(vireo_async_eof_finish_test)
        vireo_target_enable_sanitizers(vireo_async_eof_finish_test)
        add_test(NAME vireo_async_eof_finish_test COMMAND vireo_async_eof_finish_test)
        set_tests_properties(vireo_async_eof_finish_test PROPERTIES TIMEOUT 30)
    endif()

    # 显式放弃型异步停机：独占管理join与Reactor消费配合、最后drain
    if(BUILD_TESTING)
        add_executable(vireo_async_shutdown_test tests/net/test_async_shutdown.c)
        target_link_libraries(vireo_async_shutdown_test PRIVATE vireo_async_client_termination vireo_inflight_submit vireo_completion_publish vireo_notifier_completion vireo_notifier_loop Threads::Threads)
        vireo_target_enable_warnings(vireo_async_shutdown_test)
        vireo_target_enable_sanitizers(vireo_async_shutdown_test)
        add_test(NAME vireo_async_shutdown_test COMMAND vireo_async_shutdown_test)
        set_tests_properties(vireo_async_shutdown_test PROPERTIES TIMEOUT 30)
    endif()

    # 客户期限关联：身份、登记／取消／重排、固定记录表与显式到期关闭
    add_library(vireo_client_deadline STATIC
        src/net/client_deadline_binding.c src/net/client_deadline_registration.c
        src/net/client_deadline_store.c src/net/client_deadline_rearm.c
        src/net/client_deadline_expired_close.c src/net/client_deadline_expired_release.c
        src/net/client_deadline_serve.c src/net/client_deadline_idle.c
        src/net/client_deadline_request.c)
    target_link_libraries(vireo_client_deadline
        PUBLIC vireo_tcp_server vireo_timer_wheel vireo_timer_loop
        PRIVATE vireo_checked)
    vireo_target_enable_warnings(vireo_client_deadline)
    vireo_target_enable_sanitizers(vireo_client_deadline)
    if(BUILD_TESTING)
        add_executable(vireo_client_deadline_binding_test tests/net/test_client_deadline_binding.c)
        target_link_libraries(vireo_client_deadline_binding_test
            PRIVATE vireo_client_deadline vireo_timer_loop)
        vireo_target_enable_warnings(vireo_client_deadline_binding_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_binding_test)
        add_test(NAME vireo_client_deadline_binding_test COMMAND vireo_client_deadline_binding_test)
        set_tests_properties(vireo_client_deadline_binding_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_client_deadline_registration_test tests/net/test_client_deadline_registration.c)
        target_link_libraries(vireo_client_deadline_registration_test
            PRIVATE vireo_client_deadline vireo_timer_loop)
        vireo_target_enable_warnings(vireo_client_deadline_registration_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_registration_test)
        add_test(NAME vireo_client_deadline_registration_test COMMAND vireo_client_deadline_registration_test)
        set_tests_properties(vireo_client_deadline_registration_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_client_deadline_store_test tests/net/test_client_deadline_store.c)
        target_include_directories(vireo_client_deadline_store_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_client_deadline_store_test
            PRIVATE vireo_client_deadline vireo_timer_loop)
        vireo_target_enable_warnings(vireo_client_deadline_store_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_store_test)
        add_test(NAME vireo_client_deadline_store_test COMMAND vireo_client_deadline_store_test)
        set_tests_properties(vireo_client_deadline_store_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_client_deadline_rearm_test tests/net/test_client_deadline_rearm.c)
        target_link_libraries(vireo_client_deadline_rearm_test
            PRIVATE vireo_client_deadline vireo_timer_loop)
        vireo_target_enable_warnings(vireo_client_deadline_rearm_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_rearm_test)
        add_test(NAME vireo_client_deadline_rearm_test COMMAND vireo_client_deadline_rearm_test)
        set_tests_properties(vireo_client_deadline_rearm_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_client_deadline_expired_close_test tests/net/test_client_deadline_expired_close.c)
        target_include_directories(vireo_client_deadline_expired_close_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_client_deadline_expired_close_test
            PRIVATE vireo_client_deadline vireo_timer_loop)
        vireo_target_enable_warnings(vireo_client_deadline_expired_close_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_expired_close_test)
        add_test(NAME vireo_client_deadline_expired_close_test COMMAND vireo_client_deadline_expired_close_test)
        set_tests_properties(vireo_client_deadline_expired_close_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_client_deadline_expired_release_test tests/net/test_client_deadline_expired_release.c)
        target_include_directories(vireo_client_deadline_expired_release_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_client_deadline_expired_release_test
            PRIVATE vireo_client_deadline vireo_timer_loop)
        vireo_target_enable_warnings(vireo_client_deadline_expired_release_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_expired_release_test)
        add_test(NAME vireo_client_deadline_expired_release_test COMMAND vireo_client_deadline_expired_release_test)
        set_tests_properties(vireo_client_deadline_expired_release_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_client_deadline_integration_test tests/net/test_client_deadline_integration.c)
        target_link_libraries(vireo_client_deadline_integration_test
            PRIVATE vireo_client_deadline vireo_timer_loop)
        vireo_target_enable_warnings(vireo_client_deadline_integration_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_integration_test)
        add_test(NAME vireo_client_deadline_integration_test COMMAND vireo_client_deadline_integration_test)
        set_tests_properties(vireo_client_deadline_integration_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_client_deadline_serve_test tests/net/test_client_deadline_serve.c)
        target_include_directories(vireo_client_deadline_serve_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_client_deadline_serve_test PRIVATE vireo_client_deadline)
        vireo_target_enable_warnings(vireo_client_deadline_serve_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_serve_test)
        add_test(NAME vireo_client_deadline_serve_test COMMAND vireo_client_deadline_serve_test)
        set_tests_properties(vireo_client_deadline_serve_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_client_deadline_idle_test tests/net/test_client_deadline_idle.c)
        target_link_libraries(vireo_client_deadline_idle_test PRIVATE vireo_client_deadline)
        vireo_target_enable_warnings(vireo_client_deadline_idle_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_idle_test)
        add_test(NAME vireo_client_deadline_idle_test COMMAND vireo_client_deadline_idle_test)
        set_tests_properties(vireo_client_deadline_idle_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_client_deadline_request_test tests/net/test_client_deadline_request.c)
        target_link_libraries(vireo_client_deadline_request_test PRIVATE vireo_client_deadline)
        vireo_target_enable_warnings(vireo_client_deadline_request_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_request_test)
        add_test(NAME vireo_client_deadline_request_test COMMAND vireo_client_deadline_request_test)
        set_tests_properties(vireo_client_deadline_request_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_client_deadline_request_integration_test
            tests/net/test_client_deadline_request_integration.c)
        target_link_libraries(vireo_client_deadline_request_integration_test
            PRIVATE vireo_client_deadline vireo_timer_loop)
        vireo_target_enable_warnings(vireo_client_deadline_request_integration_test)
        vireo_target_enable_sanitizers(vireo_client_deadline_request_integration_test)
        add_test(NAME vireo_client_deadline_request_integration_test
            COMMAND vireo_client_deadline_request_integration_test)
        set_tests_properties(vireo_client_deadline_request_integration_test PROPERTIES TIMEOUT 30)
    endif()
endif()

# BUILD_TESTING 由 include(CTest) 提供，默认开启
if (BUILD_TESTING)
    if(TARGET vireo_tcp_server)
        add_executable(vireo_tcp_server_auxiliary_capacity_test
            tests/net/test_tcp_server_auxiliary_capacity.c)
        target_include_directories(vireo_tcp_server_auxiliary_capacity_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_auxiliary_capacity_test PRIVATE vireo_tcp_server)
        vireo_target_enable_warnings(vireo_tcp_server_auxiliary_capacity_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_auxiliary_capacity_test)
        add_test(NAME vireo_tcp_server_auxiliary_capacity_test
            COMMAND vireo_tcp_server_auxiliary_capacity_test)
        set_tests_properties(vireo_tcp_server_auxiliary_capacity_test PROPERTIES TIMEOUT 30)

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
        add_executable(vireo_tcp_server_tls_test tests/net/test_tcp_server_tls.c)
        target_include_directories(vireo_tcp_server_tls_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_tls_test PRIVATE vireo_tcp_server OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tcp_server_tls_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_tls_test)
        add_test(NAME vireo_tcp_server_tls_test COMMAND vireo_tcp_server_tls_test)
        set_tests_properties(vireo_tcp_server_tls_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_tls_auxiliary_test tests/net/test_tcp_server_tls_auxiliary.c)
        target_include_directories(vireo_tcp_server_tls_auxiliary_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_tls_auxiliary_test PRIVATE vireo_notifier_server_dispatch vireo_notifier_server)
        vireo_target_enable_warnings(vireo_tcp_server_tls_auxiliary_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_tls_auxiliary_test)
        add_test(NAME vireo_tcp_server_tls_auxiliary_test COMMAND vireo_tcp_server_tls_auxiliary_test)
        set_tests_properties(vireo_tcp_server_tls_auxiliary_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_tls_application_test tests/net/test_tcp_server_tls_application.c)
        target_include_directories(vireo_tcp_server_tls_application_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_tls_application_test PRIVATE vireo_tcp_server OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tcp_server_tls_application_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_tls_application_test)
        add_test(NAME vireo_tcp_server_tls_application_test COMMAND vireo_tcp_server_tls_application_test)
        set_tests_properties(vireo_tcp_server_tls_application_test PROPERTIES TIMEOUT 30)
        add_executable(vireo_tcp_server_tls_close_test tests/net/test_tcp_server_tls_close.c)
        target_include_directories(vireo_tcp_server_tls_close_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_tls_close_test PRIVATE vireo_tcp_server OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tcp_server_tls_close_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_tls_close_test)
        add_test(NAME vireo_tcp_server_tls_close_test COMMAND vireo_tcp_server_tls_close_test)
        set_tests_properties(vireo_tcp_server_tls_close_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_tls_round_test tests/net/test_tcp_server_tls_round.c)
        target_include_directories(vireo_tcp_server_tls_round_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_tls_round_test PRIVATE vireo_tcp_server OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tcp_server_tls_round_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_tls_round_test)
        add_test(NAME vireo_tcp_server_tls_round_test COMMAND vireo_tcp_server_tls_round_test)
        set_tests_properties(vireo_tcp_server_tls_round_test PROPERTIES TIMEOUT 30)

        add_executable(vireo_tcp_server_tls_serve_test tests/net/test_tcp_server_tls_serve.c)
        target_include_directories(vireo_tcp_server_tls_serve_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_tcp_server_tls_serve_test PRIVATE vireo_tcp_server OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_tcp_server_tls_serve_test)
        vireo_target_enable_sanitizers(vireo_tcp_server_tls_serve_test)
        add_test(NAME vireo_tcp_server_tls_serve_test COMMAND vireo_tcp_server_tls_serve_test)
        set_tests_properties(vireo_tcp_server_tls_serve_test PROPERTIES TIMEOUT 30)

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

        add_executable(vireo_connection_pool_tls_test tests/net/test_connection_pool_tls.c)
        target_include_directories(vireo_connection_pool_tls_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_connection_pool_tls_test PRIVATE vireo_connection_pool OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_connection_pool_tls_test)
        vireo_target_enable_sanitizers(vireo_connection_pool_tls_test)
        add_test(NAME vireo_connection_pool_tls_test COMMAND vireo_connection_pool_tls_test)
        set_tests_properties(vireo_connection_pool_tls_test PROPERTIES TIMEOUT 30)
    endif()
    if(TARGET vireo_connection)
        add_executable(vireo_connection_tls_test tests/net/test_connection_tls.c)
        target_include_directories(vireo_connection_tls_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(vireo_connection_tls_test PRIVATE vireo_connection OpenSSL::SSL OpenSSL::Crypto)
        vireo_target_enable_warnings(vireo_connection_tls_test)
        vireo_target_enable_sanitizers(vireo_connection_tls_test)
        add_test(NAME vireo_connection_tls_test COMMAND vireo_connection_tls_test)
        set_tests_properties(vireo_connection_tls_test PROPERTIES TIMEOUT 30)

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
