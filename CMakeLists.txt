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

# BUILD_TESTING 由 include(CTest) 提供，默认开启
if (BUILD_TESTING)
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
