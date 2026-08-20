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

# BUILD_TESTING 由 include(CTest) 提供，默认开启
if (BUILD_TESTING)
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
endif()
