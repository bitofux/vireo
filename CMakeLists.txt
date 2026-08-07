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

# GCC、Clang 和 AppleClang 的严格警告
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(
        vireo_result
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wshadow
            -Werror
    )
endif()

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

    # 测试代码使用与生产模块相同的严格警告
    if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(
            vireo_result_test
            PRIVATE
                -Wall
                -Wextra
                -Wpedantic
                -Wconversion
                -Wshadow
                -Werror
        )
    endif()

    # 把可测试文件注册到CTest
    add_test(
        NAME vireo_result_test
        COMMAND vireo_result_test
    )
endif()
