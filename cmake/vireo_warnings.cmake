# 防止本模块在同一次 cmake 配置过程中被重复加载
include_guard(GLOBAL)

# 为指定的 vireo target 启用统一的严格警告
function(vireo_target_enable_warnings target_name)
    # 调用者必须传入一个由 add_library 或add_executable 创建的 target
    if (NOT TARGET "${target_name}")
        message(
            FATAL_ERROR
            "vireo_target_enable_warnings: target '${target_name}' does not exist"
        )
    endif()

    # 为GCC、Clang、AppleClang 应用当前 vireo 严格警告
    if (CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        target_compile_options(
            "${target_name}"
            PRIVATE
                -Wall
                -Wextra
                -Wpedantic
                -Wconversion
                -Wshadow
                -Werror
        )
    endif()
endfunction()
