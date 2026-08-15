# 防止本模块在同一次 cmake 配置过程中被重复加载
include_guard(GLOBAL)

# 增加配置选项：控制是否为 vireo target 启用 AddressSanitizer
option(
    # 选项名称
    VIREO_ENABLE_ASAN
    # 选项说明
    "Enable AddressSanitizer for Vireo targets"
    # 默认开关
    OFF
)

# 增加配置选项：控制是否为 vireo target 启用 UndefinedBehaviorSanitizer
option(
    # 选项名称
    VIREO_ENABLE_UBSAN
    # 选项说明
    "Enable UndefinedBehaviorSanitizer for Vireo targets"
    # 默认开关
    OFF
)

# 为指定的 vireo target 应用当前启用的 sanitizer
function(vireo_target_enable_sanitizers target_name)
    # 调用者传入的 target_name 必须是一个已经创建的 target
    if(NOT TARGET "${target_name}")
        message(
            FATAL_ERROR
            "vireo_target_enable_sanitizers: target '${target_name}' does not exist"
        )
    endif()

    # 两个 sanitizer 都未启用时，不修改 target
    if (NOT VIREO_ENABLE_ASAN AND NOT VIREO_ENABLE_UBSAN)
        return()
    endif()

    # 当前 sanitizer 只支持GCC、Clang、AppleClang
    if (NOT CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        message(
            FATAL_ERROR
            "vireo_target_enable_sanitizers: compiler '${CMAKE_C_COMPILER_ID}' is not supported"
        )
    endif()

    # 获取 target 的类型，主要用于判断它是否具有最终链接步骤
    get_target_property(
        target_type
        "${target_name}"
        TYPE
    )

    # 只要开启 sanitizer 就保留栈帧指针以改善错误调用栈
    set(
        vireo_sanitizer_compile_options
        -fno-omit-frame-pointer
    )

    # 链接参数从空列表开始，随后根据启用选项逐项加入
    set(vireo_sanitizer_link_options)

    # AddressSanitizer 同时需要编译插桩和运行时链接
    if(VIREO_ENABLE_ASAN)
        list(
            APPEND
            vireo_sanitizer_compile_options
            -fsanitize=address
        )

        list(
            APPEND
            vireo_sanitizer_link_options
            -fsanitize=address
        )
    endif()

    # UndefinedBehaviorSanitizer 同时需要编译插桩和运行时链接
    if(VIREO_ENABLE_UBSAN)
        list(
            APPEND
            vireo_sanitizer_compile_options
            -fsanitize=undefined
            -fno-sanitize-recover=undefined
        )

        list(
            APPEND
            vireo_sanitizer_link_options
            -fsanitize=undefined
        )
    endif()

    # 所有具有源文件的当前 vireo target 都需要编译插桩
    target_compile_options(
        "${target_name}"
        PRIVATE
            ${vireo_sanitizer_compile_options}
    )

    # 只有具有最终链接步骤的 target 才添加 sanitizer 链接参数
    if(target_type MATCHES "^(EXECUTABLE|SHARED_LIBRARY|MODULE_LIBRARY)$")
        target_link_options(
            "${target_name}"
            PRIVATE
                ${vireo_sanitizer_link_options}
        )
    endif()
endfunction()
