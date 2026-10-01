/* PROJECT : VIREO -- 008-02 窄资源测试 seam；不是安装/稳定公共 API。 */
#ifndef VIREO_BASE_LOG_INTERNAL_H
#define VIREO_BASE_LOG_INTERNAL_H

#include <stddef.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <vireo/base/log.h>

/**
 * @brief 只替换本阶段实际资源操作，按值复制进对象，没有全局可变注入表
 * @note 每个函数必须非空；allocate 返回足够且适当对齐的存储，失败置 ENOMEM。
 * @note open/dup 成功返回独占 fd，失败 -1/errno；inspect/sync/close 为 0 或 -1/errno。
 * @note inspect_file 必须填写 stat；close 的失败必须遵守 Linux 已释放 fd 的语义。
 * @note 函数及其依赖状态须活到 destroy 完成；测试串行并负责其自有上下文。
 * @note M3锁/采集/write和M4三个固定名称轮转seam，仅对应已实现操作，不是通用I/O框架。
 * @note inspect_entry用no-follow，archive只选择两个固定名称之一；-1/ENOENT才表示不存在。
 * @note rename_file只在同一目录内替换单归档；open_new_file排他创建固定当前文件。
 * @note mutex 操作返回 pthread 直接错误码；注入销毁/解锁错误也须实际释放资源。
 * @note read_time 为 0（填完整 timestamp）或 -1/errno；thread_id 为正值，零模拟内部失败。
 * @note write_fd 为 write 的短进度/-1合同；生产版本包含线程级 SIGPIPE 防护。
 * @note 并发测试 callbacks 自行同步或仅在 logger 锁内访问测试状态，禁止重入 logger。
 */
typedef struct vireo_log_ops {
    void *(*allocate)(size_t size);
    void (*deallocate)(void *pointer);
    int (*duplicate_stderr)(void);
    int (*inspect_stderr)(int fd);
    int (*open_directory)(char const *directory);
    int (*open_file)(int directory_fd);
    int (*inspect_file)(int fd, struct stat *out_info);
    int (*sync_file)(int fd);
    int (*close_fd)(int fd);
    int (*init_mutex)(pthread_mutex_t *mutex);
    int (*destroy_mutex)(pthread_mutex_t *mutex);
    int (*lock_mutex)(pthread_mutex_t *mutex);
    int (*unlock_mutex)(pthread_mutex_t *mutex);
    int (*read_time)(vireo_log_timestamp_t *out_time);
    uint64_t (*thread_id)(void);
    ssize_t (*write_fd)(int fd, void const *data, size_t size);
    int (*inspect_entry)(int directory_fd, bool archive, struct stat *out_info);
    int (*rename_file)(int directory_fd);
    int (*open_new_file)(int directory_fd);
} vireo_log_ops_t;

/** 系统适配表只读，测试复制后才改变自己的版本。 */
extern vireo_log_ops_t const vireo_log_system_ops;

/**
 * @brief 内部 create 入口，生产 API 使用固定系统操作表，测试传入窄替代
 * @param[in] ops 完整且稳定，成功后按值复制；函数代码/依赖活到 destroy。
 * @note 其余参数/结果/errno/所有权合同与公共 create 相同；仅实现和测试使用。
 */
vireo_result_t vireo_log_create_with_ops(vireo_log_options_t const *options,
                                       vireo_log_t **out_logger, vireo_log_error_t *out_error,
                                       vireo_log_ops_t const *ops);

#endif /* VIREO_BASE_LOG_INTERNAL_H */
