/*
 * PROJECT : VIREO
 * FILE    : log.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-01
 * BRIEF   : 此模块负责：
 * -- 校验日志 record 和显式 UTC 时间
 * -- 使用相同渲染逻辑完成先测量、后提交的固定单行格式化
 * -- 获取拥有型 logger 的资源，失败回滚，销毁时尽力同步和释放
 * -- 在单对象锁内写出完整事件，处理短进度及 sticky sink 首错
 * -- 同锁执行 file 数据同步与单归档轮转，明确部分成功后的 fd 所有权
 * IMPLEMENTATION : formatter 仍是无资源纯内存操作；共享 scratch/state/write 受对象锁保护。
 */
#define _GNU_SOURCE
#include <vireo/base/log.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <vireo/base/checked.h>
#include <vireo/base/result.h>

#include "log_internal.h"

typedef struct vireo_log_writer {
    char *data;            /* NULL 表示只计数；非空时拥有足够的已验证输出容量。 */
    size_t size;           /* 已渲染的字节数，尚不含最终 C NUL。 */
    vireo_result_t result; /* 受检加法的第一个失败，后续追加不再操作。 */
} vireo_log_writer_t;

char const *vireo_log_level_name(vireo_log_level_t level) {
    switch (level) {
        case VIREO_LOG_LEVEL_DEBUG:
            return "DEBUG";
        case VIREO_LOG_LEVEL_INFO:
            return "INFO";
        case VIREO_LOG_LEVEL_WARN:
            return "WARN";
        case VIREO_LOG_LEVEL_ERROR:
            return "ERROR";
        default:
            return "unknown";
    }
}

/**
 * @brief 追加已知有效且不重叠的字节，或只累计它们的长度
 * @param[in,out] writer 非空的局部 writer；写入模式具有预先测量的完整容量。
 * @param[in] data 指向 size 个可读字节，只借用本次调用。
 * @param[in] size 本次追加长度。
 * @note 累计失败后不写入、不推进；写模式必须以同一稳定输入预先测量。
 * @note 无所有权转移，无共享状态，不改变 errno；仅用于本实现。
 */
static void vireo_log_append(vireo_log_writer_t *writer, char const *data, size_t size) {
    size_t next_size;
    if (writer->result != VIREO_OK) {
        return;
    }
    writer->result = vireo_checked_size_add(writer->size, size, &next_size);
    if (writer->result != VIREO_OK) {
        return;
    }
    if (writer->data != NULL && size != 0) {
        memcpy(writer->data + writer->size, data, size);
    }
    writer->size = next_size;
}

/**
 * @brief 输出 uint64_t 的 ASCII 十进制，以最小位宽或指定零填充宽度显示
 * @param[in,out] writer 已初始化且容量已验证的局部 writer。
 * @param[in] value 任意无符号 64 位值。
 * @param[in] width 最小显示位数；本实现只传入 0、2、4、9。
 * @note 20 位局部数组足够 UINT64_MAX；不返回或保存局部数组指针。
 * @note 无 heap、共享状态或 errno 副作用；仅用于本实现。
 */
static void vireo_log_append_number(vireo_log_writer_t *writer, uint64_t value, size_t width) {
    char digits[20];
    size_t count = 0;
    do {
        digits[count++] = (char)('0' + (char)(value % UINT64_C(10)));
        value /= UINT64_C(10);
    } while (value != 0);
    while (width > count) {
        vireo_log_append(writer, "0", 1);
        --width;
    }
    while (count != 0) {
        --count;
        vireo_log_append(writer, &digits[count], 1);
    }
}

/**
 * @brief 用双引号包围已校验 span 并对所有字节执行确定性转义
 * @param[in,out] writer 计数或容量已验证的局部 writer。
 * @param[in] span size 已受字段上限约束，非零 size 的 data 可读且稳定。
 * @note byte 最大扩为四字节；只借用输入，空 span 不解引用 data。
 * @note ASCII 分类显式比较，避免 signed char、locale 和 UTF-8 推测。
 * @note 无共享可变状态，不修改 errno；只供当前实现。
 */
static void vireo_log_append_span(vireo_log_writer_t *writer, vireo_log_span_t span) {
    static char const hex[] = "0123456789ABCDEF";
    vireo_log_append(writer, "\"", 1);
    for (size_t i = 0; i < span.size; ++i) {
        uint8_t byte = span.data[i];
        if (byte == (uint8_t)'\n') {
            vireo_log_append(writer, "\\n", 2);
        } else if (byte == (uint8_t)'\r') {
            vireo_log_append(writer, "\\r", 2);
        } else if (byte == (uint8_t)'\t') {
            vireo_log_append(writer, "\\t", 2);
        } else if (byte == (uint8_t)'"' || byte == (uint8_t)'\\') {
            char escaped[2] = {'\\', (char)byte};
            vireo_log_append(writer, escaped, sizeof(escaped));
        } else if (byte >= UINT8_C(0x20) && byte <= UINT8_C(0x7E)) {
            char printable = (char)byte;
            vireo_log_append(writer, &printable, 1);
        } else {
            char escaped[4] = {'\\', 'x', hex[byte >> 4U], hex[byte & UINT8_C(0x0F)]};
            vireo_log_append(writer, escaped, sizeof(escaped));
        }
    }
    vireo_log_append(writer, "\"", 1);
}

static bool vireo_log_valid_timestamp(vireo_log_timestamp_t const *timestamp) {
    static uint8_t const month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (timestamp->year < 1970 || timestamp->year > 9999 || timestamp->month < 1 ||
        timestamp->month > 12 || timestamp->hour > 23 || timestamp->minute > 59 ||
        timestamp->second > 59 || timestamp->nanosecond > UINT32_C(999999999)) {
        return false;
    }
    uint8_t days = month_days[timestamp->month - 1U];
    bool leap =
        timestamp->year % 4U == 0 && (timestamp->year % 100U != 0 || timestamp->year % 400U == 0);
    if (timestamp->month == 2 && leap) {
        days = 29;
    }
    return timestamp->day >= 1 && timestamp->day <= days;
}

/**
 * @brief 在访问 span 字节前拒绝过长输入和缺失指针
 * @param[in] span 调用者借用的字节范围。
 * @param[in] limit 该字段允许的原始字节上限。
 * @retval VIREO_OK 结构合法；地址可读性仍由调用者保证。
 * @retval VIREO_RESULT_RANGE size 超过字段上限，未读取 span.data。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 合法非零 size 配 NULL data。
 * @note 只查元数据，无写入、所有权转移或 errno 副作用。
 */
static vireo_result_t vireo_log_validate_span(vireo_log_span_t span, size_t limit) {
    if (span.size > limit) {
        return VIREO_RESULT_RANGE;
    }
    if (span.size != 0 && span.data == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    return VIREO_OK;
}

/**
 * @brief 渲染固定字段顺序，供测量和正式写入共用
 * @param[in,out] writer 已初始化的测量器或预先验证容量的输出器。
 * @param[in] record 已校验、稳定的借用输入。
 * @param[in] timestamp 已校验的 UTC；调用期间不变。
 * @param[in] thread_id 已校验为正的线程身份。
 * @note 调用者必须先验证全部字段；写模式的容量来自完全相同输入的测量。
 * @note 不提交 out_size 或 C NUL，无共享状态，不修改 errno。
 */
static void vireo_log_render(vireo_log_writer_t *writer, vireo_log_record_t const *record,
                             vireo_log_timestamp_t const *timestamp, uint64_t thread_id) {
    vireo_log_append_number(writer, timestamp->year, 4);
    vireo_log_append(writer, "-", 1);
    vireo_log_append_number(writer, timestamp->month, 2);
    vireo_log_append(writer, "-", 1);
    vireo_log_append_number(writer, timestamp->day, 2);
    vireo_log_append(writer, "T", 1);
    vireo_log_append_number(writer, timestamp->hour, 2);
    vireo_log_append(writer, ":", 1);
    vireo_log_append_number(writer, timestamp->minute, 2);
    vireo_log_append(writer, ":", 1);
    vireo_log_append_number(writer, timestamp->second, 2);
    vireo_log_append(writer, ".", 1);
    vireo_log_append_number(writer, timestamp->nanosecond, 9);
    vireo_log_append(writer, "Z level=", 8);
    char const *level = vireo_log_level_name(record->level);
    vireo_log_append(writer, level, strlen(level));
    vireo_log_append(writer, " tid=", 5);
    vireo_log_append_number(writer, thread_id, 0);
    vireo_log_append(writer, " module=", 8);
    vireo_log_append_span(writer, record->module);
    vireo_log_append(writer, " connection_id=", 15);
    vireo_log_append_number(writer, record->connection_id, 0);
    vireo_log_append(writer, " generation=", 12);
    vireo_log_append_number(writer, record->generation, 0);
    vireo_log_append(writer, " sequence=", 10);
    vireo_log_append_number(writer, record->sequence, 0);
    vireo_log_append(writer, " request_id=", 12);
    vireo_log_append_span(writer, record->request_id);
    vireo_log_append(writer, " task_id=", 9);
    vireo_log_append_span(writer, record->task_id);
    vireo_log_append(writer, " message=", 9);
    vireo_log_append_span(writer, record->message);
    vireo_log_append(writer, "\n", 1);
}

vireo_result_t vireo_log_format(vireo_log_record_t const *record,
                                vireo_log_timestamp_t const *timestamp, uint64_t thread_id,
                                char *buffer, size_t capacity, size_t *out_size) {
    if (record == NULL || timestamp == NULL || buffer == NULL || out_size == NULL ||
        thread_id == 0 || record->level < VIREO_LOG_LEVEL_DEBUG ||
        record->level > VIREO_LOG_LEVEL_ERROR) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (!vireo_log_valid_timestamp(timestamp)) {
        return VIREO_RESULT_RANGE;
    }
    vireo_log_span_t spans[] = {record->module, record->request_id, record->task_id,
                                record->message};
    size_t const limits[] = {VIREO_LOG_MAX_MODULE_SIZE, VIREO_LOG_MAX_ID_SIZE,
                             VIREO_LOG_MAX_ID_SIZE, VIREO_LOG_MAX_MESSAGE_SIZE};
    for (size_t i = 0; i < sizeof(spans) / sizeof(spans[0]); ++i) {
        vireo_result_t result = vireo_log_validate_span(spans[i], limits[i]);
        if (result != VIREO_OK) {
            return result;
        }
    }

    vireo_log_writer_t measure = {.data = NULL, .size = 0, .result = VIREO_OK};
    vireo_log_render(&measure, record, timestamp, thread_id);
    if (measure.result != VIREO_OK) {
        return measure.result;
    }
    if (measure.size > VIREO_LOG_MAX_LINE_SIZE) {
        return VIREO_RESULT_RANGE;
    }
    size_t required;
    vireo_result_t result = vireo_checked_size_add(measure.size, 1, &required);
    if (result != VIREO_OK) {
        return result;
    }
    if (capacity < required) {
        return VIREO_RESULT_RANGE;
    }

    /* 输入稳定且测量成功，第二遍不再存在可拒绝的字段或容量分支。 */
    vireo_log_writer_t output = {.data = buffer, .size = 0, .result = VIREO_OK};
    vireo_log_render(&output, record, timestamp, thread_id);
    buffer[output.size] = '\0';
    *out_size = output.size;
    return VIREO_OK;
}

/* 以下资源与同步写入层复用上面的纯 formatter，不向 formatter 混入系统依赖。 */
struct vireo_log {
    vireo_log_ops_t ops; /* 拷贝的稳定函数表，无全局 mutable hook。 */
    int directory_fd;    /* -1 未取得；其他值由本对象唯一关闭。 */
    int file_fd;
    int stderr_fd;
    uint64_t max_file_size_bytes;                 /* 写前以真实 fstat size 判定，不保存漂移计数。 */
    char directory[VIREO_LOG_DIRECTORY_CAPACITY]; /* 自有路径，不借用 config。 */
    pthread_mutex_t mutex;                        /* 发布后不拷贝/移动；整个 emit 临界区。 */
    bool mutex_initialized;                       /* rollback 只销毁真实初始化成功的锁。 */
    enum { VIREO_LOG_DISABLED, VIREO_LOG_HEALTHY, VIREO_LOG_FAILED } file_state, stderr_state;
    vireo_log_error_t file_error, stderr_error; /* FAILED 终态的按值首错。 */
    char line[VIREO_LOG_MAX_LINE_SIZE + 1];     /* 仅持锁格式化和写入，无 emit heap。 */
};

static int vireo_log_init_mutex(pthread_mutex_t *mutex) {
    return pthread_mutex_init(mutex, NULL);
}

/**
 * @brief 获取有界 UTC 显示时间，成功才提交；仅在 emit 对象锁内调用
 * @param[out] out_time 非空局部输出；time_t 到窄字段先范围验证。
 * @return 0 成功；-1 并设置 errno 表示系统错误或不可表示日历。
 * @note clock_gettime 可能走 vDSO；gmtime_r 使用自有 tm，不借静态缓冲。
 */
static int vireo_log_read_time(vireo_log_timestamp_t *out_time) {
    struct timespec now;
    struct tm utc;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || gmtime_r(&now.tv_sec, &utc) == NULL) {
        return -1;
    }
    if (utc.tm_year < 70 || utc.tm_year > 8099 || utc.tm_mon < 0 || utc.tm_mon > 11 ||
        utc.tm_mday < 1 || utc.tm_mday > 31 || utc.tm_hour < 0 || utc.tm_hour > 23 ||
        utc.tm_min < 0 || utc.tm_min > 59 || utc.tm_sec < 0 || utc.tm_sec > 59 || now.tv_nsec < 0 ||
        now.tv_nsec > 999999999L) {
        errno = EOVERFLOW;
        return -1;
    }
    *out_time = (vireo_log_timestamp_t){.year = (uint16_t)(utc.tm_year + 1900),
                                        .month = (uint8_t)(utc.tm_mon + 1),
                                        .day = (uint8_t)utc.tm_mday,
                                        .hour = (uint8_t)utc.tm_hour,
                                        .minute = (uint8_t)utc.tm_min,
                                        .second = (uint8_t)utc.tm_sec,
                                        .nanosecond = (uint32_t)now.tv_nsec};
    return 0;
}

static uint64_t vireo_log_thread_id(void) {
    pid_t tid = gettid();
    return tid > 0 ? (uint64_t)tid : 0;
}

/**
 * @brief 只在调用线程临时屏蔽 write 产生的 SIGPIPE，保持旧 mask 和 pending
 * @param[in] fd/data/size 合法的借用 write 输入；不关闭 fd 或保存指针。
 * @return write 的原始短进度/-1；预备 mask/pending 失败不执行 write。
 * @note 外部不得在这段调用中人工发送 SIGPIPE；已有 pending 必须原样保留。
 * @note 不改全进程 handler；有效 mask/set 的恢复失败按错误返回，不重写已输出字节。
 */
static ssize_t vireo_log_write_safe(int fd, void const *data, size_t size) {
    sigset_t blocked, original, pending;
    if (sigemptyset(&blocked) != 0 || sigaddset(&blocked, SIGPIPE) != 0) {
        return -1;
    }
    int code = pthread_sigmask(SIG_BLOCK, &blocked, &original);
    if (code != 0) {
        errno = code;
        return -1;
    }
    if (sigpending(&pending) != 0) {
        int error = errno;
        (void)pthread_sigmask(SIG_SETMASK, &original, NULL);
        errno = error;
        return -1;
    }
    bool was_pending = sigismember(&pending, SIGPIPE) == 1;
    ssize_t result = write(fd, data, size);
    int error = errno;
    /* 阻塞管道失去读端也可能先写出部分字节、正返回并产生 SIGPIPE。
     * 正返回后的 errno 不是错误证据；保留进度，让 write_all 继续剩余字节。 */
    bool may_have_sigpipe = (result < 0 && error == EPIPE) ||
                            (result > 0 && (size_t)result < size);
    if (may_have_sigpipe && !was_pending) {
        struct timespec const zero = {0};
        /* EAGAIN 在 SIG_IGN 情况下合法；EINTR 不代表已经消费了本次 SIGPIPE。 */
        while (sigtimedwait(&blocked, NULL, &zero) < 0 && errno == EINTR) {
        }
    }
    code = pthread_sigmask(SIG_SETMASK, &original, NULL);
    if (code != 0) {
        errno = code;
        return -1;
    }
    errno = error;
    return result;
}

static void *vireo_log_allocate(size_t size) {
    return calloc(1, size);
}

static int vireo_log_duplicate_stderr(void) {
    return fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);
}

static int vireo_log_inspect_stderr(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        return -1;
    }
    if ((flags & O_ACCMODE) == O_RDONLY) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

static int vireo_log_open_directory(char const *directory) {
    return open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

static int vireo_log_open_file(int directory_fd) {
    /* O_NONBLOCK 避免打开 FIFO 等待；普通文件仍可能阻塞，不声称 Reactor-safe。 */
    return openat(directory_fd, VIREO_LOG_FILE_NAME,
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY,
                  (mode_t)0640);
}

static int vireo_log_inspect_entry(int directory_fd, bool archive, struct stat *out_info) {
    return fstatat(directory_fd, archive ? VIREO_LOG_ARCHIVE_NAME : VIREO_LOG_FILE_NAME, out_info,
                   AT_SYMLINK_NOFOLLOW);
}

static int vireo_log_rename_file(int directory_fd) {
    return renameat(directory_fd, VIREO_LOG_FILE_NAME, directory_fd, VIREO_LOG_ARCHIVE_NAME);
}

static int vireo_log_open_new_file(int directory_fd) {
    return openat(
        directory_fd, VIREO_LOG_FILE_NAME,
        O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY,
        (mode_t)0640);
}

vireo_log_ops_t const vireo_log_system_ops = {
    .allocate = vireo_log_allocate,
    .deallocate = free,
    .duplicate_stderr = vireo_log_duplicate_stderr,
    .inspect_stderr = vireo_log_inspect_stderr,
    .open_directory = vireo_log_open_directory,
    .open_file = vireo_log_open_file,
    .inspect_file = fstat,
    .sync_file = fdatasync,
    .close_fd = close,
    .init_mutex = vireo_log_init_mutex,
    .destroy_mutex = pthread_mutex_destroy,
    .lock_mutex = pthread_mutex_lock,
    .unlock_mutex = pthread_mutex_unlock,
    .read_time = vireo_log_read_time,
    .thread_id = vireo_log_thread_id,
    .write_fd = vireo_log_write_safe,
    .inspect_entry = vireo_log_inspect_entry,
    .rename_file = vireo_log_rename_file,
    .open_new_file = vireo_log_open_new_file,
};

/** 按值写诊断，NULL 不改变真实操作；输出属于调用者，不保存指针或打印。 */
static void vireo_log_error_set(vireo_log_error_t *out_error, vireo_log_sink_t sink,
                                vireo_log_stage_t stage, int system_errno) {
    if (out_error != NULL) {
        *out_error =
            (vireo_log_error_t){.sink = sink, .stage = stage, .system_errno = system_errno};
    }
}

/**
 * @brief 在获取资源前校验选项并计算有界路径长度
 * @note options/length 非空；path 可读性和 bool 对象表示由调用者保证。
 * @note 不写主要输出、不获取资源、不修改 errno；directory=NULL 不读取阈值。
 */
static vireo_result_t vireo_log_validate_options(vireo_log_options_t const *options,
                                                 size_t *out_directory_size) {
    *out_directory_size = 0;
    if (options->directory == NULL) {
        return options->to_stderr ? VIREO_OK : VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t size = 0;
    while (size < VIREO_LOG_DIRECTORY_CAPACITY && options->directory[size] != '\0') {
        unsigned char byte = (unsigned char)options->directory[size];
        if (byte < 32U || byte == 127U) {
            return VIREO_RESULT_INVALID_ARGUMENT;
        }
        ++size;
    }
    if (size == VIREO_LOG_DIRECTORY_CAPACITY) {
        return VIREO_RESULT_RANGE;
    }
    if (size == 0 || options->directory[0] != '/') {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (options->max_file_size_bytes < VIREO_LOG_MIN_FILE_SIZE_BYTES ||
        options->max_file_size_bytes > VIREO_LOG_MAX_FILE_SIZE_BYTES) {
        return VIREO_RESULT_RANGE;
    }
    while (size > 1 && options->directory[size - 1] == '/') {
        --size;
    }
    *out_directory_size = size;
    return VIREO_OK;
}

static bool vireo_log_ops_valid(vireo_log_ops_t const *ops) {
    return ops != NULL && ops->allocate != NULL && ops->deallocate != NULL &&
           ops->duplicate_stderr != NULL && ops->inspect_stderr != NULL &&
           ops->open_directory != NULL && ops->open_file != NULL && ops->inspect_file != NULL &&
           ops->sync_file != NULL && ops->close_fd != NULL && ops->init_mutex != NULL &&
           ops->destroy_mutex != NULL && ops->lock_mutex != NULL && ops->unlock_mutex != NULL &&
           ops->read_time != NULL && ops->thread_id != NULL && ops->write_fd != NULL &&
           ops->inspect_entry != NULL && ops->rename_file != NULL && ops->open_new_file != NULL;
}

/** 同一基本属性规则用于创建、当前 file 和轮转归档；不修改外部属性。 */
static bool vireo_log_file_attributes_valid(struct stat const *info) {
    mode_t forbidden = S_IXUSR | S_IXGRP | S_IXOTH | S_IWGRP | S_IRWXO;
    return S_ISREG(info->st_mode) && info->st_nlink == 1 && info->st_uid == geteuid() &&
           (info->st_mode & forbidden) == 0;
}

/**
 * @brief 回收未发布对象；主错误已在调用者局部值保存，清理不能覆盖它
 * @note 逆取得顺序 close 一次；不 sync、不 unlink，所有函数来自对象拷贝的表。
 */
static void vireo_log_rollback(vireo_log_t *logger) {
    if (logger->file_fd >= 0) {
        (void)logger->ops.close_fd(logger->file_fd);
    }
    if (logger->directory_fd >= 0) {
        (void)logger->ops.close_fd(logger->directory_fd);
    }
    if (logger->stderr_fd >= 0) {
        (void)logger->ops.close_fd(logger->stderr_fd);
    }
    if (logger->mutex_initialized) {
        (void)logger->ops.destroy_mutex(&logger->mutex);
    }
    logger->ops.deallocate(logger);
}

vireo_result_t vireo_log_create_with_ops(vireo_log_options_t const *options,
                                         vireo_log_t **out_logger, vireo_log_error_t *out_error,
                                         vireo_log_ops_t const *ops) {
    int saved_errno = errno;
    vireo_log_error_t error = {.sink = VIREO_LOG_SINK_NONE, .stage = VIREO_LOG_STAGE_VALIDATE};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_log_t *logger = NULL;
    size_t directory_size = 0;
    if (options == NULL || out_logger == NULL || !vireo_log_ops_valid(ops) || *out_logger != NULL) {
        goto fail;
    }
    error.sink = options->directory == NULL ? VIREO_LOG_SINK_NONE : VIREO_LOG_SINK_FILE;
    result = vireo_log_validate_options(options, &directory_size);
    if (result != VIREO_OK) {
        goto fail;
    }
    error = (vireo_log_error_t){.stage = VIREO_LOG_STAGE_ALLOCATE};
    logger = ops->allocate(sizeof(*logger));
    if (logger == NULL) {
        error.system_errno = ENOMEM;
        result = VIREO_RESULT_NO_MEMORY;
        goto fail;
    }
    *logger = (vireo_log_t){
        .ops = *ops,
        .directory_fd = -1,
        .file_fd = -1,
        .stderr_fd = -1,
        .max_file_size_bytes = options->directory == NULL ? 0 : options->max_file_size_bytes};
    if (options->directory != NULL) {
        memcpy(logger->directory, options->directory, directory_size);
        logger->directory[directory_size] = '\0';
    }

    error = (vireo_log_error_t){.stage = VIREO_LOG_STAGE_INIT_MUTEX};
    int code = logger->ops.init_mutex(&logger->mutex);
    if (code != 0) {
        error.system_errno = code;
        result = VIREO_RESULT_INTERNAL;
        goto fail;
    }
    logger->mutex_initialized = true;

    result = VIREO_RESULT_IO;
    /* 必须在其他 open 可能复用 fd 2 之前捕获调用者 stderr。 */
    if (options->to_stderr) {
        error =
            (vireo_log_error_t){.sink = VIREO_LOG_SINK_STDERR, .stage = VIREO_LOG_STAGE_DUP_STDERR};
        logger->stderr_fd = logger->ops.duplicate_stderr();
        if (logger->stderr_fd < 0) {
            error.system_errno = errno;
            goto fail;
        }
        error.stage = VIREO_LOG_STAGE_CHECK_STDERR;
        if (logger->ops.inspect_stderr(logger->stderr_fd) != 0) {
            error.system_errno = errno;
            goto fail;
        }
    }
    if (options->directory != NULL) {
        error = (vireo_log_error_t){.sink = VIREO_LOG_SINK_FILE,
                                    .stage = VIREO_LOG_STAGE_OPEN_DIRECTORY};
        logger->directory_fd = logger->ops.open_directory(logger->directory);
        if (logger->directory_fd < 0) {
            error.system_errno = errno;
            goto fail;
        }
        error.stage = VIREO_LOG_STAGE_OPEN_FILE;
        logger->file_fd = logger->ops.open_file(logger->directory_fd);
        if (logger->file_fd < 0) {
            error.system_errno = errno;
            goto fail;
        }
        error.stage = VIREO_LOG_STAGE_CHECK_FILE;
        struct stat info;
        if (logger->ops.inspect_file(logger->file_fd, &info) != 0) {
            error.system_errno = errno;
            goto fail;
        }
        if (!vireo_log_file_attributes_valid(&info)) {
            goto fail;
        }
    }
    logger->file_state = logger->file_fd < 0 ? VIREO_LOG_DISABLED : VIREO_LOG_HEALTHY;
    logger->stderr_state = logger->stderr_fd < 0 ? VIREO_LOG_DISABLED : VIREO_LOG_HEALTHY;
    *out_logger = logger;
    vireo_log_error_set(out_error, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0);
    errno = saved_errno;
    return VIREO_OK;

fail:
    if (logger != NULL) {
        vireo_log_rollback(logger);
    }
    vireo_log_error_set(out_error, error.sink, error.stage, error.system_errno);
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_log_create(vireo_log_options_t const *options, vireo_log_t **out_logger,
                                vireo_log_error_t *out_error) {
    return vireo_log_create_with_ops(options, out_logger, out_error, &vireo_log_system_ops);
}

/** 仅在尚无首错时记录当前系统原因；始终由上层继续其他清理。 */
static void vireo_log_first_cleanup_error(vireo_log_error_t *error, vireo_log_sink_t sink,
                                          vireo_log_stage_t stage, int system_errno) {
    if (error->stage == VIREO_LOG_STAGE_NONE) {
        *error = (vireo_log_error_t){.sink = sink, .stage = stage, .system_errno = system_errno};
    }
}

vireo_result_t vireo_log_destroy(vireo_log_t **inout_logger, vireo_log_error_t *out_error) {
    int saved_errno = errno;
    vireo_log_error_t error = {0};
    if (inout_logger == NULL) {
        vireo_log_error_set(out_error, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_VALIDATE, 0);
        errno = saved_errno;
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_log_t *logger = *inout_logger;
    if (logger != NULL) {
        if (logger->file_fd >= 0) {
            if (logger->ops.sync_file(logger->file_fd) != 0) {
                vireo_log_first_cleanup_error(&error, VIREO_LOG_SINK_FILE,
                                              VIREO_LOG_STAGE_SYNC_FILE, errno);
            }
            if (logger->ops.close_fd(logger->file_fd) != 0) {
                vireo_log_first_cleanup_error(&error, VIREO_LOG_SINK_FILE,
                                              VIREO_LOG_STAGE_CLOSE_FILE, errno);
            }
        }
        if (logger->stderr_fd >= 0 && logger->ops.close_fd(logger->stderr_fd) != 0) {
            vireo_log_first_cleanup_error(&error, VIREO_LOG_SINK_STDERR,
                                          VIREO_LOG_STAGE_CLOSE_STDERR, errno);
        }
        if (logger->directory_fd >= 0 && logger->ops.close_fd(logger->directory_fd) != 0) {
            vireo_log_first_cleanup_error(&error, VIREO_LOG_SINK_FILE,
                                          VIREO_LOG_STAGE_CLOSE_DIRECTORY, errno);
        }
        int code = logger->ops.destroy_mutex(&logger->mutex);
        if (code != 0) {
            vireo_log_first_cleanup_error(&error, VIREO_LOG_SINK_NONE,
                                          VIREO_LOG_STAGE_DESTROY_MUTEX, code);
        }
        logger->ops.deallocate(logger);
        *inout_logger = NULL;
    }
    vireo_log_error_set(out_error, error.sink, error.stage, error.system_errno);
    errno = saved_errno;
    return error.stage == VIREO_LOG_STAGE_NONE            ? VIREO_OK
           : error.stage == VIREO_LOG_STAGE_DESTROY_MUTEX ? VIREO_RESULT_INTERNAL
                                                          : VIREO_RESULT_IO;
}

/**
 * @brief 持锁写完一行；每次正进度精确推进，返回第一个终止原因
 * @param[in] logger/fd/size 已持对象锁，line 已完整生成，size 不含 NUL 且非零。
 * @return 0 全部接受；非零为 errno 原因，零进度/非法 seam 返回值归 EIO。
 * @note 不分配、不关闭、不重入；16 次连续 EINTR 重试防止注入/持续信号忙循环。
 */
static int vireo_log_write_all(vireo_log_t *logger, int fd, size_t size) {
    size_t offset = 0;
    unsigned interruptions = 0;
    while (offset < size) {
        ssize_t count = logger->ops.write_fd(fd, logger->line + offset, size - offset);
        if (count > 0 && (size_t)count <= size - offset) {
            offset += (size_t)count;
            interruptions = 0;
        } else if (count < 0 && errno == EINTR && interruptions < 16U) {
            ++interruptions;
        } else {
            return count < 0 && errno != 0 ? errno : EIO;
        }
    }
    return 0;
}

/**
 * @brief 已持锁、file健康时写前检查；必要轮转，不写行、不改变sink状态
 * @param[in] size 完整下一行的正长度；不超过 formatter 行上限。
 * @param[out] error 非空；失败为 FILE 的实际阶段和原因。
 * @return true 可以写当前fd；false需由上层将file置FAILED并继续其他sink。
 * @note 源项/归档检查到rename期间目录必须外部独占，不能当恶意并发沙箱。
 * @note 排他创建后检查前局部拥有新fd，交接后logger拥有；旧fd只close一次。
 */
static bool vireo_log_prepare_file(vireo_log_t *logger, size_t size, vireo_log_error_t *error) {
    struct stat current, entry;
    *error = (vireo_log_error_t){VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_FILE_SIZE, 0};
    if (logger->ops.inspect_file(logger->file_fd, &current) != 0) {
        error->system_errno = errno;
        return false;
    }
    if (!vireo_log_file_attributes_valid(&current)) {
        error->system_errno = EPERM;
        return false;
    }
    if (current.st_size < 0 || (uint64_t)size > logger->max_file_size_bytes) {
        error->system_errno = EFBIG;
        return false;
    }
    uint64_t bytes = (uint64_t)current.st_size;
    if (bytes <= logger->max_file_size_bytes &&
        (uint64_t)size <= logger->max_file_size_bytes - bytes) {
        return true;
    }

    error->stage = VIREO_LOG_STAGE_CHECK_CURRENT_ENTRY;
    if (logger->ops.inspect_entry(logger->directory_fd, false, &entry) != 0) {
        error->system_errno = errno;
        return false;
    }
    if (!vireo_log_file_attributes_valid(&entry) || entry.st_dev != current.st_dev ||
        entry.st_ino != current.st_ino) {
        error->system_errno = EPERM;
        return false;
    }
    error->stage = VIREO_LOG_STAGE_CHECK_ARCHIVE;
    if (logger->ops.inspect_entry(logger->directory_fd, true, &entry) != 0) {
        if (errno != ENOENT) {
            error->system_errno = errno;
            return false;
        }
    } else if (!vireo_log_file_attributes_valid(&entry)) {
        error->system_errno = EPERM;
        return false;
    }
    error->stage = VIREO_LOG_STAGE_SYNC_FILE;
    if (logger->ops.sync_file(logger->file_fd) != 0) {
        error->system_errno = errno;
        return false;
    }
    error->stage = VIREO_LOG_STAGE_RENAME_FILE;
    if (logger->ops.rename_file(logger->directory_fd) != 0) {
        error->system_errno = errno;
        return false;
    }
    error->stage = VIREO_LOG_STAGE_OPEN_NEW_FILE;
    int new_fd = logger->ops.open_new_file(logger->directory_fd);
    if (new_fd < 0) {
        error->system_errno = errno;
        return false; /* logger仍拥有改名后的旧fd，不能继续写归档。 */
    }
    error->stage = VIREO_LOG_STAGE_CHECK_NEW_FILE;
    bool valid = logger->ops.inspect_file(new_fd, &entry) == 0;
    if (!valid) {
        error->system_errno = errno;
    } else if (!vireo_log_file_attributes_valid(&entry) || entry.st_size != 0) {
        valid = false;
        error->system_errno = EPERM;
    }
    if (!valid) {
        (void)logger->ops.close_fd(new_fd); /* 保留检查首错，不回滚目录项。 */
        return false;
    }
    int old_fd = logger->file_fd;
    logger->file_fd = new_fd; /* 新fd已通过检查，发布后旧fd不再由destroy消费。 */
    error->stage = VIREO_LOG_STAGE_CLOSE_OLD_FILE;
    if (logger->ops.close_fd(old_fd) != 0) {
        error->system_errno = errno;
        return false; /* Linux close已消费old_fd，失败不能重试。 */
    }
    return true;
}

vireo_result_t vireo_log_emit(vireo_log_t *logger, vireo_log_record_t const *record,
                              vireo_log_error_t *out_error) {
    int saved_errno = errno;
    vireo_log_error_t error = {.stage = VIREO_LOG_STAGE_VALIDATE};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (logger == NULL || record == NULL) {
        goto done;
    }
    int code = logger->ops.lock_mutex(&logger->mutex);
    if (code != 0) {
        error = (vireo_log_error_t){.stage = VIREO_LOG_STAGE_LOCK, .system_errno = code};
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }
    /* 借用 record 整次调用稳定；参数失败优先于时间错误，且不访问 sink。 */
    if (record->level < VIREO_LOG_LEVEL_DEBUG || record->level > VIREO_LOG_LEVEL_ERROR) {
        goto unlock;
    }
    vireo_log_span_t const spans[] = {record->module, record->request_id, record->task_id,
                                      record->message};
    size_t const limits[] = {VIREO_LOG_MAX_MODULE_SIZE, VIREO_LOG_MAX_ID_SIZE,
                             VIREO_LOG_MAX_ID_SIZE, VIREO_LOG_MAX_MESSAGE_SIZE};
    for (size_t i = 0; i < sizeof(spans) / sizeof(spans[0]); ++i) {
        result = vireo_log_validate_span(spans[i], limits[i]);
        if (result != VIREO_OK) {
            goto unlock;
        }
    }
    vireo_log_timestamp_t timestamp;
    error = (vireo_log_error_t){.stage = VIREO_LOG_STAGE_CLOCK};
    if (logger->ops.read_time(&timestamp) != 0) {
        error.system_errno = errno;
        result = VIREO_RESULT_IO;
        goto unlock;
    }
    uint64_t tid = logger->ops.thread_id();
    if (tid == 0) {
        error = (vireo_log_error_t){.stage = VIREO_LOG_STAGE_THREAD_ID};
        result = VIREO_RESULT_INTERNAL;
        goto unlock;
    }
    size_t size = 0;
    error = (vireo_log_error_t){.stage = VIREO_LOG_STAGE_FORMAT};
    result = vireo_log_format(record, &timestamp, tid, logger->line, sizeof(logger->line), &size);
    if (result != VIREO_OK) {
        goto unlock;
    }
    error = (vireo_log_error_t){0};
    if (logger->file_state == VIREO_LOG_HEALTHY) {
        vireo_log_error_t file_error;
        if (!vireo_log_prepare_file(logger, size, &file_error)) {
            logger->file_state = VIREO_LOG_FAILED;
            logger->file_error = file_error;
        } else {
            int cause = vireo_log_write_all(logger, logger->file_fd, size);
            if (cause != 0) {
                logger->file_state = VIREO_LOG_FAILED;
                logger->file_error =
                    (vireo_log_error_t){VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_WRITE, cause};
            }
        }
    }
    if (logger->file_state == VIREO_LOG_FAILED) {
        error = logger->file_error;
    }
    if (logger->stderr_state == VIREO_LOG_HEALTHY) {
        int cause = vireo_log_write_all(logger, logger->stderr_fd, size);
        if (cause != 0) {
            logger->stderr_state = VIREO_LOG_FAILED;
            logger->stderr_error =
                (vireo_log_error_t){VIREO_LOG_SINK_STDERR, VIREO_LOG_STAGE_WRITE, cause};
        }
    }
    if (logger->stderr_state == VIREO_LOG_FAILED && error.stage == VIREO_LOG_STAGE_NONE) {
        error = logger->stderr_error;
    }
    result = error.stage == VIREO_LOG_STAGE_NONE ? VIREO_OK : VIREO_RESULT_IO;

unlock:
    code = logger->ops.unlock_mutex(&logger->mutex);
    if (code != 0 && result == VIREO_OK) {
        error = (vireo_log_error_t){.stage = VIREO_LOG_STAGE_UNLOCK, .system_errno = code};
        result = VIREO_RESULT_INTERNAL;
    }
done:
    vireo_log_error_set(out_error, error.sink, error.stage, error.system_errno);
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_log_flush(vireo_log_t *logger, vireo_log_error_t *out_error) {
    int saved_errno = errno;
    vireo_log_error_t error = {.stage = VIREO_LOG_STAGE_VALIDATE};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (logger == NULL) {
        goto done;
    }
    int code = logger->ops.lock_mutex(&logger->mutex);
    if (code != 0) {
        error = (vireo_log_error_t){.stage = VIREO_LOG_STAGE_LOCK, .system_errno = code};
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }
    error = (vireo_log_error_t){0};
    if (logger->file_state == VIREO_LOG_HEALTHY && logger->ops.sync_file(logger->file_fd) != 0) {
        logger->file_state = VIREO_LOG_FAILED;
        logger->file_error =
            (vireo_log_error_t){VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_SYNC_FILE, errno};
    }
    if (logger->file_state == VIREO_LOG_FAILED) {
        error = logger->file_error;
    } else if (logger->stderr_state == VIREO_LOG_FAILED) {
        error = logger->stderr_error;
    }
    result = error.stage == VIREO_LOG_STAGE_NONE ? VIREO_OK : VIREO_RESULT_IO;
    code = logger->ops.unlock_mutex(&logger->mutex);
    if (code != 0 && result == VIREO_OK) {
        error = (vireo_log_error_t){.stage = VIREO_LOG_STAGE_UNLOCK, .system_errno = code};
        result = VIREO_RESULT_INTERNAL;
    }
done:
    vireo_log_error_set(out_error, error.sink, error.stage, error.system_errno);
    errno = saved_errno;
    return result;
}
