/*
 * PROJECT : VIREO
 * FILE    : buffer.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-01
 * BRIEF   : 此模块负责：
 * -- 有界连续存储、发布前回滚与唯一资源清理
 * -- 先受检后复制/提交的字节进度核心
 * IMPLEMENTATION :
 * -- 0 <= read_index <= write_index <= capacity；可读区间已初始化
 * -- append 不分配/compact，consume 全空时归零，不使用索引回绕
 * -- reserve/shrink 分配前不移动旧区，成功交接后才释放旧存储
 */
#include <vireo/base/buffer.h>
#include <vireo/base/checked.h>
#include "buffer_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct vireo_buffer {
    uint8_t *data;                     /**< 自有字节分配，可读区外不得公开。 */
    size_t capacity;                   /**< 当前字节容量，reserve 增长/shrink 回缩。 */
    size_t read_index;                 /**< 已消费前缀的末端。 */
    size_t write_index;                /**< 已初始化字节的末端。 */
    vireo_buffer_allocator_t allocator; /**< 配对释放操作，context 只借用。 */
};

/**
 * @brief 将对象内分配器签名适配到标准 malloc
 * @param[in] context 为接口一致性保留，不保存或访问；生产传 NULL。
 * @param[in] size 调用者已验证的正字节数，对象或候选存储的请求大小。
 * @return 独立且适当对齐的自有分配；调用者接管并用 deallocate_default 释放。
 * @retval NULL 无法取得请求内存，不取得资源。
 * @note 不初始化字节，不改变其他已发布资源；无共享可变分配设置。
 * @note errno 可能由 malloc 改变；create/replace_storage 负责保存恢复公共入口值。
 */
static void *allocate_default(void *context, size_t size) {
    (void)context;
    return malloc(size);
}

/**
 * @brief 配对释放标准分配器取得的内存，消费其所有权
 * @param[in] context 不保存或访问；生产传 NULL。
 * @param[in] memory 本适配器分配且未释放的自有内存；调用后不可再使用。
 * @note 无返回错误、不重入对象；调用者在释放前完成交接或保存清理操作表。
 * @note 不提供安全擦除；不依赖 free 是否保持 errno，公共调用者负责恢复。
 */
static void deallocate_default(void *context, void *memory) {
    (void)context;
    free(memory);
}

vireo_result_t vireo_buffer_create_with_allocator(size_t capacity,
    vireo_buffer_allocator_t const *allocator, vireo_buffer_t **out_buffer) {
    if (out_buffer == NULL || *out_buffer != NULL || allocator == NULL ||
        allocator->allocate == NULL || allocator->deallocate == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (capacity == 0 || capacity > VIREO_BUFFER_MAX_CAPACITY) {
        return VIREO_RESULT_RANGE;
    }

    int saved_errno = errno;
    vireo_buffer_t *candidate = allocator->allocate(allocator->context, sizeof(*candidate));
    if (candidate == NULL) {
        errno = saved_errno;
        return VIREO_RESULT_NO_MEMORY;
    }
    uint8_t *data = allocator->allocate(allocator->context, capacity);
    if (data == NULL) {
        allocator->deallocate(allocator->context, candidate);
        errno = saved_errno;
        return VIREO_RESULT_NO_MEMORY;
    }

    /* 未初始化容量不会通过 peek 暴露；对象只在两个分配均成功后发布。 */
    *candidate = (vireo_buffer_t){.data = data, .capacity = capacity,
        .read_index = 0, .write_index = 0, .allocator = *allocator};
    *out_buffer = candidate;
    errno = saved_errno;
    return VIREO_OK;
}

vireo_result_t vireo_buffer_create(size_t capacity, vireo_buffer_t **out_buffer) {
    static vireo_buffer_allocator_t const allocator = {
        .context = NULL, .allocate = allocate_default, .deallocate = deallocate_default,
    };
    return vireo_buffer_create_with_allocator(capacity, &allocator, out_buffer);
}

vireo_result_t vireo_buffer_destroy(vireo_buffer_t **buffer) {
    if (buffer == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (*buffer == NULL) {
        return VIREO_OK;
    }
    int saved_errno = errno;
    vireo_buffer_t *owned = *buffer;
    /* 释放对象前先保存配对操作，避免再读取已经释放的对象字段。 */
    vireo_buffer_allocator_t allocator = owned->allocator;
    allocator.deallocate(allocator.context, owned->data);
    allocator.deallocate(allocator.context, owned);
    *buffer = NULL;
    errno = saved_errno;
    return VIREO_OK;
}

vireo_result_t vireo_buffer_inspect(vireo_buffer_t const *buffer,
                                    vireo_buffer_info_t *out_info) {
    if (buffer == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    *out_info = (vireo_buffer_info_t){.capacity = buffer->capacity,
        .readable_size = buffer->write_index - buffer->read_index,
        .tail_space = buffer->capacity - buffer->write_index};
    return VIREO_OK;
}

vireo_result_t vireo_buffer_append(vireo_buffer_t *buffer, uint8_t const *data, size_t size) {
    if (buffer == NULL || (size != 0 && data == NULL)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t next_write = 0;
    vireo_result_t result = vireo_checked_size_add(buffer->write_index, size, &next_write);
    if (result != VIREO_OK) {
        return result;
    }
    result = vireo_checked_size_range(buffer->write_index, size, buffer->capacity);
    if (result != VIREO_OK) {
        return result;
    }
    if (size != 0) {
        memcpy(buffer->data + buffer->write_index, data, size);
    }
    buffer->write_index = next_write;
    return VIREO_OK;
}

vireo_result_t vireo_buffer_peek(vireo_buffer_t const *buffer,
                                 uint8_t const **out_data, size_t *out_size) {
    if (buffer == NULL || out_data == NULL || out_size == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t size = buffer->write_index - buffer->read_index;
    *out_data = size == 0 ? NULL : buffer->data + buffer->read_index;
    *out_size = size;
    return VIREO_OK;
}

vireo_result_t vireo_buffer_consume(vireo_buffer_t *buffer, size_t size) {
    if (buffer == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    /* checked range 成功已证明 read_index+size <= write_index，才执行加法。 */
    vireo_result_t result = vireo_checked_size_range(buffer->read_index, size,
                                                     buffer->write_index);
    if (result != VIREO_OK) {
        return result;
    }
    buffer->read_index += size;
    if (buffer->read_index == buffer->write_index) {
        buffer->read_index = 0;
        buffer->write_index = 0;
    }
    return VIREO_OK;
}

vireo_result_t vireo_buffer_compact(vireo_buffer_t *buffer) {
    if (buffer == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t readable = buffer->write_index - buffer->read_index;
    /* 不变量证明源 [r,w) 和目的 [0,w-r) 均在容量内；两区可重叠。 */
    if (readable != 0 && buffer->read_index != 0) {
        memmove(buffer->data, buffer->data + buffer->read_index, readable);
    }
    buffer->read_index = 0;
    buffer->write_index = readable;
    return VIREO_OK;
}

/**
 * @brief 在容量计划已验证后执行完整存储交接，供 reserve/shrink 共享
 * @param[in,out] buffer 非空存活且独占的对象，allocator 配对有效且不可重入。
 * @param[in] capacity 1..硬上限且不少于未读长度，由调用者完成边界/受检计算。
 * @retval VIREO_OK 对象接管独立新区，r=0/w=未读长度，旧区已配对释放。
 * @retval VIREO_RESULT_NO_MEMORY 分配失败，全部旧区/字段/view 保持。
 * @note candidate 在提交前局部拥有；提交后由 buffer 拥有。只复制非空未读区；
 *     不先整理旧区。对象/allocator 不变，成功结束 view，所有路径保持 errno。
 * @note 仅内部已验证调用；释放不可报告失败，不执行 I/O 或日志。
 */
static vireo_result_t replace_storage(vireo_buffer_t *buffer, size_t capacity) {
    size_t readable = buffer->write_index - buffer->read_index;
    int saved_errno = errno;
    uint8_t *candidate = buffer->allocator.allocate(buffer->allocator.context, capacity);
    if (candidate == NULL) {
        errno = saved_errno;
        return VIREO_RESULT_NO_MEMORY;
    }
    if (readable != 0) {
        memcpy(candidate, buffer->data + buffer->read_index, readable);
    }
    uint8_t *old_data = buffer->data;
    buffer->data = candidate;
    buffer->capacity = capacity;
    buffer->read_index = 0;
    buffer->write_index = readable;
    buffer->allocator.deallocate(buffer->allocator.context, old_data);
    errno = saved_errno;
    return VIREO_OK;
}

vireo_result_t vireo_buffer_reserve(vireo_buffer_t *buffer, size_t min_tail_space) {
    if (buffer == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t readable = buffer->write_index - buffer->read_index;
    size_t required = 0;
    vireo_result_t result = vireo_checked_size_add(readable, min_tail_space, &required);
    if (result != VIREO_OK) {
        return result;
    }
    if (required > VIREO_BUFFER_MAX_CAPACITY) {
        return VIREO_RESULT_RANGE;
    }
    if (min_tail_space <= buffer->capacity - buffer->write_index) {
        return VIREO_OK;
    }
    if (required <= buffer->capacity) {
        return vireo_buffer_compact(buffer);
    }

    size_t next_capacity = VIREO_BUFFER_MAX_CAPACITY;
    if (buffer->capacity <= VIREO_BUFFER_MAX_CAPACITY / 2) {
        result = vireo_checked_size_mul(buffer->capacity, 2, &next_capacity);
        if (result != VIREO_OK) {
            return result;
        }
    }
    if (next_capacity < required) {
        next_capacity = required;
    }

    return replace_storage(buffer, next_capacity);
}

vireo_result_t vireo_buffer_shrink(vireo_buffer_t *buffer, size_t capacity) {
    if (buffer == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t readable = buffer->write_index - buffer->read_index;
    if (capacity == 0 || capacity > buffer->capacity || capacity < readable) {
        return VIREO_RESULT_RANGE;
    }
    if (capacity == buffer->capacity) {
        return VIREO_OK;
    }
    return replace_storage(buffer, capacity);
}
