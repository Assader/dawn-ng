#include <stdint.h>
#include <string.h>

#include "dawn_log.h"
#include "memory_utils.h"

enum {
    DAWN_MEM_FILENAME_LEN = 20
};

struct mem_list {
    struct mem_list *next_mem;
    int line;
    char file[DAWN_MEM_FILENAME_LEN];
    char type;
    size_t size;
    void *ptr;
    uint64_t ref;
};

static struct mem_list *mem_base;
static uint64_t alloc_ref;

void *dawn_memory_alloc(enum dawn_memop type, const char *file, int line, size_t nmemb, size_t size, void *ptr)
{
    void *ret = NULL;

    switch (type) {
    case DAWN_MALLOC:
        ret = malloc(size);
        break;
    case DAWN_REALLOC:
        ret = realloc(ptr, size);
        if (ret != NULL) {
            dawn_memory_unregister(DAWN_REALLOC, file, line, ptr);
        }
        break;
    case DAWN_CALLOC:
        ret = calloc(nmemb, size);
        size *= nmemb; /* May not be correct allowing for padding but gives a sense of scale */
        break;
    default:
        break;
    }

    if (ret != NULL) {
        dawn_memory_register(type, file, line, size, ret);
    }

    return ret;
}

void *dawn_memory_register(enum dawn_memop type, const char *file, int line, size_t size, void *ptr)
{
    struct mem_list *this_log = NULL;
    char type_c = '?';

    /* Ignore over enthusiastic effort to register a failed allocation */
    if (ptr == NULL) {
        goto exit;
    }

    switch (type) {
    case DAWN_MALLOC:
        type_c = 'M';
        break;
    case DAWN_REALLOC:
        type_c = 'R';
        break;
    case DAWN_CALLOC:
        type_c = 'C';
        break;
    case DAWN_MEMREG:
        type_c = 'X';
        break;
    default:
        DAWN_LOG_WARNING("Unexpected memory operation tag");
        break;
    }

    /* Insert to linked list with ascending memory reference */
    struct mem_list **ipos = &mem_base;
    while (*ipos != NULL && (*ipos)->ptr < ptr) {
        ipos = &((*ipos)->next_mem);
    }

    if (*ipos != NULL && (*ipos)->ptr == ptr) {
        DAWN_LOG_WARNING("Attempting to register memory already registered (%c@%s:%d)...\n", type_c, file, line);
    }
    else {
        this_log = malloc(sizeof (struct mem_list));
        if (this_log == NULL) {
            DAWN_LOG_WARNING("Oh the irony! malloc() failed in dawn_memory_register()");
            goto exit;
        }

        this_log->next_mem = *ipos;
        *ipos = this_log;

        /* Just use filename - no path */
        file = strrchr(file, '/');

        if (file != NULL) {
            strncpy(this_log->file, file + 1, DAWN_MEM_FILENAME_LEN);
        }
        else {
            strncpy(this_log->file, "?? UNKNOWN ??", DAWN_MEM_FILENAME_LEN);
        }

        this_log->type = type_c;
        this_log->line = line;
        this_log->ptr = ptr;
        this_log->size = size;
        this_log->ref = alloc_ref++;
    }

exit:
    return ptr;
}

void dawn_memory_unregister(enum dawn_memop type, const char *file, int line, void *ptr)
{
    struct mem_list **mem = &mem_base;
    char type_c = '?';

    switch (type) {
    case DAWN_FREE:
        type_c = 'F';
        break;
    case DAWN_MEMUNREG:
        type_c = 'U';
        break;
    case DAWN_REALLOC:
        type_c = 'R';
        break;
    default:
        DAWN_LOG_WARNING("Unexpected memory operation tag");
        break;
    }

    while (*mem != NULL && (*mem)->ptr < ptr) {
        mem = &((*mem)->next_mem);
    }

    if (*mem != NULL && (*mem)->ptr == ptr) {
        struct mem_list *tmp = *mem;
        *mem = tmp->next_mem;
        free(tmp);
    }
    else {
        DAWN_LOG_WARNING("Releasing (%c) memory we hadn't registered (%s:%d)...", type_c, file, line);
    }

    return;
}

void dawn_memory_free(enum dawn_memop type, const char *file, int line, void *ptr)
{
    dawn_memory_unregister(type, file, line, ptr);
    free(ptr);
}

void dawn_memory_audit(void)
{
    size_t total = 0;

    DAWN_LOG_DEBUG("Listing currently recorded allocations...");
    for (struct mem_list *mem = mem_base; mem != NULL; mem = mem->next_mem) {
        DAWN_LOG_DEBUG(" - %8ull - %c@%s:d %zu\n", mem->ref, mem->type, mem->file, mem->line, mem->size);
        total += mem->size;
    }

    char *suffix = "bytes";
    if (total > 128 * 1024) {
        total /= 1024;
        suffix = "kbytes";
    }

    DAWN_LOG_DEBUG("End of list: %zu %s", total, suffix);
}
