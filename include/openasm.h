#ifndef OPENASM_H
#define OPENASM_H 1

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <elf.h>

#define openasm_stringify1(x) #x
#define openasm_stringify(x) openasm_stringify1(x)
#define openasm_assertf(x, fmt, ...) do {       \
        if (!(x)) { \
            fprintf(stderr, "error: assertion failed at %s:%d: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__); \
            exit(1); \
        } \
    } while (0)
#define openasm_assert(x) openasm_assertf(x, "%s", openasm_stringify(x))

#define openasm_align_down(x, align) ((x) & ~((align) - 1))
#define openasm_align_up(x, align) openasm_align_down((x) + (align) - 1, align)

// jit procedure types
typedef void (*OpenasmProc)();
typedef int (*OpenasmFni)();
typedef long (*OpenasmFnl)();
typedef long long (*OpenasmFnll)();
typedef float (*OpenasmFnf)();
typedef double (*OpenasmFnd)();
typedef void *(*OpenasmFnvp)();

#define OPENASM_ELF_TYPE 0x3
#define OPENASM_ELF_CORE 3
#define OPENASM_ELF_DYN 2
#define OPENASM_ELF_EXEC 1
#define OPENASM_ELF_REL 0

struct OpenasmElf {
    Elf64_Ehdr ehdr;
    Elf64_Phdr phdrs[5];
    Elf64_Shdr shdrs[11];
    /* Elf64_Dyn dyns[0]; */
};

enum {
    OPENASM_SYM_FUNC_DEFAULT,
    OPENASM_SYM_FUNC_SHIFT_MASK,
    OPENASM_SYM_FUNC_SPLIT_SHIFT_MASK,
};

enum {
    OPENASM_BIND_LOCAL,
    OPENASM_BIND_GLOBAL,
    OPENASM_BIND_WEAK,
    OPENASM_BIND_PRIVATE,
};

struct OpenasmSymbol {
    const char *src_section;
    const char *addr_section;
    const char *sym;
    int binding;
    int defined;
    int bits;
    size_t offset;
    int func;
    size_t shift1;
    size_t shift2;
    uint64_t mask2;
    uint64_t mask1;
    uint64_t addr;
    uint64_t size;
    int rel;
};

struct OpenasmSymbolTable {
    size_t len;
    size_t cap;
    struct OpenasmSymbol *table;
};

#if defined(OPENASM_ARCH_AMD64)

#if defined(OPENASM_ARCH_AARCH64) || defined(OPENASM_ARCH_VOID)
#error "cannot include more than 1 architecture"
#endif /* OPENASM_ARCH_AARCH64 || .. */

#include "amd64.h"
#endif /* OPENASM_ARCH_AMD64 */

#if defined(OPENASM_ARCH_AARCH64)

#if defined(OPENASM_ARCH_AMD64) || defined(OPENASM_ARCH_VOID)
#error "cannot include more than 1 architecture"
#endif /* OPENASM_ARCH_AMD64 || .. */

#include "aarch64.h"
#endif /* OPENASM_ARCH_AARCH64 */

#if defined(OPENASM_ARCH_VOID)

#if defined(OPENASM_ARCH_AMD64) || defined(OPENASM_ARCH_AARCH64)
#error "cannot include more than 1 architecture"
#endif /* OPENASM_ARCH_AMD64 || .. */

#include "void.h"
#endif /* OPENASM_ARCH_VOID */

typedef void (*openasm_buffer_f)(OpenasmBuffer *buf);
typedef void (*openasm_del_buffer_f)(OpenasmBuffer *buf);
typedef int (*openasm_instf_f)(OpenasmBuffer *buf, const char *fmt, ...);
typedef int (*openasm_instfv_f)(OpenasmBuffer *buf, const char *fmt, va_list args);
typedef uint64_t (*openasm_data_f)(OpenasmBuffer *buf, size_t len, void *ptr);
typedef uint64_t (*openasm_res_f)(OpenasmBuffer *buf, size_t len);
typedef void (*openasm_section_f)(OpenasmBuffer *buf, const char *section);
    
typedef uint64_t (*openasm_addr_of_f)(OpenasmBuffer *buf, uint8_t *inst);
typedef uint64_t (*openasm_current_addr_f)(OpenasmBuffer *buf);
typedef bool (*openasm_symbol_f)(OpenasmBuffer *buf, const char *section, const char *sym, uint64_t addr);
typedef int (*openasm_link_f)(OpenasmBuffer *buf);
typedef int (*openasm_elfdump_f)(FILE *fileout, int flags, OpenasmBuffer *buf);

typedef OpenasmProc (*openasm_jit_proc_f)(OpenasmBuffer *buf);
typedef OpenasmFni (*openasm_jit_fni_f)(OpenasmBuffer *buf);
typedef OpenasmFnl (*openasm_jit_fnl_f)(OpenasmBuffer *buf);
typedef OpenasmFnll (*openasm_jit_fnll_f)(OpenasmBuffer *buf);
typedef OpenasmFnf (*openasm_jit_fnf_f)(OpenasmBuffer *buf);
typedef OpenasmFnd (*openasm_jit_fnd_f)(OpenasmBuffer *buf);
typedef OpenasmFnvp (*openasm_jit_fnvp_f)(OpenasmBuffer *buf);

#endif /* OPENASM_H */
