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
    Elf64_Shdr shdrs[6];
    /* Elf64_Dyn dyns[0]; */
};

struct OpenasmSymbol {
    const char *src_section;
    const char *addr_section;
    const char *sym;
    int defined;
    int bits;
    size_t offset;
    size_t shift;
    uint64_t mask;
    uint64_t addr;
    int rel;
};

struct OpenasmSymbolTable {
    size_t len;
    size_t cap;
    struct OpenasmSymbol *table;
};

#if defined(OPENASM_ARCH_AMD64)

#if defined(OPENASM_ARCH_AARCH64)
#error "cannot include more than 1 architecture"
#endif /* OPENASM_ARCH_AARCH64) */

#include "amd64.h"
#endif /* OPENASM_ARCH_AMD64 */

#if defined(OPENASM_ARCH_AARCH64)

#if defined(OPENASM_ARCH_AMD64)
#error "cannot include more than 1 architecture"
#endif /* OPENASM_ARCH_AMD64) */

#include "aarch64.h"
#endif /* OPENASM_ARCH_AARCH64 */

#endif /* OPENASM_H */
