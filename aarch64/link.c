#include <sys/stat.h>
#define OPENASM_ARCH_AARCH64 1
#include "include/openasm.h"

#define DEFAULT_BUFFER_CAP ((size_t) 16384)

void openasm_section(OpenasmBuffer *buf, const char *section) {
    for (size_t i = 0; i < buf->len; i++) {
        if (strcmp(buf->sections[i].name, section) == 0) {
            buf->section = i;
            return;
        }
    }

    if (buf->len == buf->cap) {
        buf->cap *= 2;
        buf->sections = realloc(buf->sections, buf->cap * sizeof(struct OpenasmSection));
    }

    size_t cap = DEFAULT_BUFFER_CAP / sizeof(uint32_t);
    buf->sections[buf->len].name = section;
    buf->sections[buf->len].cap = cap;
    buf->sections[buf->len].len = 0;
    buf->sections[buf->len].buffer = malloc(cap * sizeof(uint32_t));
    buf->section = buf->len++;
}

uint64_t openasm_addr_of(OpenasmBuffer *buf, uint32_t *inst) {
    return (uint64_t) inst - (uint64_t) buf->sections[buf->section].buffer;
}

uint64_t openasm_current_addr(OpenasmBuffer *buf) {
    return buf->sections[buf->section].len * sizeof(uint32_t);
}

bool openasm_symbol(OpenasmBuffer *buf, const char *section, const char *sym, uint64_t addr) {
    bool used = 0;
    for (size_t i = 0; i < buf->symtable.len; i++) {
        if (strcmp(buf->symtable.table[i].addr_section, section) == 0
            && strcmp(buf->symtable.table[i].sym, sym) == 0) {
            used = 1;
	    // TODO: set the shift and mask shits
            buf->symtable.table[i].addr = addr;
            buf->symtable.table[i].defined = 1;
        }
    }
    return used;
}

int openasm_link(OpenasmBuffer *buf) {
    int status = 0;
    for (size_t i = 0; i < buf->symtable.len; i++) {
        if (!buf->symtable.table[i].defined) {
            status = 1;
            fprintf(stderr, "warning: undefined symbol: %s\n", buf->symtable.table[i].sym);
            continue;
        }
        openasm_section(buf, buf->symtable.table[i].src_section);
        int rel = buf->symtable.table[i].rel;
        size_t size = buf->symtable.table[i].bits >> 3;
        uint64_t offset = buf->symtable.table[i].offset / sizeof(uint32_t);
        uint32_t addr = buf->symtable.table[i].addr;
        uint32_t mask = buf->symtable.table[i].mask;
        uint32_t shift = buf->symtable.table[i].shift;
        if (rel) {
            addr = addr - (offset + size);
        }
	addr = (addr & mask) << shift;
        uint32_t *ptr = buf->sections[buf->section].buffer + offset;
	*ptr |= addr;
    }
    return status;
}

int openasm_rawdump(FILE *fileout, OpenasmBuffer *buf) {
    openasm_section(buf, "text");
    size_t text_size = buf->sections[buf->section].len;
    void *text_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "data");
    size_t data_size = buf->sections[buf->section].len;
    void *data_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "rodata");
    size_t rodata_size = buf->sections[buf->section].len;
    void *rodata_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "bss");
    size_t bss_size = buf->sections[buf->section].len;
    void *bss_ptr = buf->sections[buf->section].buffer;
    
    fwrite(text_ptr, sizeof(uint32_t), text_size, fileout);
    fwrite(rodata_ptr, sizeof(uint32_t), rodata_size, fileout);
    fwrite(data_ptr, sizeof(uint32_t), data_size, fileout);
    fwrite(bss_ptr, sizeof(uint32_t), bss_size, fileout);

    /* fchmod(fileno(fileout), 0755); */

    return 0;
}
