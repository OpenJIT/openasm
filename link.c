#include "include/openasm.h"

bool openasm_symbol(OpenasmBuffer *buf, const char *sym, uint64_t addr) {
    bool used = 0;
    for (size_t i = 0; i < buf->symtable.len; i++) {
        if (strcmp(buf->symtable.table[i].sym, sym) == 0) {
            used = 1;
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
        uint64_t offset = buf->symtable.table[i].offset;
        uint64_t addr = buf->symtable.table[i].addr;
        uint8_t *ptr = buf->buffer + offset;
        switch (buf->symtable.table[i].bits) {
        case 8:
            *ptr = addr & 0xff;
            break;
        case 16:
            *((uint16_t *) ptr) = addr & 0xffff;
            break;
        case 32:
            *((uint32_t *) ptr) = addr & 0xffffffff;
            break;
        case 64:
            *((uint64_t *) ptr) = addr;
            break;
        default:
            /* unreachable */
            break;
        }
    }
    return status;
}
