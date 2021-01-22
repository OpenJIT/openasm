#include <stdarg.h>
#include "include/openasm.h"

int openasm_instf(OpenasmBuffer *buf, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    const char *input = fmt;
    
    while (*fmt == ' ' || *fmt == '\t') ++fmt;
    
    const char *ptr = fmt;
    char *mnemonic = malloc(strlen(fmt) + 1);
    OpenasmOperand operands[8] = {0};
    int ext[3] = {0};
    size_t arity = 0;
    size_t regs = 0;

    while (*fmt && *fmt != ' ') ++fmt;

    size_t len = fmt - ptr;
    strncpy(mnemonic, ptr, len);
    mnemonic[len] = 0;
    
    while (*fmt == ' ' || *fmt == '\t') ++fmt;
    ptr = fmt;

    for (size_t i = 0; i < 8; i++) {
        while (*fmt) {
            if (*fmt == ' ' || *fmt == '\t') {
                ++fmt;
                continue;
            }
            if (*fmt == '%') {
                ++fmt;
                switch (*fmt) {
                case '*': {
                    operands[arity++] = va_arg(args, struct OpenasmOperand);
                } break;
                case 'r': {
                    const char *target = va_arg(args, char *);
                    uint32_t tag = -1;
                    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
                        if (strcmp(target, reg->key) == 0) {
                            ext[regs] = reg->ext;
                            switch (reg->bits) {
                            case 8:
                                tag = OPENASM_OP_REG8;
                                break;
                            case 16:
                                tag = OPENASM_OP_REG16;
                                break;
                            case 32:
                                tag = OPENASM_OP_REG32;
                                break;
                            case 64:
                                tag = OPENASM_OP_REG64;
                                break;
                            default:
                                /* unreachable */
                                break;
                            }
                        }
                    }
                    operands[arity].tag = tag;
                    if (regs == 0 && ext[regs]) {
                        operands[0].aux |= OPENASM_AUX_REXR;
                    } else if (regs == 1 && ext[regs]) {
                        operands[0].aux |= OPENASM_AUX_REXB;
                    } else {
                        operands[0].aux |= OPENASM_AUX_NONE;
                    }
                    operands[arity++].reg = target;
                    ++regs;
                } break;
                case 'i': {
                    uint64_t imm = va_arg(args, uint64_t);
                    operands[arity].imm = imm;
                    if (fmt[1] == '8') {
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_IMM8;
                    } else if (fmt[1] == '1') {
                        ++fmt;
                        if (fmt[1] != '6') {
                            fprintf(stderr, "error: invalid immediate bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_IMM16;
                    } else if (fmt[1] == '3') {
                        ++fmt;
                        if (fmt[1] != '2') {
                            fprintf(stderr, "error: invalid immediate bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_IMM32;
                    } else if (fmt[1] == '6') {
                        ++fmt;
                        if (fmt[1] != '4') {
                            fprintf(stderr, "error: invalid immediate bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_IMM64;
                    } else if (fmt[1] >= '0' && fmt[1] <= '9') {
                        fprintf(stderr, "error: invalid immediate bitwidth\n");
                        return 1;
                    } else {
                        fprintf(stderr, "warning: unspecified immediate bitwidth, defaulting to 32\n");
                        operands[arity++].tag = OPENASM_OP_IMM32;
                    }
                } break;
                case 'm': {
                    struct OpenasmMemory mem = va_arg(args, struct OpenasmMemory);
                    operands[arity++].mem = mem;
                    if (fmt[1] == '8') {
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_MEMORY8;
                    } else if (fmt[1] == '1') {
                        ++fmt;
                        if (fmt[1] != '6') {
                            fprintf(stderr, "error: invalid immediate bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_MEMORY16;
                    } else if (fmt[1] == '3') {
                        ++fmt;
                        if (fmt[1] != '2') {
                            fprintf(stderr, "error: invalid immediate bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_MEMORY32;
                    } else if (fmt[1] == '6') {
                        ++fmt;
                        if (fmt[1] != '4') {
                            fprintf(stderr, "error: invalid immediate bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_MEMORY64;
                    } else if (fmt[1] >= '0' && fmt[1] <= '9') {
                        fprintf(stderr, "error: invalid immediate bitwidth\n");
                        return 1;
                    } else {
                        fprintf(stderr, "warning: unspecified immediate bitwidth, defaulting to 32\n");
                        operands[arity++].tag = OPENASM_OP_MEMORY32;
                    }
                } break;
                case 's': {
                    if (buf->symtable.len == buf->symtable.cap) {
                        buf->symtable.cap *= 2;
                        buf->symtable.table = realloc(buf->symtable.table, buf->symtable.cap * sizeof(struct OpenasmSymbol));
                    }
                    
                    const char *src_section = buf->sections[buf->section].name;
                    const char *addr_section = va_arg(args, char *);
                    const char *symbol = va_arg(args, char *);
                    buf->sym = 1;
                    buf->symtable.table[buf->symtable.len].src_section = src_section;
                    buf->symtable.table[buf->symtable.len].addr_section = addr_section;
                    buf->symtable.table[buf->symtable.len].sym = symbol;
                    buf->symtable.table[buf->symtable.len].defined = 0;
                    buf->symtable.table[buf->symtable.len].bits = 0;
                    buf->symtable.table[buf->symtable.len].offset = 0;
                    buf->symtable.table[buf->symtable.len].addr = 0;
                    buf->symtable.table[buf->symtable.len++].rel = 0;
                    operands[arity].imm = 0;
                    if (fmt[1] == '8') {
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_IMM8;
                    } else if (fmt[1] == '1') {
                        ++fmt;
                        if (fmt[1] != '6') {
                            fprintf(stderr, "error: invalid symbol bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_IMM16;
                    } else if (fmt[1] == '3') {
                        ++fmt;
                        if (fmt[1] != '2') {
                            fprintf(stderr, "error: invalid symbol bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_IMM32;
                    } else if (fmt[1] == '6') {
                        ++fmt;
                        if (fmt[1] != '4') {
                            fprintf(stderr, "error: invalid symbol bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[arity++].tag = OPENASM_OP_IMM64;
                    } else if (fmt[1] >= '0' && fmt[1] <= '9') {
                        fprintf(stderr, "error: invalid symbol bitwidth\n");
                        return 1;
                    } else {
                        fprintf(stderr, "warning: unspecified symbol bitwidth, defaulting to 64\n");
                        operands[arity++].tag = OPENASM_OP_IMM64;
                    }
                } break;
                case 'p': {
                    if (buf->symtable.len == buf->symtable.cap) {
                        buf->symtable.cap *= 2;
                        buf->symtable.table = realloc(buf->symtable.table, buf->symtable.cap * sizeof(struct OpenasmSymbol));
                    }
                    
                    const char *src_section = buf->sections[buf->section].name;
                    const char *addr_section = va_arg(args, char *);
                    const char *symbol = va_arg(args, char *);
                    buf->sym = 1;
                    buf->symtable.table[buf->symtable.len].src_section = src_section;
                    buf->symtable.table[buf->symtable.len].addr_section = addr_section;
                    buf->symtable.table[buf->symtable.len].sym = symbol;
                    buf->symtable.table[buf->symtable.len].defined = 0;
                    buf->symtable.table[buf->symtable.len].bits = 0;
                    buf->symtable.table[buf->symtable.len].offset = 0;
                    buf->symtable.table[buf->symtable.len].addr = 0;
                    buf->symtable.table[buf->symtable.len++].rel = 1;
                    operands[arity].imm = 0;
                    operands[arity++].tag = OPENASM_OP_IMM32;
                } break;
                default: {
                    fprintf(stderr, "error: invalid `openasm_instf` parameter: '%c'\n", *fmt);
                    return 1;
                } break;
                }
                break;
            } else {
                fprintf(stderr, "error: invalid `openasm_instf` format: \"%s\"\n", input);
                return 1;
            }
        }
        while (*fmt && *fmt != ',') ++fmt;
        if (!*fmt) {
            break;
        } else if (*fmt == ',') {
            ++fmt;
        }
    }

    va_end(args);

    int tag;
    if (arity == 0) {
        tag = 0;
    } else if (arity == 1) {
        tag = OPENASM_CONS1(operands[0].tag);
    } else {
        tag = OPENASM_CONS2(operands[1].tag, operands[0].tag);
    }
    for (struct OpenasmEntry *entry = openasm_inst; entry->mnem; entry++) {
        if (strcmp(mnemonic, entry->mnem) == 0) {
            int (*fn)(OpenasmBuffer *, OpenasmOperand *) = entry->inst_table[tag];
            if (!fn) {
                fprintf(stderr, "error: invalid combination of opcode and operands: \"%s\"\n", mnemonic);
                return 1;
            }
            return fn(buf, operands);
        }
    }
    
    fprintf(stderr, "error: unimplemented `openasm_instf` mnemonic: \"%s\"\n", mnemonic);
    return 1;
}
