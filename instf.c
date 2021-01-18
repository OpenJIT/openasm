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

    while (*fmt && *fmt != ' ') ++fmt;

    strncpy(mnemonic, ptr, fmt - ptr);
    
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
                    operands[i] = va_arg(args, struct OpenasmOperand);
                } break;
                case 'r': {
                    const char *target = va_arg(args, char *);
                    uint32_t tag = -1;
                    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
                        if (strcmp(target, reg->key) == 0) {
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
                    operands[i].tag = tag;
                    operands[i].reg = target;
                } break;
                case 'i': {
                    uint64_t imm = va_arg(args, uint64_t);
                    operands[i].imm = imm;
                    if (fmt[1] == '1') {
                        ++fmt;
                        if (fmt[1] != '6') {
                            fprintf(stderr, "error: invalid immediate bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[i].tag = OPENASM_OP_IMM16;
                    } else if (fmt[1] == '3') {
                        ++fmt;
                        if (fmt[1] != '2') {
                            fprintf(stderr, "error: invalid immediate bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[i].tag = OPENASM_OP_IMM32;
                    } else if (fmt[1] == '6') {
                        ++fmt;
                        if (fmt[1] != '4') {
                            fprintf(stderr, "error: invalid immediate bitwidth\n");
                            return 1;
                        }
                        ++fmt;
                        operands[i].tag = OPENASM_OP_IMM64;
                    } else if (fmt[1] >= '0' && fmt[1] <= '9') {
                        fprintf(stderr, "error: invalid immediate bitwidth\n");
                        return 1;
                    } else {
                        fprintf(stderr, "warning: unspecified immediate bitwidth, defaulting to 32\n");
                        operands[i].tag = OPENASM_OP_IMM32;
                    }
                } break;
                case 'm': {
                    struct OpenasmMemory mem = va_arg(args, struct OpenasmMemory);
                    operands[i].tag = OPENASM_OP_MEMORY;
                    operands[i].mem = mem;
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

    for (struct OpenasmEntry *entry = openasm_inst; entry->mnem; entry++) {
        if (strcmp(mnemonic, entry->mnem) == 0) {
            int tag = OPENASM_CONS2(operands[1].tag, operands[0].tag);
            return entry->inst_table[tag](buf, operands);
        }
    }
    
    fprintf(stderr, "error: unimplemented `openasm_instf` mnemonic: \"%s\"\n", mnemonic);
    return 1;
}
