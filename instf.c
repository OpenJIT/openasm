#include <stdarg.h>
#include "include/openasm.h"

static size_t openasm_opsize(int tag) {
    switch (tag) {
    case OPENASM_OP_AL:
    case OPENASM_OP_REG8:
    case OPENASM_OP_IMM8:
    case OPENASM_OP_MEMORY8:
        return 8;
    case OPENASM_OP_AX:
    case OPENASM_OP_REG16:
    case OPENASM_OP_IMM16:
    case OPENASM_OP_MEMORY16:
        return 16;
    case OPENASM_OP_EAX:
    case OPENASM_OP_REG32:
    case OPENASM_OP_IMM32:
    case OPENASM_OP_MEMORY32:
        return 32;
    case OPENASM_OP_RAX:
    case OPENASM_OP_REG64:
    case OPENASM_OP_IMM64:
    case OPENASM_OP_MEMORY64:
        return 64;
    default:
        abort();
    }
}

static const char *openasm_match_reg(const char *op, size_t size) {
    if (op[0] == 'r') {
        ++op;
    } else if (op[0] == 'e') {
        ++op;
    }

    switch (op[0]) {
    case 'a':
        switch (size) {
        case 8:
            return "al";
        case 16:
            return "ax";
        case 32:
            return "eax";
        case 64:
            return "rax";
        default:
            abort();
        }
    case 'c':
        switch (size) {
        case 8:
            return "cl";
        case 16:
            return "cx";
        case 32:
            return "ecx";
        case 64:
            return "rcx";
        default:
            abort();
        }
    case 'd':
        switch (op[1]) {
        case 'i':
            switch (size) {
            case 8:
                return "dil";
            case 16:
                return "di";
            case 32:
                return "edi";
            case 64:
                return "rdi";
            default:
                abort();
            }
        default:
            switch (size) {
            case 8:
                return "dl";
            case 16:
                return "dx";
            case 32:
                return "edx";
            case 64:
                return "rdx";
            default:
                abort();
            }
        }
    case 'b':
        switch (op[1]) {
        case 'p':
            switch (size) {
            case 8:
                return "bpl";
            case 16:
                return "bp";
            case 32:
                return "ebp";
            case 64:
                return "rbp";
            default:
                abort();
            }
        default:
            switch (size) {
            case 8:
                return "bl";
            case 16:
                return "bx";
            case 32:
                return "ebx";
            case 64:
                return "rbx";
            default:
                abort();
            }
        }
    case 's':
        switch (op[1]) {
        case 'p':
            switch (size) {
            case 8:
                return "spl";
            case 16:
                return "sp";
            case 32:
                return "esp";
            case 64:
                return "rsp";
            default:
                abort();
            }
        case 'i':
            switch (size) {
            case 8:
                return "sil";
            case 16:
                return "si";
            case 32:
                return "esi";
            case 64:
                return "rsi";
            default:
                abort();
            }
        default:
            abort();
        }
    case '8':
        switch (size) {
        case 8:
            return "r8b";
        case 16:
            return "r8w";
        case 32:
            return "r8d";
        case 64:
            return "r8";
        default:
            abort();
        }
    case '9':
        switch (size) {
        case 8:
            return "r9b";
        case 16:
            return "r9w";
        case 32:
            return "r9d";
        case 64:
            return "r9";
        default:
            abort();
        }
    case '1':
        switch (op[1]) {
        case '0':
            switch (size) {
            case 8:
                return "r10b";
            case 16:
                return "r10w";
            case 32:
                return "r10d";
            case 64:
                return "r10";
            default:
                abort();
            }
        case '1':
            switch (size) {
            case 8:
                return "r11b";
            case 16:
                return "r11w";
            case 32:
                return "r11d";
            case 64:
                return "r11";
            default:
                abort();
            }
        case '2':
            switch (size) {
            case 8:
                return "r12b";
            case 16:
                return "r12w";
            case 32:
                return "r12d";
            case 64:
                return "r12";
            default:
                abort();
            }
        case '3':
            switch (size) {
            case 8:
                return "r13b";
            case 16:
                return "r13w";
            case 32:
                return "r13d";
            case 64:
                return "r13";
            default:
                abort();
            }
        case '4':
            switch (size) {
            case 8:
                return "r14b";
            case 16:
                return "r14w";
            case 32:
                return "r14d";
            case 64:
                return "r14";
            default:
                abort();
            }
        case '5':
            switch (size) {
            case 8:
                return "r15b";
            case 16:
                return "r15w";
            case 32:
                return "r15d";
            case 64:
                return "r15";
            default:
                abort();
            }
        default:
            abort();
        }
    default:
        abort();
    }
}

static int openasm_match_opsize(OpenasmOperand *op, int tag) {
    switch (openasm_opsize(tag)) {
    case 8:
        switch (op->tag) {
        case OPENASM_OP_REG8:
        case OPENASM_OP_REG16:
        case OPENASM_OP_REG32:
        case OPENASM_OP_REG64:
            op->reg = openasm_match_reg(op->reg, 8);
            return OPENASM_OP_REG8;
        case OPENASM_OP_IMM8:
        case OPENASM_OP_IMM16:
        case OPENASM_OP_IMM32:
        case OPENASM_OP_IMM64:
            return OPENASM_OP_IMM8;
        case OPENASM_OP_MEMORY8:
        case OPENASM_OP_MEMORY16:
        case OPENASM_OP_MEMORY32:
        case OPENASM_OP_MEMORY64:
            if (op->mem.base) op->mem.base = openasm_match_reg(op->mem.base, 8);
            if (op->mem.index) op->mem.index = openasm_match_reg(op->mem.index, 8);
            return OPENASM_OP_MEMORY8;
        default:
            abort();
        }
    case 16:
        switch (op->tag) {
        case OPENASM_OP_REG8:
        case OPENASM_OP_REG16:
        case OPENASM_OP_REG32:
        case OPENASM_OP_REG64:
            op->reg = openasm_match_reg(op->reg, 16);
            return OPENASM_OP_REG16;
        case OPENASM_OP_IMM8:
        case OPENASM_OP_IMM16:
        case OPENASM_OP_IMM32:
        case OPENASM_OP_IMM64:
            return OPENASM_OP_IMM16;
        case OPENASM_OP_MEMORY8:
        case OPENASM_OP_MEMORY16:
        case OPENASM_OP_MEMORY32:
        case OPENASM_OP_MEMORY64:
            if (op->mem.base) op->mem.base = openasm_match_reg(op->mem.base, 16);
            if (op->mem.index) op->mem.index = openasm_match_reg(op->mem.index, 16);
            return OPENASM_OP_MEMORY16;
        default:
            abort();
        }
    case 32:
        switch (op->tag) {
        case OPENASM_OP_REG8:
        case OPENASM_OP_REG16:
        case OPENASM_OP_REG32:
        case OPENASM_OP_REG64:
            op->reg = openasm_match_reg(op->reg, 32);
            return OPENASM_OP_REG32;
        case OPENASM_OP_IMM8:
        case OPENASM_OP_IMM16:
        case OPENASM_OP_IMM32:
        case OPENASM_OP_IMM64:
            op->reg = openasm_match_reg(op->reg, 64);
            return OPENASM_OP_IMM32;
        case OPENASM_OP_MEMORY8:
        case OPENASM_OP_MEMORY16:
        case OPENASM_OP_MEMORY32:
        case OPENASM_OP_MEMORY64:
            if (op->mem.base) op->mem.base = openasm_match_reg(op->mem.base, 32);
            if (op->mem.index) op->mem.index = openasm_match_reg(op->mem.index, 32);
            return OPENASM_OP_MEMORY32;
        default:
            abort();
        }
    case 64:
        switch (op->tag) {
        case OPENASM_OP_REG8:
        case OPENASM_OP_REG16:
        case OPENASM_OP_REG32:
        case OPENASM_OP_REG64:
            return OPENASM_OP_REG64;
        case OPENASM_OP_IMM8:
        case OPENASM_OP_IMM16:
        case OPENASM_OP_IMM32:
        case OPENASM_OP_IMM64:
            return OPENASM_OP_IMM64;
        case OPENASM_OP_MEMORY8:
        case OPENASM_OP_MEMORY16:
        case OPENASM_OP_MEMORY32:
        case OPENASM_OP_MEMORY64:
            if (op->mem.base) op->mem.base = openasm_match_reg(op->mem.base, 64);
            if (op->mem.index) op->mem.index = openasm_match_reg(op->mem.index, 64);
            return OPENASM_OP_MEMORY64;
        default:
            abort();
        }
    default:
        abort();
    }
}

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
                    int bext = 0;
                    int iext = 0;
                    OpenasmOperand op = va_arg(args, struct OpenasmOperand);
                    if (op.tag == OPENASM_OP_REG8
                        || op.tag == OPENASM_OP_REG16
                        || op.tag == OPENASM_OP_REG32
                        || op.tag == OPENASM_OP_REG64) {
                        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
                            if (strcmp(op.reg, reg->key) == 0) {
                                switch (reg->bits) {
                                case 8:
                                    ext[regs] = reg->ext;
                                    break;
                                case 16:
                                    ext[regs] = reg->ext;
                                    break;
                                case 32:
                                    ext[regs] = reg->ext;
                                    break;
                                case 64:
                                    ext[regs] = reg->ext;
                                    break;
                                default:
                                    /* unreachable */
                                    break;
                                }
                                break;
                            }
                        }
                    } else if (op.tag == OPENASM_OP_MEMORY8
                        || op.tag == OPENASM_OP_MEMORY16
                        || op.tag == OPENASM_OP_MEMORY32
                        || op.tag == OPENASM_OP_MEMORY64) {
                        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
                            if (strcmp(op.mem.base, reg->key) == 0) {
                                switch (reg->bits) {
                                case 8:
                                    bext = reg->ext;
                                    break;
                                case 16:
                                    bext = reg->ext;
                                    break;
                                case 32:
                                    bext = reg->ext;
                                    break;
                                case 64:
                                    bext = reg->ext;
                                    break;
                                default:
                                    /* unreachable */
                                    break;
                                }
                                break;
                            }
                            if (op.mem.index && strcmp(op.mem.index, reg->key) == 0) {
                                switch (reg->bits) {
                                case 8:
                                    iext = reg->ext;
                                    break;
                                case 16:
                                    iext = reg->ext;
                                    break;
                                case 32:
                                    iext = reg->ext;
                                    break;
                                case 64:
                                    iext = reg->ext;
                                    break;
                                default:
                                    /* unreachable */
                                    break;
                                }
                                break;
                            }
                        }
                    }
                    operands[arity++] = op;
                    if (bext) {
                        operands[0].aux |= OPENASM_AUX_REXB;
                    }
                    if (iext) {
                        operands[0].aux |= OPENASM_AUX_REXX;
                    }
                    if (regs == 0 && ext[regs]) {
                        operands[0].aux |= OPENASM_AUX_REXR;
                        ++regs;
                    } else if (regs == 1 && ext[regs]) {
                        operands[0].aux |= OPENASM_AUX_REXB;
                        ++regs;
                    } else {
                        operands[0].aux |= OPENASM_AUX_NONE;
                    }
                } break;
                case 'r': {
                    const char *target = va_arg(args, char *);
                    uint32_t tag = -1;
                    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
                        if (strcmp(target, reg->key) == 0) {
                            switch (reg->bits) {
                            case 8:
                                ext[regs] = reg->ext;
                                tag = OPENASM_OP_REG8;
                                break;
                            case 16:
                                ext[regs] = reg->ext;
                                tag = OPENASM_OP_REG16;
                                break;
                            case 32:
                                ext[regs] = reg->ext;
                                tag = OPENASM_OP_REG32;
                                break;
                            case 64:
                                ext[regs] = reg->ext;
                                tag = OPENASM_OP_REG64;
                                break;
                            default:
                                /* unreachable */
                                break;
                            }
                            break;
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
                    int bext = 0;
                    int iext = 0;
                    struct OpenasmMemory mem = va_arg(args, struct OpenasmMemory);
                    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
                        if (strcmp(mem.base, reg->key) == 0) {
                            switch (reg->bits) {
                            case 8:
                                bext = reg->ext;
                                break;
                            case 16:
                                bext = reg->ext;
                                break;
                            case 32:
                                bext = reg->ext;
                                break;
                            case 64:
                                bext = reg->ext;
                                break;
                            default:
                                /* unreachable */
                                break;
                            }
                            break;
                        }
                        if (mem.index && strcmp(mem.index, reg->key) == 0) {
                            switch (reg->bits) {
                            case 8:
                                iext = reg->ext;
                                break;
                            case 16:
                                iext = reg->ext;
                                break;
                            case 32:
                                iext = reg->ext;
                                break;
                            case 64:
                                iext = reg->ext;
                                break;
                            default:
                                /* unreachable */
                                break;
                            }
                            break;
                        }
                    }
                    if (bext) {
                        operands[0].aux |= OPENASM_AUX_REXB;
                    }
                    if (iext) {
                        operands[0].aux |= OPENASM_AUX_REXX;
                    }
                    operands[arity].mem = mem;
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
                // second attempt, change operand size
                size_t size0 = openasm_opsize(operands[0].tag);
                size_t size1 = openasm_opsize(operands[1].tag);
                if (size0 > size1) {
                    operands[0].tag = openasm_match_opsize(&operands[0], operands[1].tag);
                    fprintf(stderr, "warning: truncating 1st operand to match 2nd operand's size\n");
                } else if (size1 > size0) {
                    operands[1].tag = openasm_match_opsize(&operands[1], operands[0].tag);
                    fprintf(stderr, "warning: truncating 2nd operand to match 1st operand's size\n");
                }
                tag = OPENASM_CONS2(operands[1].tag, operands[0].tag);
                fn = entry->inst_table[tag];
                if (!fn) {
                    if (arity == 1) {
                        fprintf(stderr, "error: invalid combination of opcode and operands: \"%s %d\"\n", mnemonic, operands[0].tag);
                    } else {
                        fprintf(stderr, "error: invalid combination of opcode and operands: \"%s %d, %d\"\n", mnemonic, operands[0].tag, operands[1].tag);
                    }
                    return 1;
                }
            }
            return fn(buf, operands);
        }
    }
    
    fprintf(stderr, "error: unimplemented `openasm_instf` mnemonic: \"%s\"\n", mnemonic);
    return 1;
}
