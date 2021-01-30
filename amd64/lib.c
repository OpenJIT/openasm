#define OPENASM_ARCH_AMD64 1
#include "include/openasm.h"

#define DEFAULT_SECTION_CAP ((size_t) 32)
#define DEFAULT_SYMTABLE_CAP ((size_t) 128)

void openasm_buffer(OpenasmBuffer *buf) {
    size_t cap = DEFAULT_SECTION_CAP;
    buf->cap = cap;
    buf->len = 0;
    buf->sections = malloc(cap * sizeof(struct OpenasmSection));

    openasm_section(buf, "debug_info");
    openasm_section(buf, "debug_line");
    openasm_section(buf, "debug_abbrev");
    openasm_section(buf, "rodata");
    openasm_section(buf, "data");
    openasm_section(buf, "bss");
    openasm_section(buf, "text");

    buf->sym = 0;
    cap = DEFAULT_SYMTABLE_CAP;
    buf->symtable.cap = cap;
    buf->symtable.len = 0;
    buf->symtable.table = malloc(cap * sizeof(struct OpenasmSymbol));

    buf->export.cap = cap;
    buf->export.len = 0;
    buf->export.table = malloc(cap * sizeof(struct OpenasmSymbol));

    buf->has_legacy_prefix = 0;
    buf->has_rex_prefix = 0;
    buf->has_opcode = 0;
    buf->has_modrm = 0;
    buf->has_sib = 0;
    buf->has_disp = 0;
    buf->has_imm = 0;
    buf->size = 0;
}

void openasm_del_buffer(OpenasmBuffer *buf) {
    for (size_t i = 0; i < buf->len; i++) {
        free(buf->sections[i].buffer);
    }
    free(buf->symtable.table);
    free(buf->sections);
}

uint64_t openasm_data(OpenasmBuffer *buf, size_t len, void *ptr) {
    if (buf->sections[buf->section].len + len >= buf->sections[buf->section].cap) {
        buf->sections[buf->section].cap *= 2;
        buf->sections[buf->section].buffer = realloc(buf->sections[buf->section].buffer, buf->sections[buf->section].cap);
    }

    uint8_t *buffer = buf->sections[buf->section].buffer;
    uint8_t *dest = buffer + buf->sections[buf->section].len;
    memcpy(dest, ptr, len);
    buf->sections[buf->section].len += len;
    
    return dest - buffer;
}

uint64_t openasm_res(OpenasmBuffer *buf, size_t len) {
    if (buf->sections[buf->section].len + len >= buf->sections[buf->section].cap) {
        buf->sections[buf->section].cap *= 2;
        buf->sections[buf->section].buffer = realloc(buf->sections[buf->section].buffer, buf->sections[buf->section].cap);
    }

    uint8_t *buffer = buf->sections[buf->section].buffer;
    uint8_t *dest = buffer + buf->sections[buf->section].len;
    memset(dest, 0, len);
    buf->sections[buf->section].len += len;
    
    return dest - buffer;
}

uint8_t *openasm_new(OpenasmBuffer *buf) {
    if (buf->sections[buf->section].len + OPENASM_MAX_SIZE >= buf->sections[buf->section].cap) {
        buf->sections[buf->section].cap *= 2;
        buf->sections[buf->section].buffer = realloc(buf->sections[buf->section].buffer, buf->sections[buf->section].cap);
    }

    return buf->sections[buf->section].buffer + buf->sections[buf->section].len;
}

uint8_t *openasm_legacy_prefix(OpenasmBuffer *buf, uint8_t *ptr, uint8_t prefix) {
    openasm_assert(!buf->has_legacy_prefix);
    openasm_assert(!buf->has_opcode);

    buf->has_legacy_prefix = 1;
    buf->size += 1;
    *ptr = prefix;

    return ptr + 1;
}

uint8_t *openasm_rex_prefix(OpenasmBuffer *buf, uint8_t *ptr, uint8_t prefix) {
    openasm_assert(!buf->has_rex_prefix);
    openasm_assert(!buf->has_opcode);

    buf->has_rex_prefix = 1;
    buf->size += 1;
    *ptr = prefix;

    return ptr + 1;
}

uint8_t *openasm_opcode1(OpenasmBuffer *buf, uint8_t *ptr, uint8_t op) {
    openasm_assert(!buf->has_opcode);

    buf->has_opcode = 1;
    buf->size += 1;
    *ptr = op;

    return ptr + 1;
}

uint8_t *openasm_opcode2(OpenasmBuffer *buf, uint8_t *ptr, uint8_t op) {
    openasm_assert(!buf->has_opcode);

    buf->has_opcode = 2;
    buf->size += 2;
    ptr[0] = OPENASM_OPCODE2_ESCAPE;
    ptr[1] = op;

    return ptr + 2;
}

uint8_t *openasm_opcode3a(OpenasmBuffer *buf, uint8_t *ptr, uint8_t op) {
    openasm_assert(!buf->has_opcode);

    buf->has_opcode = 3;
    buf->size += 3;
    ptr[0] = OPENASM_OPCODE2_ESCAPE;
    ptr[1] = OPENASM_OPCODE3_ESCAPE1;
    ptr[2] = op;

    return ptr + 3;
}

uint8_t *openasm_opcode3b(OpenasmBuffer *buf, uint8_t *ptr, uint8_t op) {
    openasm_assert(!buf->has_opcode);

    buf->has_opcode = 3;
    buf->size += 3;
    ptr[0] = OPENASM_OPCODE2_ESCAPE;
    ptr[1] = OPENASM_OPCODE3_ESCAPE2;
    ptr[2] = op;

    return ptr + 3;
}

uint8_t *openasm_modrm(OpenasmBuffer *buf, uint8_t *ptr, uint8_t modrm) {
    openasm_assert(!buf->has_modrm);
    openasm_assert(buf->has_opcode);
    openasm_assert(!buf->has_sib);

    buf->has_modrm = 1;
    buf->size += 1;
    *ptr = modrm;

    return ptr + 1;
}

uint8_t *openasm_sib(OpenasmBuffer *buf, uint8_t *ptr, uint8_t sib) {
    openasm_assert(!buf->has_sib);
    openasm_assert(buf->has_opcode);
    openasm_assert(!buf->has_disp);

    buf->has_sib = 1;
    buf->size += 1;
    *ptr = sib;

    return ptr + 1;
}

uint8_t *openasm_disp8(OpenasmBuffer *buf, uint8_t *ptr, uint8_t disp) {
    openasm_assert(!buf->has_disp);
    openasm_assert(buf->has_opcode);
    openasm_assert(!buf->has_imm);

    buf->has_disp = 1;
    buf->size += 1;
    *ptr = disp;

    return ptr + 1;
}

uint8_t *openasm_disp16(OpenasmBuffer *buf, uint8_t *ptr, uint16_t disp) {
    openasm_assert(!buf->has_disp);
    openasm_assert(buf->has_opcode);
    openasm_assert(!buf->has_imm);

    buf->has_disp = 2;
    buf->size += 2;
    ptr[0] = disp & 0xff;
    ptr[1] = (disp >> 8) & 0xff;

    return ptr + 2;
}

uint8_t *openasm_disp32(OpenasmBuffer *buf, uint8_t *ptr, uint32_t disp) {
    openasm_assert(!buf->has_disp);
    openasm_assert(buf->has_opcode);
    openasm_assert(!buf->has_imm);

    buf->has_disp = 4;
    buf->size += 4;
    ptr[0] = disp & 0xff;
    ptr[1] = (disp >> 8) & 0xff;
    ptr[2] = (disp >> 16) & 0xff;
    ptr[3] = (disp >> 24) & 0xff;

    return ptr + 4;
}

uint8_t *openasm_imm8(OpenasmBuffer *buf, uint8_t *ptr, uint8_t imm) {
    openasm_assert(!buf->has_imm);
    openasm_assert(buf->has_opcode);

    buf->has_imm = 1;
    buf->size += 1;
    ptr[0] = imm;
    if (buf->sym) {
        buf->symtable.table[buf->symtable.len - 1].offset = ptr - buf->sections[buf->section].buffer;
        buf->symtable.table[buf->symtable.len - 1].bits = 8;
        buf->sym = 0;
    }

    return ptr + 1;
}

uint8_t *openasm_imm16(OpenasmBuffer *buf, uint8_t *ptr, uint16_t imm) {
    openasm_assert(!buf->has_imm);
    openasm_assert(buf->has_opcode);

    buf->has_imm = 2;
    buf->size += 2;
    ptr[0] = imm & 0xff;
    ptr[1] = (imm >> 8) & 0xff;
    if (buf->sym) {
        buf->symtable.table[buf->symtable.len - 1].offset = ptr - buf->sections[buf->section].buffer;
        buf->symtable.table[buf->symtable.len - 1].bits = 16;
        buf->sym = 0;
    }

    return ptr + 2;
}

uint8_t *openasm_imm32(OpenasmBuffer *buf, uint8_t *ptr, uint32_t imm) {
    openasm_assert(!buf->has_imm);
    openasm_assert(buf->has_opcode);

    buf->has_imm = 4;
    buf->size += 4;
    ptr[0] = imm & 0xff;
    ptr[1] = (imm >> 8) & 0xff;
    ptr[2] = (imm >> 16) & 0xff;
    ptr[3] = (imm >> 24) & 0xff;
    if (buf->sym) {
        buf->symtable.table[buf->symtable.len - 1].offset = ptr - buf->sections[buf->section].buffer;
        buf->symtable.table[buf->symtable.len - 1].bits = 32;
        buf->sym = 0;
    }

    return ptr + 4;
}

uint8_t *openasm_imm64(OpenasmBuffer *buf, uint8_t *ptr, uint64_t imm) {
    openasm_assert(!buf->has_imm);
    openasm_assert(buf->has_opcode);

    buf->has_imm = 8;
    buf->size += 8;
    ptr[0] = imm & 0xff;
    ptr[1] = (imm >> 8) & 0xff;
    ptr[2] = (imm >> 16) & 0xff;
    ptr[3] = (imm >> 24) & 0xff;
    ptr[4] = (imm >> 32) & 0xff;
    ptr[5] = (imm >> 40) & 0xff;
    ptr[6] = (imm >> 48) & 0xff;
    ptr[7] = (imm >> 56) & 0xff;
    if (buf->sym) {
        buf->symtable.table[buf->symtable.len - 1].offset = ptr - buf->sections[buf->section].buffer;
        buf->symtable.table[buf->symtable.len - 1].bits = 64;
        buf->sym = 0;
    }

    return ptr + 8;
}

int openasm_build(OpenasmBuffer *buf, uint8_t *start, uint8_t *end) {
    /* TODO: actually validate the instruction */
    (void) start;
    (void) end;
    
    buf->has_legacy_prefix = 0;
    buf->has_rex_prefix = 0;
    buf->has_opcode = 0;
    buf->has_modrm = 0;
    buf->has_sib = 0;
    buf->has_disp = 0;
    buf->has_imm = 0;
    buf->sections[buf->section].len += end - start;

    return 0;
}

/* unused */
void openasm_set_imm(uint8_t *inst, int bits, uint64_t imm) {
    int has_legacy_prefix = *inst == OPENASM_PREFIX1_LOCK
        || *inst == OPENASM_PREFIX1_REPNZ
        || *inst == OPENASM_PREFIX1_REPZ
        || *inst == OPENASM_PREFIX1_REP
        || *inst == OPENASM_PREFIX2_CS_OR
        || *inst == OPENASM_PREFIX2_SS_OR
        || *inst == OPENASM_PREFIX2_DS_OR
        || *inst == OPENASM_PREFIX2_ES_OR
        || *inst == OPENASM_PREFIX2_FS_OR
        || *inst == OPENASM_PREFIX2_GS_OR
        || *inst == OPENASM_PREFIX2_BR_NT
        || *inst == OPENASM_PREFIX2_BR_T
        || *inst == OPENASM_PREFIX3_OP_SIZE
        || *inst == OPENASM_PREFIX4_ADDR_SIZE;
    if (has_legacy_prefix) {
        ++inst;
    }

    int has_rex_prefix = (*inst & 0xf0) != 0;
    if (has_rex_prefix) {
        ++inst;
    }

    int has_op2_escape = *inst == OPENASM_OPCODE2_ESCAPE;
    int has_op3a_escape = 0;
    int has_op3b_escape = 0;

    if (has_op2_escape) {
        ++inst;
    
        has_op3a_escape = *inst == OPENASM_OPCODE3_ESCAPE1;
        has_op3b_escape = *inst == OPENASM_OPCODE3_ESCAPE2;
    
        if (has_op3a_escape || has_op3b_escape) {
            ++inst;
        }
    }

    uint8_t opcode = *inst;

    // opcode
    ++inst;

    int has_modrm = 0;
    int has_imm = 0;

    if (has_op3a_escape) {
        if (openasm_properties3a[opcode].modrm) {
            has_modrm = 1;
        }
        has_imm = openasm_properties3a[opcode].imm;
    } else if (has_op3b_escape) {
        if (openasm_properties3b[opcode].modrm) {
            has_modrm = 1;
        }
        has_imm = openasm_properties3b[opcode].imm;
    } else if (has_op2_escape) {
        if (openasm_properties2[opcode].modrm) {
            has_modrm = 1;
        }
        has_imm = openasm_properties2[opcode].imm;
    } else {
        if (openasm_properties1[opcode].modrm) {
            has_modrm = 1;
        }
        has_imm = openasm_properties1[opcode].imm;
    }

    if (has_modrm) {
        uint8_t modrm = *inst;
        uint8_t a = OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB, 0, OPENASM_MODRM_RM_EA_SIB);
        uint8_t b = OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB_DISP8, 0, OPENASM_MODRM_RM_EA_SIB);
        uint8_t c = OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB_DISP32, 0, OPENASM_MODRM_RM_EA_SIB);
        // isb
        int has_sib = (modrm & ~OPENASM_MODRM_REGMASK) == a
            || (modrm & ~OPENASM_MODRM_REGMASK) == b
            || (modrm & ~OPENASM_MODRM_REGMASK) == c;
        if (has_sib) {
            ++inst;
        }
        uint8_t d = OPENASM_MODRM(OPENASM_MODRM_MOD_EA_DISP32, 0, OPENASM_MODRM_RM_EA_DISP32);
        uint8_t e = OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM_DISP8, 0, 0);
        uint8_t f = OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM_DISP32, 0, 0);
        int has_disp8 = (modrm & OPENASM_MODRM_MODMASK) == e;
        int has_disp32 = (modrm & OPENASM_MODRM_MODMASK) == f
            || (modrm & ~OPENASM_MODRM_REGMASK) == d;
        if (has_disp8) {
            ++inst;
        } else if (has_disp32) {
            inst += 4;
        }
    }

    if (has_imm == bits) {
        switch (bits) {
        case 8:
            *inst = imm & 0xff;
            break;
        case 16:
            *((uint16_t *) inst) = imm & 0xffff;
            break;
        case 32:
            *((uint32_t *) inst) = imm & 0xffffffff;
            break;
        case 64:
            *((uint64_t *) inst) = imm;
            break;
        default:
            /* unreachable */
            break;
        }
    }
}

#define SET_REGISTER(name, rr, bb) do { \
        for (struct OpenasmRegister *_reg = openasm_register; _reg->key; _reg++) { \
            if (strcmp(name, _reg->key) == 0 && _reg->bits == bb) { \
                rr = _reg->val; \
                break; \
            } \
        } \
\
        if (rr == (uint32_t) -1) { \
            fprintf(stderr, "error: invalid target register: \"%s\"\n", name); \
            return 1; \
        } \
    } while (0)

#define SET_REGISTER_O(name, opcode, bb) do {   \
    uint32_t reg = -1; \
    SET_REGISTER(name, reg, bb); \
    inst = openasm_opcode1(buf, inst, opcode + reg); \
} while (0)

#define SET_REGISTER_REG(name, bb) do { \
    uint32_t reg = -1; \
    SET_REGISTER(name, reg, bb); \
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, reg, 0)); \
} while (0)

#define SET_REGISTER_RM(name, regval, bb) do { \
    uint32_t reg = -1; \
    SET_REGISTER(name, reg, bb); \
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, regval, reg)); \
} while (0)

#define SET_MEMORY_RM(op, aux) do { \
        uint32_t base_reg = -1; \
        const char *base = op.mem.base; \
 \
        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) { \
            if (strcmp(base, reg->key) == 0 && reg->bits == 64) { \
                base_reg = reg->val; \
                break; \
            } \
        } \
 \
        if (base_reg == (uint32_t) -1) { \
            fprintf(stderr, "error: invalid base register: \"%s\"\n", base); \
            return 1; \
        } \
 \
        uint32_t index_reg = -1; \
        const char *index = op.mem.index; \
 \
        if (index) { \
            for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) { \
                if (strcmp(index, reg->key) == 0 && reg->bits == 64) { \
                    index_reg = reg->val; \
                    break; \
                } \
            } \
 \
            if (index_reg == (uint32_t) -1) { \
                fprintf(stderr, "error: invalid index register: \"%s\"\n", index); \
                return 1; \
            } \
        } \
 \
        if (index) { \
            uint32_t scale = 0; \
            switch (op.mem.scale) { \
            case 1: \
                scale = OPENASM_SCALE_1; \
                break; \
            case 2: \
                scale = OPENASM_SCALE_2; \
                break; \
            case 4: \
                scale = OPENASM_SCALE_4; \
                break; \
            case 8: \
                scale = OPENASM_SCALE_8; \
                break; \
            default: \
                fprintf(stderr, "error: invalid scale argument: %lu\n", op.mem.scale); \
                return 1; \
            } \
            /* TODO: special case where mod = 0x0, r/m = 0x5 is disp32 (and not rbp!) */ \
            if (op.mem.disp) { \
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB_DISP32, aux, OPENASM_MODRM_RM_EA_SIB)); \
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg)); \
                inst = openasm_disp32(buf, inst, (int32_t) op.mem.disp); \
            } else { \
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB, aux, OPENASM_MODRM_RM_EA_SIB)); \
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg)); \
            } \
        } else { \
            if (op.mem.disp) { \
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM_DISP32, aux, base_reg)); \
                inst = openasm_disp32(buf, inst, (int32_t) op.mem.disp); \
            } else { \
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM, aux, base_reg)); \
            } \
        } \
    } while (0)

#define SET_MEMORY_MR(aux) do { \
        uint32_t base_reg = -1; \
        const char *base = op.mem.base; \
 \
        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) { \
            if (strcmp(base, reg->key) == 0 && reg->bits == 64) { \
                base_reg = reg->val; \
                break; \
            } \
        } \
 \
        if (base_reg == (uint32_t) -1) { \
            fprintf(stderr, "error: invalid base register: \"%s\"\n", base); \
            return 1; \
        } \
 \
        uint32_t index_reg = -1; \
        const char *index = op.mem.index; \
 \
        if (index) { \
            for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) { \
                if (strcmp(index, reg->key) == 0 && reg->bits == 64) { \
                    index_reg = reg->val; \
                    break; \
                } \
            } \
 \
            if (index_reg == (uint32_t) -1) { \
                fprintf(stderr, "error: invalid index register: \"%s\"\n", index); \
                return 1; \
            } \
        } \
 \
        if (index) { \
            uint32_t scale = 0; \
            switch (op.mem.scale) { \
            case 1: \
                scale = OPENASM_SCALE_1; \
                break; \
            case 2: \
                scale = OPENASM_SCALE_2; \
                break; \
            case 4: \
                scale = OPENASM_SCALE_4; \
                break; \
            case 8: \
                scale = OPENASM_SCALE_8; \
                break; \
            default: \
                fprintf(stderr, "error: invalid scale argument: %lu\n", op.mem.scale); \
                return 1; \
            } \
            /* TODO: special case where mod = 0x0, r/m = 0x5 is disp32 (and not rbp!) */ \
            if (op.mem.disp) { \
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB_DISP32, OPENASM_MODRM_RM_EA_SIB, aux)); \
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg)); \
                inst = openasm_disp32(buf, inst, (int32_t) op.mem.disp); \
            } else { \
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB, OPENASM_MODRM_RM_EA_SIB, aux)); \
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg)); \
            } \
        } else { \
            if (op.mem.disp) { \
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM_DISP32, base_reg, aux)); \
                inst = openasm_disp32(buf, inst, (int32_t) op.mem.disp); \
            } else { \
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM, base_reg, aux)); \
            } \
        } \
    } while (0)

#define SET_REG_OR_MEM(op, regval, mm, bb) do {  \
    if (op.tag == mm) { \
        SET_MEMORY_RM(op, regval);           \
    } else { \
        SET_REGISTER_RM(op.reg, regval, bb); \
    } \
} while (0)

#define SET_RM_AND_R(op0, op1, mm, bb) do {  \
    uint32_t reg1 = -1; \
    SET_REGISTER(op1.reg, reg1, bb); \
    SET_REG_OR_MEM(op0, reg1, mm, bb);            \
} while (0)

#define REX_RM_R \
uint8_t R; \
do { \
     if (op[0].tag == OPENASM_OP_MEMORY64) {                         \
        R = (op->aux & OPENASM_AUX_REXR)? OPENASM_PREFIX64_REXR : 0; \
        R |= (op->aux & OPENASM_AUX_REXB)? OPENASM_PREFIX64_REXB : 0; \
        R |= (op->aux & OPENASM_AUX_REXX)? OPENASM_PREFIX64_REXX : 0; \
    } else { \
        R = (op->aux & OPENASM_AUX_REXR)? OPENASM_PREFIX64_REXB : 0; \
        R |= (op->aux & OPENASM_AUX_REXB)? OPENASM_PREFIX64_REXR : 0; \
        R |= (op->aux & OPENASM_AUX_REXX)? OPENASM_PREFIX64_REXX : 0; \
    } \
} while (0)

#define REX_R_RM \
uint8_t R; \
do { \
    if (op[1].tag == OPENASM_OP_MEMORY64) { \
        R = (op->aux & OPENASM_AUX_REXR)? OPENASM_PREFIX64_REXR : 0; \
        R |= (op->aux & OPENASM_AUX_REXB)? OPENASM_PREFIX64_REXB : 0; \
        R |= (op->aux & OPENASM_AUX_REXX)? OPENASM_PREFIX64_REXX : 0; \
    } else { \
        R = (op->aux & OPENASM_AUX_REXR)? OPENASM_PREFIX64_REXB : 0; \
        R |= (op->aux & OPENASM_AUX_REXB)? OPENASM_PREFIX64_REXR : 0; \
        R |= (op->aux & OPENASM_AUX_REXX)? OPENASM_PREFIX64_REXX : 0; \
    } \
} while (0)

int openasm_addlike_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REX0);
    inst = openasm_opcode1(buf, inst, opcode);

    inst = openasm_imm8(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addlike_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    inst = openasm_opcode1(buf, inst, opcode);

    inst = openasm_imm16(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addlike_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, opcode);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addsxlike_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW);
    inst = openasm_opcode1(buf, inst, opcode);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addlike_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REX0 | R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_REG_OR_MEM(op[0], regval, OPENASM_OP_MEMORY8, 8);

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addlike_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_REG_OR_MEM(op[0], regval, OPENASM_OP_MEMORY16, 16);

    inst = openasm_imm16(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addlike_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_REG_OR_MEM(op[0], regval, OPENASM_OP_MEMORY32, 32);

    inst = openasm_imm32(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addsxlike_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_REG_OR_MEM(op[0], regval, OPENASM_OP_MEMORY64, 64);

    inst = openasm_imm32(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addsxlike_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_REG_OR_MEM(op[0], regval, OPENASM_OP_MEMORY16, 16);

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addsxlike_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_REG_OR_MEM(op[0], regval, OPENASM_OP_MEMORY32, 32);

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addsxlike_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_REG_OR_MEM(op[0], regval, OPENASM_OP_MEMORY64, 64);

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_addlike_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REX0 | R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_RM_AND_R(op[0], op[1], OPENASM_OP_MEMORY8, 8);

    return openasm_build(buf, start, inst);
}

int openasm_addlike_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_RM_AND_R(op[0], op[1], OPENASM_OP_MEMORY16, 16);

    return openasm_build(buf, start, inst);
}

int openasm_addlike_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_RM_AND_R(op[0], op[1], OPENASM_OP_MEMORY32, 32);

    return openasm_build(buf, start, inst);
}

int openasm_addlike_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_RM_AND_R(op[0], op[1], OPENASM_OP_MEMORY64, 64);

    return openasm_build(buf, start, inst);
}

int openasm_addlike_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_RM_AND_R(op[1], op[0], OPENASM_OP_MEMORY8, 8);

    return openasm_build(buf, start, inst);
}

int openasm_addlike_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_RM_AND_R(op[1], op[0], OPENASM_OP_MEMORY16, 16);

    return openasm_build(buf, start, inst);
}

int openasm_addlike_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_RM_AND_R(op[1], op[0], OPENASM_OP_MEMORY32, 32);

    return openasm_build(buf, start, inst);
}

int openasm_addlike_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode1(buf, inst, opcode);

    SET_RM_AND_R(op[1], op[0], OPENASM_OP_MEMORY64, 64);

    return openasm_build(buf, start, inst);
}


int openasm_add_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_al_imm8(buf, op, OPENASM_ADD_AL_IMM8, 0);
}

int openasm_add_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_ax_imm16(buf, op, OPENASM_ADD_AX_IMM16, 0);
}

int openasm_add_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_eax_imm32(buf, op, OPENASM_ADD_EAX_IMM32, 0);
}

int openasm_addsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rax_imm32(buf, op, OPENASM_ADDSX_RAX_IMM32, 0);
}

int openasm_add_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_imm8(buf, op, OPENASM_ADD_RM8_IMM8, 0);
}

int openasm_add_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_imm16(buf, op, OPENASM_ADD_RM16_IMM16, 0);
}

int openasm_add_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_imm32(buf, op, OPENASM_ADD_RM32_IMM32, 0);
}

int openasm_addsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm32(buf, op, OPENASM_ADDSX_RM64_IMM32, 0);
}

int openasm_addsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm16_imm8(buf, op, OPENASM_ADDSX_RM16_IMM8, 0);
}

int openasm_addsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm32_imm8(buf, op, OPENASM_ADDSX_RM32_IMM8, 0);
}

int openasm_addsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm8(buf, op, OPENASM_ADDSX_RM64_IMM8, 0);
}

int openasm_add_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_r8(buf, op, OPENASM_ADD_RM8_R8, 0);
}

int openasm_add_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_r16(buf, op, OPENASM_ADD_RM16_R16, 0);
}

int openasm_add_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_r32(buf, op, OPENASM_ADD_RM32_R32, 0);
}

int openasm_add_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm64_r64(buf, op, OPENASM_ADD_RM64_R64, 0);
}

int openasm_add_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r8_rm8(buf, op, OPENASM_ADD_R8_RM8, 0);
}

int openasm_add_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r16_rm16(buf, op, OPENASM_ADD_R16_RM16, 0);
}

int openasm_add_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r32_rm32(buf, op, OPENASM_ADD_R32_RM32, 0);
}

int openasm_add_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r64_rm64(buf, op, OPENASM_ADD_R64_RM64, 0);
}


int openasm_adc_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_al_imm8(buf, op, OPENASM_ADC_AL_IMM8, 2);
}

int openasm_adc_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_ax_imm16(buf, op, OPENASM_ADC_AX_IMM16, 2);
}

int openasm_adc_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_eax_imm32(buf, op, OPENASM_ADC_EAX_IMM32, 2);
}

int openasm_adcsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rax_imm32(buf, op, OPENASM_ADCSX_RAX_IMM32, 2);
}

int openasm_adc_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_imm8(buf, op, OPENASM_ADC_RM8_IMM8, 2);
}

int openasm_adc_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_imm16(buf, op, OPENASM_ADC_RM16_IMM16, 2);
}

int openasm_adc_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_imm32(buf, op, OPENASM_ADC_RM32_IMM32, 2);
}

int openasm_adcsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm32(buf, op, OPENASM_ADCSX_RM64_IMM32, 2);
}

int openasm_adcsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm16_imm8(buf, op, OPENASM_ADCSX_RM16_IMM8, 2);
}

int openasm_adcsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm32_imm8(buf, op, OPENASM_ADCSX_RM32_IMM8, 2);
}

int openasm_adcsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm8(buf, op, OPENASM_ADCSX_RM64_IMM8, 2);
}

int openasm_adc_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_r8(buf, op, OPENASM_ADC_RM8_R8, 2);
}

int openasm_adc_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_r16(buf, op, OPENASM_ADC_RM16_R16, 2);
}

int openasm_adc_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_r32(buf, op, OPENASM_ADC_RM32_R32, 2);
}

int openasm_adc_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm64_r64(buf, op, OPENASM_ADC_RM64_R64, 2);
}

int openasm_adc_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r8_rm8(buf, op, OPENASM_ADC_R8_RM8, 2);
}

int openasm_adc_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r16_rm16(buf, op, OPENASM_ADC_R16_RM16, 2);
}

int openasm_adc_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r32_rm32(buf, op, OPENASM_ADC_R32_RM32, 2);
}

int openasm_adc_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r64_rm64(buf, op, OPENASM_ADC_R64_RM64, 2);
}


int openasm_and_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_al_imm8(buf, op, OPENASM_AND_AL_IMM8, 4);
}

int openasm_and_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_ax_imm16(buf, op, OPENASM_AND_AX_IMM16, 4);
}

int openasm_and_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_eax_imm32(buf, op, OPENASM_AND_EAX_IMM32, 4);
}

int openasm_andsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rax_imm32(buf, op, OPENASM_ANDSX_RAX_IMM32, 4);
}

int openasm_and_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_imm8(buf, op, OPENASM_AND_RM8_IMM8, 4);
}

int openasm_and_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_imm16(buf, op, OPENASM_AND_RM16_IMM16, 4);
}

int openasm_and_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_imm32(buf, op, OPENASM_AND_RM32_IMM32, 4);
}

int openasm_andsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm32(buf, op, OPENASM_ANDSX_RM64_IMM32, 4);
}

int openasm_andsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm16_imm8(buf, op, OPENASM_ANDSX_RM16_IMM8, 4);
}

int openasm_andsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm32_imm8(buf, op, OPENASM_ANDSX_RM32_IMM8, 4);
}

int openasm_andsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm8(buf, op, OPENASM_ANDSX_RM64_IMM8, 4);
}

int openasm_and_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_r8(buf, op, OPENASM_AND_RM8_R8, 4);
}

int openasm_and_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_r16(buf, op, OPENASM_AND_RM16_R16, 4);
}

int openasm_and_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_r32(buf, op, OPENASM_AND_RM32_R32, 4);
}

int openasm_and_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm64_r64(buf, op, OPENASM_AND_RM64_R64, 4);
}

int openasm_and_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r8_rm8(buf, op, OPENASM_AND_R8_RM8, 4);
}

int openasm_and_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r16_rm16(buf, op, OPENASM_AND_R16_RM16, 4);
}

int openasm_and_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r32_rm32(buf, op, OPENASM_AND_R32_RM32, 4);
}

int openasm_and_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r64_rm64(buf, op, OPENASM_AND_R64_RM64, 4);
}


int openasm_or_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_al_imm8(buf, op, OPENASM_OR_AL_IMM8, 1);
}

int openasm_or_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_ax_imm16(buf, op, OPENASM_OR_AX_IMM16, 1);
}

int openasm_or_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_eax_imm32(buf, op, OPENASM_OR_EAX_IMM32, 1);
}

int openasm_orsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rax_imm32(buf, op, OPENASM_ORSX_RAX_IMM32, 1);
}

int openasm_or_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_imm8(buf, op, OPENASM_OR_RM8_IMM8, 1);
}

int openasm_or_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_imm16(buf, op, OPENASM_OR_RM16_IMM16, 1);
}

int openasm_or_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_imm32(buf, op, OPENASM_OR_RM32_IMM32, 1);
}

int openasm_orsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm32(buf, op, OPENASM_ORSX_RM64_IMM32, 1);
}

int openasm_orsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm16_imm8(buf, op, OPENASM_ORSX_RM16_IMM8, 1);
}

int openasm_orsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm32_imm8(buf, op, OPENASM_ORSX_RM32_IMM8, 1);
}

int openasm_orsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm8(buf, op, OPENASM_ORSX_RM64_IMM8, 1);
}

int openasm_or_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_r8(buf, op, OPENASM_OR_RM8_R8, 1);
}

int openasm_or_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_r16(buf, op, OPENASM_OR_RM16_R16, 1);
}

int openasm_or_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_r32(buf, op, OPENASM_OR_RM32_R32, 1);
}

int openasm_or_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm64_r64(buf, op, OPENASM_OR_RM64_R64, 1);
}

int openasm_or_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r8_rm8(buf, op, OPENASM_OR_R8_RM8, 1);
}

int openasm_or_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r16_rm16(buf, op, OPENASM_OR_R16_RM16, 1);
}

int openasm_or_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r32_rm32(buf, op, OPENASM_OR_R32_RM32, 1);
}

int openasm_or_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r64_rm64(buf, op, OPENASM_OR_R64_RM64, 1);
}


int openasm_xor_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_al_imm8(buf, op, OPENASM_XOR_AL_IMM8, 6);
}

int openasm_xor_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_ax_imm16(buf, op, OPENASM_XOR_AX_IMM16, 6);
}

int openasm_xor_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_eax_imm32(buf, op, OPENASM_XOR_EAX_IMM32, 6);
}

int openasm_xorsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rax_imm32(buf, op, OPENASM_XORSX_RAX_IMM32, 6);
}

int openasm_xor_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_imm8(buf, op, OPENASM_XOR_RM8_IMM8, 6);
}

int openasm_xor_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_imm16(buf, op, OPENASM_XOR_RM16_IMM16, 6);
}

int openasm_xor_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_imm32(buf, op, OPENASM_XOR_RM32_IMM32, 6);
}

int openasm_xorsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm32(buf, op, OPENASM_XORSX_RM64_IMM32, 6);
}

int openasm_xorsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm16_imm8(buf, op, OPENASM_XORSX_RM16_IMM8, 6);
}

int openasm_xorsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm32_imm8(buf, op, OPENASM_XORSX_RM32_IMM8, 6);
}

int openasm_xorsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm8(buf, op, OPENASM_XORSX_RM64_IMM8, 6);
}

int openasm_xor_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_r8(buf, op, OPENASM_XOR_RM8_R8, 6);
}

int openasm_xor_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_r16(buf, op, OPENASM_XOR_RM16_R16, 6);
}

int openasm_xor_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_r32(buf, op, OPENASM_XOR_RM32_R32, 6);
}

int openasm_xor_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm64_r64(buf, op, OPENASM_XOR_RM64_R64, 6);
}

int openasm_xor_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r8_rm8(buf, op, OPENASM_XOR_R8_RM8, 6);
}

int openasm_xor_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r16_rm16(buf, op, OPENASM_XOR_R16_RM16, 6);
}

int openasm_xor_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r32_rm32(buf, op, OPENASM_XOR_R32_RM32, 6);
}

int openasm_xor_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r64_rm64(buf, op, OPENASM_XOR_R64_RM64, 6);
}


int openasm_sub_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_al_imm8(buf, op, OPENASM_SUB_AL_IMM8, 5);
}

int openasm_sub_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_ax_imm16(buf, op, OPENASM_SUB_AX_IMM16, 5);
}

int openasm_sub_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_eax_imm32(buf, op, OPENASM_SUB_EAX_IMM32, 5);
}

int openasm_subsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rax_imm32(buf, op, OPENASM_SUBSX_RAX_IMM32, 5);
}

int openasm_sub_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_imm8(buf, op, OPENASM_SUB_RM8_IMM8, 5);
}

int openasm_sub_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_imm16(buf, op, OPENASM_SUB_RM16_IMM16, 5);
}

int openasm_sub_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_imm32(buf, op, OPENASM_SUB_RM32_IMM32, 5);
}

int openasm_subsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm32(buf, op, OPENASM_SUBSX_RM64_IMM32, 5);
}

int openasm_subsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm16_imm8(buf, op, OPENASM_SUBSX_RM16_IMM8, 5);
}

int openasm_subsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm32_imm8(buf, op, OPENASM_SUBSX_RM32_IMM8, 5);
}

int openasm_subsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm8(buf, op, OPENASM_SUBSX_RM64_IMM8, 5);
}

int openasm_sub_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_r8(buf, op, OPENASM_SUB_RM8_R8, 5);
}

int openasm_sub_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_r16(buf, op, OPENASM_SUB_RM16_R16, 5);
}

int openasm_sub_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_r32(buf, op, OPENASM_SUB_RM32_R32, 5);
}

int openasm_sub_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm64_r64(buf, op, OPENASM_SUB_RM64_R64, 5);
}

int openasm_sub_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r8_rm8(buf, op, OPENASM_SUB_R8_RM8, 5);
}

int openasm_sub_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r16_rm16(buf, op, OPENASM_SUB_R16_RM16, 5);
}

int openasm_sub_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r32_rm32(buf, op, OPENASM_SUB_R32_RM32, 5);
}

int openasm_sub_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r64_rm64(buf, op, OPENASM_SUB_R64_RM64, 5);
}


int openasm_cmp_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_al_imm8(buf, op, OPENASM_CMP_AL_IMM8, 7);
}

int openasm_cmp_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_ax_imm16(buf, op, OPENASM_CMP_AX_IMM16, 7);
}

int openasm_cmp_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_eax_imm32(buf, op, OPENASM_CMP_EAX_IMM32, 7);
}

int openasm_cmpsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rax_imm32(buf, op, OPENASM_CMPSX_RAX_IMM32, 7);
}

int openasm_cmp_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_imm8(buf, op, OPENASM_CMP_RM8_IMM8, 7);
}

int openasm_cmp_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_imm16(buf, op, OPENASM_CMP_RM16_IMM16, 7);
}

int openasm_cmp_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_imm32(buf, op, OPENASM_CMP_RM32_IMM32, 7);
}

int openasm_cmpsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm32(buf, op, OPENASM_CMPSX_RM64_IMM32, 7);
}

int openasm_cmpsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm16_imm8(buf, op, OPENASM_CMPSX_RM16_IMM8, 7);
}

int openasm_cmpsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm32_imm8(buf, op, OPENASM_CMPSX_RM32_IMM8, 7);
}

int openasm_cmpsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addsxlike_rm64_imm8(buf, op, OPENASM_CMPSX_RM64_IMM8, 7);
}

int openasm_cmp_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm8_r8(buf, op, OPENASM_CMP_RM8_R8, 7);
}

int openasm_cmp_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm16_r16(buf, op, OPENASM_CMP_RM16_R16, 7);
}

int openasm_cmp_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm32_r32(buf, op, OPENASM_CMP_RM32_R32, 7);
}

int openasm_cmp_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_rm64_r64(buf, op, OPENASM_CMP_RM64_R64, 7);
}

int openasm_cmp_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r8_rm8(buf, op, OPENASM_CMP_R8_RM8, 7);
}

int openasm_cmp_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r16_rm16(buf, op, OPENASM_CMP_R16_RM16, 7);
}

int openasm_cmp_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r32_rm32(buf, op, OPENASM_CMP_R32_RM32, 7);
}

int openasm_cmp_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_addlike_r64_rm64(buf, op, OPENASM_CMP_R64_RM64, 7);
}


int openasm_mullike_al_rm8(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REX0 | R);
    inst = openasm_opcode1(buf, inst, opcode);
    SET_REGISTER_RM(op[0].reg, regval, 8);
    
    return openasm_build(buf, start, inst);
}

int openasm_mullike_ax_rm16(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);
    SET_REGISTER_RM(op[0].reg, regval, 16);
    
    return openasm_build(buf, start, inst);
}

int openasm_mullike_eax_rm32(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, opcode);
    SET_REGISTER_RM(op[0].reg, regval, 32);
    
    return openasm_build(buf, start, inst);
}

int openasm_mullike_rax_rm64(OpenasmBuffer *buf, OpenasmOperand *op, uint8_t opcode, uint8_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode1(buf, inst, opcode);
    SET_REGISTER_RM(op[0].reg, regval, 64);
    
    return openasm_build(buf, start, inst);
}


int openasm_mul_al_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_al_rm8(buf, op, OPENASM_MUL_AL_RM8, 4);
}

int openasm_mul_ax_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_ax_rm16(buf, op, OPENASM_MUL_AX_RM16, 4);
}

int openasm_mul_eax_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_eax_rm32(buf, op, OPENASM_MUL_EAX_RM32, 4);
}

int openasm_mul_rax_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_rax_rm64(buf, op, OPENASM_MUL_RAX_RM64, 4);
}


int openasm_imul_al_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_al_rm8(buf, op, OPENASM_IMUL_AL_RM8, 5);
}

int openasm_imul_ax_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_ax_rm16(buf, op, OPENASM_IMUL_AX_RM16, 5);
}

int openasm_imul_eax_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_eax_rm32(buf, op, OPENASM_IMUL_EAX_RM32, 5);
}

int openasm_imul_rax_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_rax_rm64(buf, op, OPENASM_IMUL_RAX_RM64, 5);
}


int openasm_div_al_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_al_rm8(buf, op, OPENASM_DIV_AL_RM8, 6);
}

int openasm_div_ax_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_ax_rm16(buf, op, OPENASM_DIV_AX_RM16, 6);
}

int openasm_div_eax_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_eax_rm32(buf, op, OPENASM_DIV_EAX_RM32, 6);
}

int openasm_div_rax_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_rax_rm64(buf, op, OPENASM_DIV_RAX_RM64, 6);
}


int openasm_idiv_al_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_al_rm8(buf, op, OPENASM_IDIV_AL_RM8, 7);
}

int openasm_idiv_ax_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_ax_rm16(buf, op, OPENASM_IDIV_AX_RM16, 7);
}

int openasm_idiv_eax_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_eax_rm32(buf, op, OPENASM_IDIV_EAX_RM32, 7);
}

int openasm_idiv_rax_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    return openasm_mullike_rax_rm64(buf, op, OPENASM_IDIV_RAX_RM64, 7);
}


int openasm_mov_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REX0 | R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM8_R8);

    SET_RM_AND_R(op[0], op[1], OPENASM_OP_MEMORY8, 8);

    return openasm_build(buf, start, inst);
}

int openasm_mov_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM16_R16);

    SET_RM_AND_R(op[0], op[1], OPENASM_OP_MEMORY16, 16);

    return openasm_build(buf, start, inst);
}

int openasm_mov_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM32_R32);

    SET_RM_AND_R(op[0], op[1], OPENASM_OP_MEMORY32, 32);

    return openasm_build(buf, start, inst);
}

int openasm_mov_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM64_R64);

    SET_RM_AND_R(op[0], op[1], OPENASM_OP_MEMORY64, 64);

    return openasm_build(buf, start, inst);
}

int openasm_mov_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REX0 | R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_R8_RM8);

    SET_RM_AND_R(op[1], op[0], OPENASM_OP_MEMORY8, 8);

    return openasm_build(buf, start, inst);
}

int openasm_mov_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_R16_RM16);

    SET_RM_AND_R(op[1], op[0], OPENASM_OP_MEMORY16, 16);

    return openasm_build(buf, start, inst);
}

int openasm_mov_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_R32_RM32);

    SET_RM_AND_R(op[1], op[0], OPENASM_OP_MEMORY32, 32);

    return openasm_build(buf, start, inst);
}

int openasm_mov_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_R64_RM64);

    SET_RM_AND_R(op[1], op[0], OPENASM_OP_MEMORY64, 64);

    return openasm_build(buf, start, inst);
}

int openasm_mov_r8_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    uint8_t R = (op->aux & OPENASM_AUX_REXR)? OPENASM_PREFIX64_REXB : 0;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REX0 | R);
    SET_REGISTER_O(op[0].reg, OPENASM_MOV_R8_IMM8, 8);

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_mov_r16_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    uint8_t R = (op->aux & OPENASM_AUX_REXR)? OPENASM_PREFIX64_REXB : 0;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    SET_REGISTER_O(op[0].reg, OPENASM_MOV_R16_IMM16, 16);

    inst = openasm_imm16(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_mov_r32_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    uint8_t R = (op->aux & OPENASM_AUX_REXR)? OPENASM_PREFIX64_REXB : 0;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    SET_REGISTER_O(op[0].reg, OPENASM_MOV_R32_IMM32, 32);

    inst = openasm_imm32(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_mov_r64_imm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    uint8_t R = (op->aux & OPENASM_AUX_REXR)? OPENASM_PREFIX64_REXB : 0;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    SET_REGISTER_O(op[0].reg, OPENASM_MOV_R64_IMM64, 64);

    inst = openasm_imm64(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_mov_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REX0 | R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM8_IMM8);
    SET_REGISTER_RM(op[0].reg, 0, 8);

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_mov_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM16_IMM16);
    SET_REGISTER_RM(op[0].reg, 0, 16);

    inst = openasm_imm16(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_mov_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM32_IMM32);
    SET_REGISTER_RM(op[0].reg, 0, 32);

    inst = openasm_imm32(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_movsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOVSX_RM64_IMM32);
    SET_REGISTER_RM(op[0].reg, 0, 64);

    inst = openasm_imm32(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}


int openasm_movzx_r16_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode2(buf, inst, OPENASM_MOVZX_R16_RM8);
    uint32_t reg = -1;
    SET_REGISTER(op[0].reg, reg, 16);
    if (op[0].tag == OPENASM_OP_MEMORY8) {
        SET_MEMORY_RM(op[1], reg);
    } else {
        SET_REGISTER_RM(op[1].reg, reg, 8);
    }

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_movzx_r32_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode2(buf, inst, OPENASM_MOVZX_R32_RM8);
    uint32_t reg = -1;
    SET_REGISTER(op[0].reg, reg, 32);
    if (op[0].tag == OPENASM_OP_MEMORY8) {
        SET_MEMORY_RM(op[1], reg);
    } else {
        SET_REGISTER_RM(op[1].reg, reg, 8);
    }

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_movzx_r32_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode2(buf, inst, OPENASM_MOVZX_R32_RM16);
    uint32_t reg = -1;
    SET_REGISTER(op[0].reg, reg, 32);
    if (op[0].tag == OPENASM_OP_MEMORY16) {
        SET_MEMORY_RM(op[1], reg);
    } else {
        SET_REGISTER_RM(op[1].reg, reg, 16);
    }

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_movzx_r64_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode2(buf, inst, OPENASM_MOVZX_R64_RM16);
    uint64_t reg = -1;
    SET_REGISTER(op[0].reg, reg, 64);
    if (op[0].tag == OPENASM_OP_MEMORY16) {
        SET_MEMORY_RM(op[1], reg);
    } else {
        SET_REGISTER_RM(op[1].reg, reg, 16);
    }

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}


int openasm_movsx_r16_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode2(buf, inst, OPENASM_MOVSX_R16_RM8);
    uint32_t reg = -1;
    SET_REGISTER(op[0].reg, reg, 16);
    if (op[0].tag == OPENASM_OP_MEMORY8) {
        SET_MEMORY_RM(op[1], reg);
    } else {
        SET_REGISTER_RM(op[1].reg, reg, 8);
    }

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_movsx_r32_rm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode2(buf, inst, OPENASM_MOVSX_R32_RM8);
    uint32_t reg = -1;
    SET_REGISTER(op[0].reg, reg, 32);
    if (op[0].tag == OPENASM_OP_MEMORY8) {
        SET_MEMORY_RM(op[1], reg);
    } else {
        SET_REGISTER_RM(op[1].reg, reg, 8);
    }

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_movsx_r32_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    if (R) inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode2(buf, inst, OPENASM_MOVSX_R32_RM16);
    uint32_t reg = -1;
    SET_REGISTER(op[0].reg, reg, 32);
    if (op[0].tag == OPENASM_OP_MEMORY16) {
        SET_MEMORY_RM(op[1], reg);
    } else {
        SET_REGISTER_RM(op[1].reg, reg, 16);
    }

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_movsx_r64_rm16(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode2(buf, inst, OPENASM_MOVSX_R64_RM16);
    uint64_t reg = -1;
    SET_REGISTER(op[0].reg, reg, 64);
    if (op[0].tag == OPENASM_OP_MEMORY16) {
        SET_MEMORY_RM(op[1], reg);
    } else {
        SET_REGISTER_RM(op[1].reg, reg, 16);
    }

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}

int openasm_movsx_r64_rm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode1(buf, inst, OPENASM_MOVSX_R64_RM32);
    uint64_t reg = -1;
    SET_REGISTER(op[0].reg, reg, 64);
    if (op[0].tag == OPENASM_OP_MEMORY32) {
        SET_MEMORY_RM(op[1], reg);
    } else {
        SET_REGISTER_RM(op[1].reg, reg, 32);
    }

    inst = openasm_imm8(buf, inst, op[1].imm);
    return openasm_build(buf, start, inst);
}


int openasm_lea_r64_m64(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_R_RM;
    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW | R);
    inst = openasm_opcode1(buf, inst, OPENASM_LEA_R64_M64);

    SET_RM_AND_R(op[1], op[0], OPENASM_OP_MEMORY64, 64);

    return openasm_build(buf, start, inst);
}


int openasm_pop_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, OPENASM_POP_RM64);
    SET_REG_OR_MEM(op[0], 0, OPENASM_OP_MEMORY64, 64);

    return openasm_build(buf, start, inst);
}

int openasm_pop_r64(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    uint8_t R = (op->aux & OPENASM_AUX_REXR)? OPENASM_PREFIX64_REXB : 0;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    SET_REGISTER_O(op[0].reg, OPENASM_POP_R64, 64);

    return openasm_build(buf, start, inst);
}


int openasm_push_rm64(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    REX_RM_R;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    inst = openasm_opcode1(buf, inst, OPENASM_PUSH_RM64);
    SET_REG_OR_MEM(op[0], 0, OPENASM_OP_MEMORY64, 64);

    return openasm_build(buf, start, inst);
}

int openasm_push_r64(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    uint8_t R = (op->aux & OPENASM_AUX_REXR)? OPENASM_PREFIX64_REXB : 0;
    if (R) inst = openasm_rex_prefix(buf, inst, R);
    SET_REGISTER_O(op[0].reg, OPENASM_PUSH_R64, 64);

    return openasm_build(buf, start, inst);
}

int openasm_push_imm8(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_PUSH_IMM8);

    inst = openasm_imm8(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_push_imm32(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_PUSH_IMM32);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}


int openasm_call_rel32(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_CALL_REL32);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_syscall(OpenasmBuffer *buf, OpenasmOperand *op) {
    (void) op;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode2(buf, inst, OPENASM_SYSCALL);

    return openasm_build(buf, start, inst);
}


int openasm_ret_near(OpenasmBuffer *buf, OpenasmOperand *op) {
    (void) op;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_RET_NEAR);

    return openasm_build(buf, start, inst);
}

int openasm_ret_far(OpenasmBuffer *buf, OpenasmOperand *op) {
    (void) op;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_RET_FAR);

    return openasm_build(buf, start, inst);
}

int openasm_jmp_near(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_JMP_NEAR);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}


int openasm_jc_short(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_JC_SHORT);

    inst = openasm_imm8(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jcxz_short(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_JCXZ_SHORT);

    inst = openasm_imm8(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_je_short(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_JE_SHORT);

    inst = openasm_imm8(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jne_short(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_JNE_SHORT);

    inst = openasm_imm8(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jg_short(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_JG_SHORT);

    inst = openasm_imm8(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jge_short(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_JGE_SHORT);

    inst = openasm_imm8(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jl_short(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_JL_SHORT);

    inst = openasm_imm8(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jle_short(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_JLE_SHORT);

    inst = openasm_imm8(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}


int openasm_jc_near(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode2(buf, inst, OPENASM_JC_NEAR);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_je_near(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode2(buf, inst, OPENASM_JE_NEAR);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jne_near(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode2(buf, inst, OPENASM_JNE_NEAR);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jg_near(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode2(buf, inst, OPENASM_JG_NEAR);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jge_near(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode2(buf, inst, OPENASM_JGE_NEAR);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jl_near(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode2(buf, inst, OPENASM_JL_NEAR);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}

int openasm_jle_near(OpenasmBuffer *buf, OpenasmOperand *op) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode2(buf, inst, OPENASM_JLE_NEAR);

    inst = openasm_imm32(buf, inst, op[0].imm);
    return openasm_build(buf, start, inst);
}


static int (*openasm_inst_add[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_AL)] = openasm_add_al_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_AX)] = openasm_add_ax_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_EAX)] = openasm_add_eax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM64, OPENASM_OP_RAX)] = openasm_addsx_rax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_REG8)] = openasm_add_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_MEMORY8)] = openasm_add_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_REG16)] = openasm_add_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_MEMORY16)] = openasm_add_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG32)] = openasm_add_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY32)] = openasm_add_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_addsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY64)] = openasm_addsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_add_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_MEMORY8)] = openasm_add_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG16)] = openasm_add_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_MEMORY16)] = openasm_add_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_add_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_MEMORY32)] = openasm_add_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_add_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY64)] = openasm_add_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG8)] = openasm_add_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG16)] = openasm_add_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY32, OPENASM_OP_REG32)] = openasm_add_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY64, OPENASM_OP_REG64)] = openasm_add_r64_rm64,
};

static int (*openasm_inst_adc[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_AL)] = openasm_adc_al_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_AX)] = openasm_adc_ax_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_EAX)] = openasm_adc_eax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM64, OPENASM_OP_RAX)] = openasm_adcsx_rax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_REG8)] = openasm_adc_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_MEMORY8)] = openasm_adc_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_REG16)] = openasm_adc_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_MEMORY16)] = openasm_adc_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG32)] = openasm_adc_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY32)] = openasm_adc_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_adcsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY64)] = openasm_adcsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_adc_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_MEMORY8)] = openasm_adc_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG16)] = openasm_adc_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_MEMORY16)] = openasm_adc_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_adc_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_MEMORY32)] = openasm_adc_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_adc_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY64)] = openasm_adc_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG8)] = openasm_adc_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG16)] = openasm_adc_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY32, OPENASM_OP_REG32)] = openasm_adc_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY64, OPENASM_OP_REG64)] = openasm_adc_r64_rm64,
};

static int (*openasm_inst_and[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_AL)] = openasm_and_al_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_AX)] = openasm_and_ax_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_EAX)] = openasm_and_eax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM64, OPENASM_OP_RAX)] = openasm_andsx_rax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_REG8)] = openasm_and_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_MEMORY8)] = openasm_and_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_REG16)] = openasm_and_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_MEMORY16)] = openasm_and_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG32)] = openasm_and_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY32)] = openasm_and_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_andsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY64)] = openasm_andsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_and_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_MEMORY8)] = openasm_and_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG16)] = openasm_and_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_MEMORY16)] = openasm_and_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_and_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_MEMORY32)] = openasm_and_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_and_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY64)] = openasm_and_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG8)] = openasm_and_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG16)] = openasm_and_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY32, OPENASM_OP_REG32)] = openasm_and_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY64, OPENASM_OP_REG64)] = openasm_and_r64_rm64,
};

static int (*openasm_inst_or[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_AL)] = openasm_or_al_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_AX)] = openasm_or_ax_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_EAX)] = openasm_or_eax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM64, OPENASM_OP_RAX)] = openasm_orsx_rax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_REG8)] = openasm_or_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_MEMORY8)] = openasm_or_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_REG16)] = openasm_or_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_MEMORY16)] = openasm_or_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG32)] = openasm_or_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY32)] = openasm_or_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_orsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY64)] = openasm_orsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_or_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_MEMORY8)] = openasm_or_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG16)] = openasm_or_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_MEMORY16)] = openasm_or_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_or_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_MEMORY32)] = openasm_or_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_or_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY64)] = openasm_or_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG8)] = openasm_or_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG16)] = openasm_or_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY32, OPENASM_OP_REG32)] = openasm_or_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY64, OPENASM_OP_REG64)] = openasm_or_r64_rm64,
};

static int (*openasm_inst_xor[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_AL)] = openasm_xor_al_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_AX)] = openasm_xor_ax_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_EAX)] = openasm_xor_eax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM64, OPENASM_OP_RAX)] = openasm_xorsx_rax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_REG8)] = openasm_xor_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_MEMORY8)] = openasm_xor_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_REG16)] = openasm_xor_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_MEMORY16)] = openasm_xor_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG32)] = openasm_xor_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY32)] = openasm_xor_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_xorsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY64)] = openasm_xorsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_xor_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_MEMORY8)] = openasm_xor_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG16)] = openasm_xor_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_MEMORY16)] = openasm_xor_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_xor_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_MEMORY32)] = openasm_xor_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_xor_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY64)] = openasm_xor_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG8)] = openasm_xor_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG16)] = openasm_xor_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY32, OPENASM_OP_REG32)] = openasm_xor_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY64, OPENASM_OP_REG64)] = openasm_xor_r64_rm64,
};

static int (*openasm_inst_sub[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_AL)] = openasm_sub_al_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_AX)] = openasm_sub_ax_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_EAX)] = openasm_sub_eax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM64, OPENASM_OP_RAX)] = openasm_subsx_rax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_REG8)] = openasm_sub_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_MEMORY8)] = openasm_sub_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_REG16)] = openasm_sub_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_MEMORY16)] = openasm_sub_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG32)] = openasm_sub_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY32)] = openasm_sub_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_subsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY64)] = openasm_subsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_sub_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_MEMORY8)] = openasm_sub_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG16)] = openasm_sub_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_MEMORY16)] = openasm_sub_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_sub_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_MEMORY32)] = openasm_sub_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_sub_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY64)] = openasm_sub_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG8)] = openasm_sub_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG16)] = openasm_sub_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY32, OPENASM_OP_REG32)] = openasm_sub_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY64, OPENASM_OP_REG64)] = openasm_sub_r64_rm64,
};

static int (*openasm_inst_cmp[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_AL)] = openasm_cmp_al_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_AX)] = openasm_cmp_ax_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_EAX)] = openasm_cmp_eax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM64, OPENASM_OP_RAX)] = openasm_cmpsx_rax_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_REG8)] = openasm_cmp_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_MEMORY8)] = openasm_cmp_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_REG16)] = openasm_cmp_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_MEMORY16)] = openasm_cmp_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG32)] = openasm_cmp_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY32)] = openasm_cmp_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_cmpsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY64)] = openasm_cmpsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_cmp_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_MEMORY8)] = openasm_cmp_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG16)] = openasm_cmp_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_MEMORY16)] = openasm_cmp_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_cmp_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_MEMORY32)] = openasm_cmp_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_cmp_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY64)] = openasm_cmp_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG8)] = openasm_cmp_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG16)] = openasm_cmp_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY32, OPENASM_OP_REG32)] = openasm_cmp_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY64, OPENASM_OP_REG64)] = openasm_cmp_r64_rm64,
};

static int (*openasm_inst_mul[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_REG8)] = openasm_mul_al_rm8,
    [OPENASM_CONS1(OPENASM_OP_REG16)] = openasm_mul_ax_rm16,
    [OPENASM_CONS1(OPENASM_OP_REG32)] = openasm_mul_eax_rm32,
    [OPENASM_CONS1(OPENASM_OP_REG64)] = openasm_mul_rax_rm64,
    [OPENASM_CONS1(OPENASM_OP_MEMORY8)] = openasm_mul_al_rm8,
    [OPENASM_CONS1(OPENASM_OP_MEMORY16)] = openasm_mul_ax_rm16,
    [OPENASM_CONS1(OPENASM_OP_MEMORY32)] = openasm_mul_eax_rm32,
    [OPENASM_CONS1(OPENASM_OP_MEMORY64)] = openasm_mul_rax_rm64,
};

static int (*openasm_inst_imul[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_REG8)] = openasm_imul_al_rm8,
    [OPENASM_CONS1(OPENASM_OP_REG16)] = openasm_imul_ax_rm16,
    [OPENASM_CONS1(OPENASM_OP_REG32)] = openasm_imul_eax_rm32,
    [OPENASM_CONS1(OPENASM_OP_REG64)] = openasm_imul_rax_rm64,
    [OPENASM_CONS1(OPENASM_OP_MEMORY8)] = openasm_imul_al_rm8,
    [OPENASM_CONS1(OPENASM_OP_MEMORY16)] = openasm_imul_ax_rm16,
    [OPENASM_CONS1(OPENASM_OP_MEMORY32)] = openasm_imul_eax_rm32,
    [OPENASM_CONS1(OPENASM_OP_MEMORY64)] = openasm_imul_rax_rm64,
};

static int (*openasm_inst_div[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_REG8)] = openasm_div_al_rm8,
    [OPENASM_CONS1(OPENASM_OP_REG16)] = openasm_div_ax_rm16,
    [OPENASM_CONS1(OPENASM_OP_REG32)] = openasm_div_eax_rm32,
    [OPENASM_CONS1(OPENASM_OP_REG64)] = openasm_div_rax_rm64,
    [OPENASM_CONS1(OPENASM_OP_MEMORY8)] = openasm_div_al_rm8,
    [OPENASM_CONS1(OPENASM_OP_MEMORY16)] = openasm_div_ax_rm16,
    [OPENASM_CONS1(OPENASM_OP_MEMORY32)] = openasm_div_eax_rm32,
    [OPENASM_CONS1(OPENASM_OP_MEMORY64)] = openasm_div_rax_rm64,
};

static int (*openasm_inst_idiv[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_REG8)] = openasm_idiv_al_rm8,
    [OPENASM_CONS1(OPENASM_OP_REG16)] = openasm_idiv_ax_rm16,
    [OPENASM_CONS1(OPENASM_OP_REG32)] = openasm_idiv_eax_rm32,
    [OPENASM_CONS1(OPENASM_OP_REG64)] = openasm_idiv_rax_rm64,
    [OPENASM_CONS1(OPENASM_OP_MEMORY8)] = openasm_idiv_al_rm8,
    [OPENASM_CONS1(OPENASM_OP_MEMORY16)] = openasm_idiv_ax_rm16,
    [OPENASM_CONS1(OPENASM_OP_MEMORY32)] = openasm_idiv_eax_rm32,
    [OPENASM_CONS1(OPENASM_OP_MEMORY64)] = openasm_idiv_rax_rm64,
};

static int (*openasm_inst_mov[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_mov_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_MEMORY8)] = openasm_mov_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG16)] = openasm_mov_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_MEMORY16)] = openasm_mov_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_mov_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_MEMORY32)] = openasm_mov_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_mov_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY64)] = openasm_mov_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG8)] = openasm_mov_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG16)] = openasm_mov_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY32, OPENASM_OP_REG32)] = openasm_mov_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY64, OPENASM_OP_REG64)] = openasm_mov_r64_rm64,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_REG8)] = openasm_mov_r8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_REG16)] = openasm_mov_r16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG32)] = openasm_mov_r32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM64, OPENASM_OP_REG64)] = openasm_mov_r64_imm64,
    [OPENASM_CONS2(OPENASM_OP_IMM8, OPENASM_OP_MEMORY8)] = openasm_mov_rm8_imm8,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_MEMORY16)] = openasm_mov_rm16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY32)] = openasm_mov_rm32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY64)] = openasm_movsx_rm64_imm32,
};

static int (*openasm_inst_movzx[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG16)] = openasm_movzx_r16_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG16)] = openasm_movzx_r16_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG32)] = openasm_movzx_r32_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG32)] = openasm_movzx_r32_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG32)] = openasm_movzx_r32_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG32)] = openasm_movzx_r32_rm16,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG64)] = openasm_movzx_r64_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG64)] = openasm_movzx_r64_rm16,
};

static int (*openasm_inst_movsx[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG16)] = openasm_movsx_r16_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG16)] = openasm_movsx_r16_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG32)] = openasm_movsx_r32_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY8, OPENASM_OP_REG32)] = openasm_movsx_r32_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG32)] = openasm_movsx_r32_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG32)] = openasm_movsx_r32_rm16,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG64)] = openasm_movsx_r64_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY16, OPENASM_OP_REG64)] = openasm_movsx_r64_rm16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG64)] = openasm_movsx_r64_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY32, OPENASM_OP_REG64)] = openasm_movsx_r64_rm32,
};

static int (*openasm_inst_lea[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_MEMORY64, OPENASM_OP_REG64)] = openasm_lea_r64_m64,
};

static int (*openasm_inst_pop[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_MEMORY64)] = openasm_pop_rm64,
    [OPENASM_CONS1(OPENASM_OP_REG64)] = openasm_pop_r64,
};

static int (*openasm_inst_push[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_MEMORY64)] = openasm_push_rm64,
    [OPENASM_CONS1(OPENASM_OP_REG64)] = openasm_push_r64,
    [OPENASM_CONS1(OPENASM_OP_IMM8)] = openasm_push_imm8,
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_push_imm32,
};

static int (*openasm_inst_call[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_call_rel32,
};

static int (*openasm_inst_syscall[])(OpenasmBuffer *, OpenasmOperand *) = {
    openasm_syscall,
};

static int (*openasm_inst_ret[])(OpenasmBuffer *, OpenasmOperand *) = {
    openasm_ret_near,
};

static int (*openasm_inst_jmp[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_jmp_near,
};

static int (*openasm_inst_jc[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_jc_near,
};

static int (*openasm_inst_je[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_je_near,
};

static int (*openasm_inst_jne[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_jne_near,
};

static int (*openasm_inst_jl[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_jl_near,
};

static int (*openasm_inst_jle[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_jle_near,
};

static int (*openasm_inst_jg[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_jg_near,
};

static int (*openasm_inst_jge[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_jge_near,
};

struct OpenasmEntry openasm_inst[] = {
    { "add", openasm_inst_add },
    { "adc", openasm_inst_adc },
    { "and", openasm_inst_and },
    { "or", openasm_inst_or },
    { "xor", openasm_inst_xor },
    { "sub", openasm_inst_sub },
    { "cmp", openasm_inst_cmp },
    { "mul", openasm_inst_mul },
    { "imul", openasm_inst_imul },
    { "div", openasm_inst_div },
    { "idiv", openasm_inst_idiv },
    { "mov", openasm_inst_mov },
    { "movzx", openasm_inst_movzx },
    { "movsx", openasm_inst_movsx },
    { "lea", openasm_inst_lea },
    { "pop", openasm_inst_pop },
    { "push", openasm_inst_push },
    { "call", openasm_inst_call },
    { "syscall", openasm_inst_syscall },
    { "ret", openasm_inst_ret },
    { "jmp", openasm_inst_jmp },
    { "jc", openasm_inst_jc },
    { "jz", openasm_inst_je },
    { "jnz", openasm_inst_jne },
    { "je", openasm_inst_je },
    { "jne", openasm_inst_jne },
    { "jl", openasm_inst_jl },
    { "jle", openasm_inst_jle },
    { "jg", openasm_inst_jg },
    { "jge", openasm_inst_jge },
    { 0 },
};

struct OpenasmRegister openasm_register[] = {
    { "al", OPENASM_R8_AL, 8, 0 },
    { "cl", OPENASM_R8_CL, 8, 0 },
    { "dl", OPENASM_R8_DL, 8, 0 },
    { "bl", OPENASM_R8_BL, 8, 0 },
    { "ah", OPENASM_R8_AH, 8, 0 },
    { "ch", OPENASM_R8_CH, 8, 0 },
    { "dh", OPENASM_R8_DH, 8, 0 },
    { "bh", OPENASM_R8_BH, 8, 0 },
    { "r8b", OPENASM_R64_R8, 8, 1 },
    { "r9b", OPENASM_R64_R9, 8, 1 },
    { "r10b", OPENASM_R64_R10, 8, 1 },
    { "r11b", OPENASM_R64_R11, 8, 1 },
    { "r12b", OPENASM_R64_R12, 8, 1 },
    { "r13b", OPENASM_R64_R13, 8, 1 },
    { "r14b", OPENASM_R64_R14, 8, 1 },
    { "r15b", OPENASM_R64_R15, 8, 1 },
    { "ax", OPENASM_R16_AX, 16, 0 },
    { "cx", OPENASM_R16_CX, 16, 0 },
    { "dx", OPENASM_R16_DX, 16, 0 },
    { "bx", OPENASM_R16_BX, 16, 0 },
    { "sp", OPENASM_R16_SP, 16, 0 },
    { "bp", OPENASM_R16_BP, 16, 0 },
    { "si", OPENASM_R16_SI, 16, 0 },
    { "di", OPENASM_R16_DI, 16, 0 },
    { "r8w", OPENASM_R64_R8, 16, 1 },
    { "r9w", OPENASM_R64_R9, 16, 1 },
    { "r10w", OPENASM_R64_R10, 16, 1 },
    { "r11w", OPENASM_R64_R11, 16, 1 },
    { "r12w", OPENASM_R64_R12, 16, 1 },
    { "r13w", OPENASM_R64_R13, 16, 1 },
    { "r14w", OPENASM_R64_R14, 16, 1 },
    { "r15w", OPENASM_R64_R15, 16, 1 },
    { "eax", OPENASM_R32_EAX, 32, 0 },
    { "ecx", OPENASM_R32_ECX, 32, 0 },
    { "edx", OPENASM_R32_EDX, 32, 0 },
    { "ebx", OPENASM_R32_EBX, 32, 0 },
    { "esp", OPENASM_R32_ESP, 32, 0 },
    { "ebp", OPENASM_R32_EBP, 32, 0 },
    { "esi", OPENASM_R32_ESI, 32, 0 },
    { "edi", OPENASM_R32_EDI, 32, 0 },
    { "r8d", OPENASM_R64_R8, 32, 1 },
    { "r9d", OPENASM_R64_R9, 32, 1 },
    { "r10d", OPENASM_R64_R10, 32, 1 },
    { "r11d", OPENASM_R64_R11, 32, 1 },
    { "r12d", OPENASM_R64_R12, 32, 1 },
    { "r13d", OPENASM_R64_R13, 32, 1 },
    { "r14d", OPENASM_R64_R14, 32, 1 },
    { "r15d", OPENASM_R64_R15, 32, 1 },
    { "mm0", OPENASM_MM_MM0, 32, 0 },
    { "mm1", OPENASM_MM_MM1, 32, 0 },
    { "mm2", OPENASM_MM_MM2, 32, 0 },
    { "mm3", OPENASM_MM_MM3, 32, 0 },
    { "mm4", OPENASM_MM_MM4, 32, 0 },
    { "mm5", OPENASM_MM_MM5, 32, 0 },
    { "mm6", OPENASM_MM_MM6, 32, 0 },
    { "mm7", OPENASM_MM_MM7, 32, 0 },
    { "xmm0", OPENASM_XMM_XMM0, 32, 0 },
    { "xmm1", OPENASM_XMM_XMM1, 32, 0 },
    { "xmm2", OPENASM_XMM_XMM2, 32, 0 },
    { "xmm3", OPENASM_XMM_XMM3, 32, 0 },
    { "xmm4", OPENASM_XMM_XMM4, 32, 0 },
    { "xmm5", OPENASM_XMM_XMM5, 32, 0 },
    { "xmm6", OPENASM_XMM_XMM6, 32, 0 },
    { "xmm7", OPENASM_XMM_XMM7, 32, 0 },
    { "rax", OPENASM_R64_RAX, 64, 0 },
    { "rcx", OPENASM_R64_RCX, 64, 0 },
    { "rdx", OPENASM_R64_RDX, 64, 0 },
    { "rbx", OPENASM_R64_RBX, 64, 0 },
    { "rsp", OPENASM_R64_RSP, 64, 0 },
    { "rbp", OPENASM_R64_RBP, 64, 0 },
    { "rsi", OPENASM_R64_RSI, 64, 0 },
    { "rdi", OPENASM_R64_RDI, 64, 0 },
    { "r8", OPENASM_R64_R8, 64, 1 },
    { "r9", OPENASM_R64_R9, 64, 1 },
    { "r10", OPENASM_R64_R10, 64, 1 },
    { "r11", OPENASM_R64_R11, 64, 1 },
    { "r12", OPENASM_R64_R12, 64, 1 },
    { "r13", OPENASM_R64_R13, 64, 1 },
    { "r14", OPENASM_R64_R14, 64, 1 },
    { "r15", OPENASM_R64_R15, 64, 1 },
    { 0 },
};

OpenasmProperty openasm_properties1[] = {
    // [0x00; 0x07]
    { "add", 1, 0, 1, 0 },
    { "add", 1, 0, 1, 0 },
    { "add", 1, 0, 1, 0 },
    { "add", 1, 0, 1, 0 },
    { "add", 1, 0, 1, 1 },
    { "add", 1, 0, 1, 1 },
    { "push", 1, 0, 0, 0 },
    { "pop", 1, 0, 0, 0 },
    // [0x08; 0x0f]
    { "adc", 1, 0, 1, 0 },
    { "adc", 1, 0, 1, 0 },
    { "adc", 1, 0, 1, 0 },
    { "adc", 1, 0, 1, 0 },
    { "adc", 1, 0, 1, 1 },
    { "adc", 1, 0, 1, 1 },
    { "push", 1, 0, 0, 0 },
    { "pop", 1, 0, 0, 0 },
    // [0x10; 0x17]
    { "and", 1, 0, 1, 0 },
    { "and", 1, 0, 1, 0 },
    { "and", 1, 0, 1, 0 },
    { "and", 1, 0, 1, 0 },
    { "and", 1, 0, 1, 1 },
    { "and", 1, 0, 1, 1 },
    { 0 },
    { "daa", 1, 0, 0, 0 },
    // [0x18; 0x1f]
    { "xor", 1, 0, 1, 0 },
    { "xor", 1, 0, 1, 0 },
    { "xor", 1, 0, 1, 0 },
    { "xor", 1, 0, 1, 0 },
    { "xor", 1, 0, 1, 1 },
    { "xor", 1, 0, 1, 1 },
    { 0 },
    { "aaa", 1, 0, 0, 0 },
};

OpenasmProperty openasm_properties2[] = {
    { 0 },
};
OpenasmProperty openasm_properties3a[] = {
    { 0 },
};
OpenasmProperty openasm_properties3b[] = {
    { 0 },
};
