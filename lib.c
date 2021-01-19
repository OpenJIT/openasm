#include "include/openasm.h"

#define DEFAULT_SECTION_CAP ((size_t) 32)
#define DEFAULT_SYMTABLE_CAP ((size_t) 128)

void openasm_buffer(OpenasmBuffer *buf) {
    size_t cap = DEFAULT_SECTION_CAP;
    buf->cap = cap;
    buf->len = 0;
    buf->sections = malloc(cap * sizeof(struct OpenasmSection));

    openasm_section(buf, "data");
    openasm_section(buf, "bss");
    openasm_section(buf, "text");

    buf->sym = 0;
    cap = DEFAULT_SYMTABLE_CAP;
    buf->symtable.cap = cap;
    buf->symtable.len = 0;
    buf->symtable.table = malloc(cap * sizeof(struct OpenasmSymbol));
    
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

uint8_t *openasm_opcode2(OpenasmBuffer *buf, uint8_t *ptr, uint16_t op) {
    openasm_assert(!buf->has_opcode);

    buf->has_opcode = 2;
    buf->size += 2;
    ptr[0] = op & 0xff;
    ptr[1] = (op >> 8) & 0xff;

    return ptr + 2;
}

uint8_t *openasm_opcode3(OpenasmBuffer *buf, uint8_t *ptr, uint32_t op) {
    openasm_assert(!buf->has_opcode);

    buf->has_opcode = 3;
    buf->size += 3;
    ptr[0] = op & 0xff;
    ptr[1] = (op >> 8) & 0xff;
    ptr[2] = (op >> 16) & 0xff;

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

int openasm_addlike_al_imm8(OpenasmBuffer *buf, OpenasmOperand *args, uint32_t opcode, uint32_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, opcode);

    // NOTE: should we maybe validate that args[0] is actually al?
    /* uint32_t target_reg = -1; */
    /* const char *target = args[0].reg; */
    uint8_t source = args[1].imm;
    /* for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) { */
    /*     if (strcmp(target, reg->key) == 0 && reg->bits == 64) { */
    /*         target_reg = reg->val; */
    /*         break; */
    /*     } */
    /* } */

    /* if (target_reg == (uint32_t) -1) { */
    /*     fprintf(stderr, "error: invalid target register: \"%s\"\n", target); */
    /*     return 1; */
    /* } */
    
    inst = openasm_imm8(buf, inst, source);
    return openasm_build(buf, start, inst);
}

int openasm_addlike_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *args, uint32_t opcode, uint32_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, opcode);

    // NOTE: should we maybe validate that args[0] is actually ax?
    /* uint32_t target_reg = -1; */
    /* const char *target = args[0].reg; */
    uint16_t source = args[1].imm;
    /* for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) { */
    /*     if (strcmp(target, reg->key) == 0 && reg->bits == 64) { */
    /*         target_reg = reg->val; */
    /*         break; */
    /*     } */
    /* } */

    /* if (target_reg == (uint32_t) -1) { */
    /*     fprintf(stderr, "error: invalid target register: \"%s\"\n", target); */
    /*     return 1; */
    /* } */
    
    inst = openasm_imm16(buf, inst, source);
    return openasm_build(buf, start, inst);
}

int openasm_addlike_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *args, uint32_t opcode, uint32_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, opcode);

    // NOTE: should we maybe validate that args[0] is actually eax?
    /* uint32_t target_reg = -1; */
    /* const char *target = args[0].reg; */
    uint32_t source = args[1].imm;
    /* for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) { */
    /*     if (strcmp(target, reg->key) == 0 && reg->bits == 64) { */
    /*         target_reg = reg->val; */
    /*         break; */
    /*     } */
    /* } */

    /* if (target_reg == (uint32_t) -1) { */
    /*     fprintf(stderr, "error: invalid target register: \"%s\"\n", target); */
    /*     return 1; */
    /* } */
    
    inst = openasm_imm32(buf, inst, source);
    return openasm_build(buf, start, inst);
}

int openasm_addsxlike_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *args, uint32_t opcode, uint32_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW);
    inst = openasm_opcode1(buf, inst, opcode);

    // NOTE: should we maybe validate that args[0] is actually rax?
    /* uint32_t target_reg = -1; */
    /* const char *target = args[0].reg; */
    uint32_t source = args[1].imm;
    /* for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) { */
    /*     if (strcmp(target, reg->key) == 0 && reg->bits == 64) { */
    /*         target_reg = reg->val; */
    /*         break; */
    /*     } */
    /* } */

    /* if (target_reg == (uint32_t) -1) { */
    /*     fprintf(stderr, "error: invalid target register: \"%s\"\n", target); */
    /*     return 1; */
    /* } */
    
    inst = openasm_imm32(buf, inst, source);
    return openasm_build(buf, start, inst);
}

// TODO: accept m64 operands
int openasm_addsxlike_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *args, uint32_t opcode, uint32_t regval) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW);
    inst = openasm_opcode1(buf, inst, opcode);

    uint32_t target_reg = -1;
    const char *target = args[0].reg;
    uint32_t source = args[1].imm;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 64) {
            target_reg = reg->val;
            break;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, regval, target_reg));
    inst = openasm_imm32(buf, inst, source);
    return openasm_build(buf, start, inst);
}

// TODO: accept m64 operands
int openasm_addlike_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *args, uint32_t opcode, uint32_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW);
    inst = openasm_opcode1(buf, inst, opcode);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 64) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 64) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, source_reg, target_reg));
    return openasm_build(buf, start, inst);
}

// TODO: acept m8 operands
int openasm_addlike_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *args, uint32_t opcode, uint32_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REX0);
    inst = openasm_opcode1(buf, inst, opcode);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 8) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 8) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, target_reg, source_reg));
    return openasm_build(buf, start, inst);
}

// TODO: accept m16 operands
int openasm_addlike_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *args, uint32_t opcode, uint32_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    inst = openasm_opcode1(buf, inst, opcode);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 16) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 16) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, target_reg, source_reg));
    return openasm_build(buf, start, inst);
}

// TODO: accept m32 operands
int openasm_addlike_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *args, uint32_t opcode, uint32_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, opcode);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 32) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 32) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, target_reg, source_reg));
    return openasm_build(buf, start, inst);
}

// TODO: accept m64 operands
int openasm_addlike_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *args, uint32_t opcode, uint32_t regval) {
    (void) regval;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW);
    inst = openasm_opcode1(buf, inst, opcode);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 64) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 64) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, target_reg, source_reg));
    return openasm_build(buf, start, inst);
}

int openasm_add_al_imm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_al_imm8(buf, args, OPENASM_ADD_AL_IMM8, 0);
}

int openasm_add_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_ax_imm16(buf, args, OPENASM_ADD_AX_IMM16, 0);
}

int openasm_add_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_eax_imm32(buf, args, OPENASM_ADD_EAX_IMM32, 0);
}

int openasm_addsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rax_imm32(buf, args, OPENASM_ADDSX_RAX_IMM32, 0);
}

int openasm_addsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rm64_imm32(buf, args, OPENASM_ADDSX_RM64_IMM32, 0);
}

int openasm_add_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_rm64_r64(buf, args, OPENASM_ADD_RM64_R64, 0);
}

int openasm_add_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r8_rm8(buf, args, OPENASM_ADD_R8_RM8, 0);
}

int openasm_add_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r16_rm16(buf, args, OPENASM_ADD_R16_RM16, 0);
}

int openasm_add_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r32_rm32(buf, args, OPENASM_ADD_R32_RM32, 0);
}

int openasm_add_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r64_rm64(buf, args, OPENASM_ADD_R64_RM64, 0);
}

int openasm_adc_al_imm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_al_imm8(buf, args, OPENASM_ADC_AL_IMM8, 2);
}

int openasm_adc_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_ax_imm16(buf, args, OPENASM_ADC_AX_IMM16, 2);
}

int openasm_adc_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_eax_imm32(buf, args, OPENASM_ADC_EAX_IMM32, 2);
}

int openasm_adcsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rax_imm32(buf, args, OPENASM_ADCSX_RAX_IMM32, 2);
}

int openasm_adcsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rm64_imm32(buf, args, OPENASM_ADCSX_RM64_IMM32, 2);
}

int openasm_adc_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_rm64_r64(buf, args, OPENASM_ADC_RM64_R64, 2);
}

int openasm_adc_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r8_rm8(buf, args, OPENASM_ADC_R8_RM8, 2);
}

int openasm_adc_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r16_rm16(buf, args, OPENASM_ADC_R16_RM16, 2);
}

int openasm_adc_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r32_rm32(buf, args, OPENASM_ADC_R32_RM32, 2);
}

int openasm_adc_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r64_rm64(buf, args, OPENASM_ADC_R64_RM64, 2);
}

int openasm_and_al_imm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_al_imm8(buf, args, OPENASM_AND_AL_IMM8, 4);
}

int openasm_and_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_ax_imm16(buf, args, OPENASM_AND_AX_IMM16, 4);
}

int openasm_and_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_eax_imm32(buf, args, OPENASM_AND_EAX_IMM32, 4);
}

int openasm_andsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rax_imm32(buf, args, OPENASM_ANDSX_RAX_IMM32, 4);
}

int openasm_andsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rm64_imm32(buf, args, OPENASM_ANDSX_RM64_IMM32, 4);
}

int openasm_and_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_rm64_r64(buf, args, OPENASM_AND_RM64_R64, 4);
}

int openasm_and_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r8_rm8(buf, args, OPENASM_AND_R8_RM8, 4);
}

int openasm_and_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r16_rm16(buf, args, OPENASM_AND_R16_RM16, 4);
}

int openasm_and_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r32_rm32(buf, args, OPENASM_AND_R32_RM32, 4);
}

int openasm_and_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r64_rm64(buf, args, OPENASM_AND_R64_RM64, 4);
}

int openasm_or_al_imm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_al_imm8(buf, args, OPENASM_XOR_AL_IMM8, 1);
}

int openasm_or_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_ax_imm16(buf, args, OPENASM_OR_AX_IMM16, 1);
}

int openasm_or_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_eax_imm32(buf, args, OPENASM_OR_EAX_IMM32, 1);
}

int openasm_orsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rax_imm32(buf, args, OPENASM_ORSX_RAX_IMM32, 1);
}

int openasm_orsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rm64_imm32(buf, args, OPENASM_ORSX_RM64_IMM32, 1);
}

int openasm_or_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_rm64_r64(buf, args, OPENASM_OR_RM64_R64, 1);
}

int openasm_or_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r8_rm8(buf, args, OPENASM_OR_R8_RM8, 1);
}

int openasm_or_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r16_rm16(buf, args, OPENASM_OR_R16_RM16, 1);
}

int openasm_or_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r32_rm32(buf, args, OPENASM_OR_R32_RM32, 1);
}

int openasm_or_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r64_rm64(buf, args, OPENASM_OR_R64_RM64, 1);
}

int openasm_xor_al_imm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_al_imm8(buf, args, OPENASM_XOR_AL_IMM8, 6);
}

int openasm_xor_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_ax_imm16(buf, args, OPENASM_XOR_AX_IMM16, 6);
}

int openasm_xor_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_eax_imm32(buf, args, OPENASM_XOR_EAX_IMM32, 6);
}

int openasm_xorsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rax_imm32(buf, args, OPENASM_XORSX_RAX_IMM32, 6);
}

int openasm_xorsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rm64_imm32(buf, args, OPENASM_XORSX_RM64_IMM32, 6);
}

int openasm_xor_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_rm64_r64(buf, args, OPENASM_XOR_RM64_R64, 6);
}

int openasm_xor_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r8_rm8(buf, args, OPENASM_XOR_R8_RM8, 6);
}

int openasm_xor_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r16_rm16(buf, args, OPENASM_XOR_R16_RM16, 6);
}

int openasm_xor_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r32_rm32(buf, args, OPENASM_XOR_R32_RM32, 6);
}

int openasm_xor_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r64_rm64(buf, args, OPENASM_XOR_R64_RM64, 6);
}

int openasm_sub_al_imm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_al_imm8(buf, args, OPENASM_SUB_AL_IMM8, 5);
}

int openasm_sub_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_ax_imm16(buf, args, OPENASM_SUB_AX_IMM16, 5);
}

int openasm_sub_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_eax_imm32(buf, args, OPENASM_SUB_EAX_IMM32, 5);
}

int openasm_subsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rax_imm32(buf, args, OPENASM_SUBSX_RAX_IMM32, 5);
}

int openasm_subsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addsxlike_rm64_imm32(buf, args, OPENASM_SUBSX_RM64_IMM32, 5);
}

int openasm_sub_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_rm64_r64(buf, args, OPENASM_SUB_RM64_R64, 5);
}

int openasm_sub_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r8_rm8(buf, args, OPENASM_SUB_R8_RM8, 5);
}

int openasm_sub_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r16_rm16(buf, args, OPENASM_SUB_R16_RM16, 5);
}

int openasm_sub_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r32_rm32(buf, args, OPENASM_SUB_R32_RM32, 5);
}

int openasm_sub_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *args) {
    return openasm_addlike_r64_rm64(buf, args, OPENASM_SUB_R64_RM64, 5);
}

// TODO: accept rm8 operands
int openasm_mov_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM8_R8);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 8) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 8) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, source_reg, target_reg));
    return openasm_build(buf, start, inst);
}

// TODO: accept rm16 operands
int openasm_mov_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM16_R16);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 16) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 16) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, source_reg, target_reg));
    return openasm_build(buf, start, inst);
}

// TODO: accept rm32 operands
int openasm_mov_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM32_R32);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 32) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 32) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, source_reg, target_reg));
    return openasm_build(buf, start, inst);
}

// TODO: accept rm64 operands
int openasm_mov_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM64_R64);

    uint32_t source_reg = -1;
    const char *source = args[1].reg;

    if (args[0].tag == OPENASM_OP_MEMORY) {
        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
            if (strcmp(source, reg->key) == 0 && reg->bits == 64) {
                source_reg = reg->val;
                break;
            }
        }

        if (source_reg == (uint32_t) -1) {
            fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
            return 1;
        }

        uint32_t base_reg = -1;
        const char *base = args[0].mem.base;

        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
            if (strcmp(base, reg->key) == 0 && reg->bits == 64) {
                base_reg = reg->val;
                break;
            }
        }

        if (base_reg == (uint32_t) -1) {
            fprintf(stderr, "error: invalid base register: \"%s\"\n", base);
            return 1;
        }

        uint32_t index_reg = -1;
        const char *index = args[0].mem.index;

        if (index) {
            for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
                if (strcmp(index, reg->key) == 0 && reg->bits == 64) {
                    index_reg = reg->val;
                    break;
                }
            }

            if (index_reg == (uint32_t) -1) {
                fprintf(stderr, "error: invalid index register: \"%s\"\n", index);
                return 1;
            }
        }

        if (index) {
            uint32_t scale = 0;
            switch (args[0].mem.scale) {
            case 1:
                scale = OPENASM_SCALE_1;
                break;
            case 2:
                scale = OPENASM_SCALE_2;
                break;
            case 4:
                scale = OPENASM_SCALE_4;
                break;
            case 8:
                scale = OPENASM_SCALE_8;
                break;
            default:
                fprintf(stderr, "error: invalid scale argument: %lu\n", args[0].mem.scale);
                return 1;
            }
            // TODO: special case where mod = 0x0, r/m = 0x5 is disp32 (and not rbp!)
            if (args[0].mem.disp) {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB_DISP32, source_reg, OPENASM_MODRM_RM_EA_SIB));
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg));
                inst = openasm_disp32(buf, inst, (int32_t) args[0].mem.disp);
            } else {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB, source_reg, OPENASM_MODRM_RM_EA_SIB));
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg));
            }
        } else {
            if (args[0].mem.disp) {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM_DISP32, source_reg, base_reg));
                inst = openasm_disp32(buf, inst, (int32_t) args[0].mem.disp);
            } else {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM, source_reg, base_reg));
            }
        }
        return openasm_build(buf, start, inst);
    } else {
        uint32_t target_reg = -1;
        const char *target = args[0].reg;
        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
            if (strcmp(target, reg->key) == 0 && reg->bits == 64) {
                target_reg = reg->val;
            }
            if (strcmp(source, reg->key) == 0 && reg->bits == 64) {
                source_reg = reg->val;
            }
        }

        if (target_reg == (uint32_t) -1) {
            fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
            return 1;
        }

        if (source_reg == (uint32_t) -1) {
            fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
            return 1;
        }
    
        inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, source_reg, target_reg));
        return openasm_build(buf, start, inst);
    }
}

// TODO: accept rm8 operands
int openasm_mov_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REX0);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_R8_RM8);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 8) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 8) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, target_reg, source_reg));
    return openasm_build(buf, start, inst);
}

// TODO: accept rm16 operands
int openasm_mov_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_R16_RM16);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 16) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 16) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, target_reg, source_reg));
    return openasm_build(buf, start, inst);
}

// TODO: accept rm32 operands
int openasm_mov_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_MOV_R32_RM32);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 32) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 32) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, target_reg, source_reg));
    return openasm_build(buf, start, inst);
}

// TODO: accept m64 operands
int openasm_mov_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW);
    inst = openasm_opcode1(buf, inst, OPENASM_MOV_R64_RM64);

    uint32_t target_reg = -1;
    uint32_t source_reg = -1;
    const char *target = args[0].reg;
    const char *source = args[1].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0 && reg->bits == 64) {
            target_reg = reg->val;
        }
        if (strcmp(source, reg->key) == 0 && reg->bits == 64) {
            source_reg = reg->val;
        }
    }

    if (target_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
        return 1;
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, target_reg, source_reg));
    return openasm_build(buf, start, inst);
}

int openasm_mov_r16_imm16(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;
    
    inst = openasm_legacy_prefix(buf, inst, OPENASM_PREFIX3_OP_SIZE);

    const char *target = args[0].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0) {
            inst = openasm_opcode1(buf, inst, OPENASM_MOV_R16_IMM16 + reg->val);
            inst = openasm_imm16(buf, inst, args[1].imm);
            return openasm_build(buf, start, inst);
        }
    }
    
    fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
    return 1;
}

int openasm_mov_r32_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    const char *target = args[0].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0) {
            inst = openasm_opcode1(buf, inst, OPENASM_MOV_R32_IMM32 + reg->val);
            inst = openasm_imm32(buf, inst, args[1].imm);
            return openasm_build(buf, start, inst);
        }
    }
    
    fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
    return 1;
}

int openasm_mov_r64_imm64(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW);

    const char *target = args[0].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0) {
            inst = openasm_opcode1(buf, inst, OPENASM_MOV_R64_IMM64 + reg->val);
            inst = openasm_imm64(buf, inst, args[1].imm);
            return openasm_build(buf, start, inst);
        }
    }
    
    fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
    return 1;
}

// TODO: accept m64 operands
int openasm_mov_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_MOV_RM32_IMM32);

    const char *target = args[0].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(target, reg->key) == 0) {
            inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, 0, reg->val));
            inst = openasm_imm32(buf, inst, args[1].imm);
            return openasm_build(buf, start, inst);
        }
    }
    
    fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
    return 1;
}

// TODO: accept m64 operands
int openasm_movsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_rex_prefix(buf, inst, OPENASM_PREFIX64_REXW);
    inst = openasm_opcode1(buf, inst, OPENASM_MOVSX_RM64_IMM32);

    if (args[0].tag == OPENASM_OP_MEMORY) {
        uint32_t base_reg = -1;
        const char *base = args[0].mem.base;

        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
            if (strcmp(base, reg->key) == 0 && reg->bits == 64) {
                base_reg = reg->val;
                break;
            }
        }

        if (base_reg == (uint32_t) -1) {
            fprintf(stderr, "error: invalid base register: \"%s\"\n", base);
            return 1;
        }

        uint32_t index_reg = -1;
        const char *index = args[0].mem.index;

        if (index) {
            for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
                if (strcmp(index, reg->key) == 0 && reg->bits == 64) {
                    index_reg = reg->val;
                    break;
                }
            }

            if (index_reg == (uint32_t) -1) {
                fprintf(stderr, "error: invalid index register: \"%s\"\n", index);
                return 1;
            }
        }

        if (index) {
            uint32_t scale = 0;
            switch (args[0].mem.scale) {
            case 1:
                scale = OPENASM_SCALE_1;
                break;
            case 2:
                scale = OPENASM_SCALE_2;
                break;
            case 4:
                scale = OPENASM_SCALE_4;
                break;
            case 8:
                scale = OPENASM_SCALE_8;
                break;
            default:
                fprintf(stderr, "error: invalid scale argument: %lu\n", args[0].mem.scale);
                return 1;
            }
            // TODO: special case where mod = 0x0, r/m = 0x5 is disp32 (and not rbp!)
            if (args[0].mem.disp) {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB_DISP32, 0, OPENASM_MODRM_RM_EA_SIB));
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg));
                inst = openasm_disp32(buf, inst, (int32_t) args[0].mem.disp);
            } else {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB, 0, OPENASM_MODRM_RM_EA_SIB));
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg));
            }
        } else {
            if (args[0].mem.disp) {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM_DISP32, 0, base_reg));
                inst = openasm_disp32(buf, inst, (int32_t) args[0].mem.disp);
            } else {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM, 0, base_reg));
            }
        }
        inst = openasm_imm32(buf, inst, args[1].imm);
        return openasm_build(buf, start, inst);
    } else {
        uint32_t target_reg = -1;
        const char *target = args[0].reg;
        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
            if (strcmp(target, reg->key) == 0 && reg->bits == 64) {
                target_reg = reg->val;
                break;
            }
        }

        if (target_reg == (uint32_t) -1) {
            fprintf(stderr, "error: invalid target register: \"%s\"\n", target);
            return 1;
        }
    
        inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, 0, target_reg));
        inst = openasm_imm32(buf, inst, args[1].imm);
        return openasm_build(buf, start, inst);
    }
}

int openasm_pop_rm64(OpenasmBuffer *buf, OpenasmOperand *args) {
    (void) args;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_POP_RM64);
    if (args[0].tag == OPENASM_OP_MEMORY) {
        uint32_t base_reg = -1;
        const char *base = args[0].mem.base;

        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
            if (strcmp(base, reg->key) == 0 && reg->bits == 64) {
                base_reg = reg->val;
                break;
            }
        }

        if (base_reg == (uint32_t) -1) {
            fprintf(stderr, "error: invalid base register: \"%s\"\n", base);
            return 1;
        }

        uint32_t index_reg = -1;
        const char *index = args[0].mem.index;

        if (index) {
            for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
                if (strcmp(index, reg->key) == 0 && reg->bits == 64) {
                    index_reg = reg->val;
                    break;
                }
            }

            if (index_reg == (uint32_t) -1) {
                fprintf(stderr, "error: invalid index register: \"%s\"\n", index);
                return 1;
            }
        }

        if (index) {
            uint32_t scale = 0;
            switch (args[0].mem.scale) {
            case 1:
                scale = OPENASM_SCALE_1;
                break;
            case 2:
                scale = OPENASM_SCALE_2;
                break;
            case 4:
                scale = OPENASM_SCALE_4;
                break;
            case 8:
                scale = OPENASM_SCALE_8;
                break;
            default:
                fprintf(stderr, "error: invalid scale argument: %lu\n", args[0].mem.scale);
                return 1;
            }
            // TODO: special case where mod = 0x0, r/m = 0x5 is disp32 (and not rbp!)
            if (args[0].mem.disp) {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB_DISP32, 6, OPENASM_MODRM_RM_EA_SIB));
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg));
                inst = openasm_disp32(buf, inst, (int32_t) args[0].mem.disp);
            } else {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB, 6, OPENASM_MODRM_RM_EA_SIB));
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg));
            }
        } else {
            if (args[0].mem.disp) {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM_DISP32, 6, base_reg));
                inst = openasm_disp32(buf, inst, (int32_t) args[0].mem.disp);
            } else {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM, 6, base_reg));
            }
        }
        return openasm_build(buf, start, inst);
    } else {
        uint32_t source_reg = -1;
        const char *source = args[0].reg;
        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
            if (strcmp(source, reg->key) == 0 && reg->bits == 64) {
                source_reg = reg->val;
                break;
            }
        }

        if (source_reg == (uint32_t) -1) {
            fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
            return 1;
        }
    
        inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, 6, source_reg));
        return openasm_build(buf, start, inst);
    }
}

int openasm_pop_r64(OpenasmBuffer *buf, OpenasmOperand *args) {
    (void) args;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    uint32_t source_reg = -1;
    const char *source = args[0].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(source, reg->key) == 0 && reg->bits == 64) {
            source_reg = reg->val;
            break;
        }
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_opcode1(buf, inst, OPENASM_POP_R64 + source_reg);
    
    return openasm_build(buf, start, inst);
}

int openasm_push_rm64(OpenasmBuffer *buf, OpenasmOperand *args) {
    (void) args;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_PUSH_RM64);
    if (args[0].tag == OPENASM_OP_MEMORY) {
        uint32_t base_reg = -1;
        const char *base = args[0].mem.base;

        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
            if (strcmp(base, reg->key) == 0 && reg->bits == 64) {
                base_reg = reg->val;
                break;
            }
        }

        if (base_reg == (uint32_t) -1) {
            fprintf(stderr, "error: invalid base register: \"%s\"\n", base);
            return 1;
        }

        uint32_t index_reg = -1;
        const char *index = args[0].mem.index;

        if (index) {
            for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
                if (strcmp(index, reg->key) == 0 && reg->bits == 64) {
                    index_reg = reg->val;
                    break;
                }
            }

            if (index_reg == (uint32_t) -1) {
                fprintf(stderr, "error: invalid index register: \"%s\"\n", index);
                return 1;
            }
        }

        if (index) {
            uint32_t scale = 0;
            switch (args[0].mem.scale) {
            case 1:
                scale = OPENASM_SCALE_1;
                break;
            case 2:
                scale = OPENASM_SCALE_2;
                break;
            case 4:
                scale = OPENASM_SCALE_4;
                break;
            case 8:
                scale = OPENASM_SCALE_8;
                break;
            default:
                fprintf(stderr, "error: invalid scale argument: %lu\n", args[0].mem.scale);
                return 1;
            }
            // TODO: special case where mod = 0x0, r/m = 0x5 is disp32 (and not rbp!)
            if (args[0].mem.disp) {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB_DISP32, 6, OPENASM_MODRM_RM_EA_SIB));
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg));
                inst = openasm_disp32(buf, inst, (int32_t) args[0].mem.disp);
            } else {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_SIB, 6, OPENASM_MODRM_RM_EA_SIB));
                inst = openasm_sib(buf, inst, OPENASM_SIB(scale, index_reg, base_reg));
            }
        } else {
            if (args[0].mem.disp) {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM_DISP32, 6, base_reg));
                inst = openasm_disp32(buf, inst, (int32_t) args[0].mem.disp);
            } else {
                inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_MEM, 6, base_reg));
            }
        }
        return openasm_build(buf, start, inst);
    } else {
        uint32_t source_reg = -1;
        const char *source = args[0].reg;
        for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
            if (strcmp(source, reg->key) == 0 && reg->bits == 64) {
                source_reg = reg->val;
                break;
            }
        }

        if (source_reg == (uint32_t) -1) {
            fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
            return 1;
        }
    
        inst = openasm_modrm(buf, inst, OPENASM_MODRM(OPENASM_MODRM_MOD_EA_REG, 6, source_reg));
        return openasm_build(buf, start, inst);
    }
}

int openasm_push_r64(OpenasmBuffer *buf, OpenasmOperand *args) {
    (void) args;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    uint32_t source_reg = -1;
    const char *source = args[0].reg;
    for (struct OpenasmRegister *reg = openasm_register; reg->key; reg++) {
        if (strcmp(source, reg->key) == 0 && reg->bits == 64) {
            source_reg = reg->val;
            break;
        }
    }

    if (source_reg == (uint32_t) -1) {
        fprintf(stderr, "error: invalid source register: \"%s\"\n", source);
        return 1;
    }
    
    inst = openasm_opcode1(buf, inst, OPENASM_PUSH_R64 + source_reg);
    
    return openasm_build(buf, start, inst);
}

int openasm_push_imm8(OpenasmBuffer *buf, OpenasmOperand *args) {
    (void) args;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_PUSH_IMM8);
    inst = openasm_imm8(buf, inst, args[0].imm);
    
    return openasm_build(buf, start, inst);
}

int openasm_push_imm32(OpenasmBuffer *buf, OpenasmOperand *args) {
    (void) args;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_PUSH_IMM32);
    inst = openasm_imm32(buf, inst, args[0].imm);
    
    return openasm_build(buf, start, inst);
}

// TODO: near/far modifier
int openasm_ret(OpenasmBuffer *buf, OpenasmOperand *args) {
    (void) args;
    uint8_t *start = openasm_new(buf);
    uint8_t *inst = start;

    inst = openasm_opcode1(buf, inst, OPENASM_RET_NEAR);
    
    return openasm_build(buf, start, inst);
}

static int (*openasm_inst_add[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_addsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY)] = openasm_add_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_add_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG16)] = openasm_add_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_add_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_add_r64_rm64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG8)] = openasm_add_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG16)] = openasm_add_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG32)] = openasm_add_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG64)] = openasm_add_r64_rm64,
};

static int (*openasm_inst_adc[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_adcsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY)] = openasm_adc_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_adc_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG16)] = openasm_adc_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_adc_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_adc_r64_rm64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG8)] = openasm_adc_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG16)] = openasm_adc_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG32)] = openasm_adc_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG64)] = openasm_adc_r64_rm64,
};

static int (*openasm_inst_and[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_andsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY)] = openasm_and_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_and_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG16)] = openasm_and_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_and_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_and_r64_rm64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG8)] = openasm_and_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG16)] = openasm_and_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG32)] = openasm_and_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG64)] = openasm_and_r64_rm64,
};

static int (*openasm_inst_or[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_orsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY)] = openasm_or_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_or_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG16)] = openasm_or_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_or_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_or_r64_rm64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG8)] = openasm_or_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG16)] = openasm_or_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG32)] = openasm_or_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG64)] = openasm_or_r64_rm64,
};

static int (*openasm_inst_xor[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_xorsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY)] = openasm_xor_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_xor_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG16)] = openasm_xor_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_xor_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_xor_r64_rm64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG8)] = openasm_xor_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG16)] = openasm_xor_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG32)] = openasm_xor_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG64)] = openasm_xor_r64_rm64,
};

static int (*openasm_inst_sub[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_subsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY)] = openasm_sub_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_sub_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG16)] = openasm_sub_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_sub_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_sub_r64_rm64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG8)] = openasm_sub_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG16)] = openasm_sub_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG32)] = openasm_sub_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG64)] = openasm_sub_r64_rm64,
};

static int (*openasm_inst_mov[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_MEMORY)] = openasm_mov_rm8_r8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_MEMORY)] = openasm_mov_rm16_r16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_MEMORY)] = openasm_mov_rm32_r32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_MEMORY)] = openasm_mov_rm64_r64,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG8)] = openasm_mov_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG16)] = openasm_mov_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG32)] = openasm_mov_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_MEMORY, OPENASM_OP_REG64)] = openasm_mov_r64_rm64,
    [OPENASM_CONS2(OPENASM_OP_REG8, OPENASM_OP_REG8)] = openasm_mov_r8_rm8,
    [OPENASM_CONS2(OPENASM_OP_REG16, OPENASM_OP_REG16)] = openasm_mov_r16_rm16,
    [OPENASM_CONS2(OPENASM_OP_REG32, OPENASM_OP_REG32)] = openasm_mov_r32_rm32,
    [OPENASM_CONS2(OPENASM_OP_REG64, OPENASM_OP_REG64)] = openasm_mov_r64_rm64,
    [OPENASM_CONS2(OPENASM_OP_IMM16, OPENASM_OP_REG16)] = openasm_mov_r16_imm16,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG32)] = openasm_mov_r32_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM64, OPENASM_OP_REG64)] = openasm_mov_r64_imm64,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_REG64)] = openasm_movsx_rm64_imm32,
    [OPENASM_CONS2(OPENASM_OP_IMM32, OPENASM_OP_MEMORY)] = openasm_mov_rm32_imm32,
    // NOTE: this isn't actually move from imm64 to memory, but we pretend it is
    [OPENASM_CONS2(OPENASM_OP_IMM64, OPENASM_OP_MEMORY)] = openasm_movsx_rm64_imm32,
};

static int (*openasm_inst_pop[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_MEMORY)] = openasm_pop_rm64,
    [OPENASM_CONS1(OPENASM_OP_REG64)] = openasm_pop_r64,
};

static int (*openasm_inst_push[])(OpenasmBuffer *, OpenasmOperand *) = {
    [OPENASM_CONS1(OPENASM_OP_MEMORY)] = openasm_push_rm64,
    [OPENASM_CONS1(OPENASM_OP_REG64)] = openasm_push_r64,
    [OPENASM_CONS1(OPENASM_OP_IMM32)] = openasm_push_imm32,
};

static int (*openasm_inst_ret[])(OpenasmBuffer *, OpenasmOperand *) = {
    openasm_ret,
};

struct OpenasmEntry openasm_inst[] = {
    { "add", openasm_inst_add },
    { "adc", openasm_inst_adc },
    { "and", openasm_inst_and },
    { "or", openasm_inst_or },
    { "xor", openasm_inst_xor },
    { "sub", openasm_inst_sub },
    { "mov", openasm_inst_mov },
    { "pop", openasm_inst_pop },
    { "push", openasm_inst_push },
    { "ret", openasm_inst_ret },
    { 0 },
};

struct OpenasmRegister openasm_register[] = {
    { "al", OPENASM_R8_AL, 8 },
    { "cl", OPENASM_R8_CL, 8 },
    { "dl", OPENASM_R8_DL, 8 },
    { "bl", OPENASM_R8_BL, 8 },
    { "ah", OPENASM_R8_AH, 8 },
    { "ch", OPENASM_R8_CH, 8 },
    { "dh", OPENASM_R8_DH, 8 },
    { "bh", OPENASM_R8_BH, 8 },
    { "ax", OPENASM_R16_AX, 16 },
    { "cx", OPENASM_R16_CX, 16 },
    { "dx", OPENASM_R16_DX, 16 },
    { "bx", OPENASM_R16_BX, 16 },
    { "sp", OPENASM_R16_SP, 16 },
    { "bp", OPENASM_R16_BP, 16 },
    { "si", OPENASM_R16_SI, 16 },
    { "di", OPENASM_R16_DI, 16 },
    { "eax", OPENASM_R32_EAX, 32 },
    { "ecx", OPENASM_R32_ECX, 32 },
    { "edx", OPENASM_R32_EDX, 32 },
    { "ebx", OPENASM_R32_EBX, 32 },
    { "esp", OPENASM_R32_ESP, 32 },
    { "ebp", OPENASM_R32_EBP, 32 },
    { "esi", OPENASM_R32_ESI, 32 },
    { "edi", OPENASM_R32_EDI, 32 },
    { "mm0", OPENASM_MM_MM0, 32 },
    { "mm1", OPENASM_MM_MM1, 32 },
    { "mm2", OPENASM_MM_MM2, 32 },
    { "mm3", OPENASM_MM_MM3, 32 },
    { "mm4", OPENASM_MM_MM4, 32 },
    { "mm5", OPENASM_MM_MM5, 32 },
    { "mm6", OPENASM_MM_MM6, 32 },
    { "mm7", OPENASM_MM_MM7, 32 },
    { "xmm0", OPENASM_XMM_XMM0, 32 },
    { "xmm1", OPENASM_XMM_XMM1, 32 },
    { "xmm2", OPENASM_XMM_XMM2, 32 },
    { "xmm3", OPENASM_XMM_XMM3, 32 },
    { "xmm4", OPENASM_XMM_XMM4, 32 },
    { "xmm5", OPENASM_XMM_XMM5, 32 },
    { "xmm6", OPENASM_XMM_XMM6, 32 },
    { "xmm7", OPENASM_XMM_XMM7, 32 },
    { "rax", OPENASM_R64_RAX, 64 },
    { "rcx", OPENASM_R64_RCX, 64 },
    { "rdx", OPENASM_R64_RDX, 64 },
    { "rbx", OPENASM_R64_RBX, 64 },
    { "rsp", OPENASM_R64_RSP, 64 },
    { "rbp", OPENASM_R64_RBP, 64 },
    { "rsi", OPENASM_R64_RSI, 64 },
    { "rdi", OPENASM_R64_RDI, 64 },
    { "r8", OPENASM_R64_R8, 64 },
    { "r9", OPENASM_R64_R9, 64 },
    { "r10", OPENASM_R64_R10, 64 },
    { "r11", OPENASM_R64_R11, 64 },
    { "r12", OPENASM_R64_R12, 64 },
    { "r13", OPENASM_R64_R13, 64 },
    { "r14", OPENASM_R64_R14, 64 },
    { "r15", OPENASM_R64_R15, 64 },
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
