#define OPENASM_ARCH_AARCH64 1
#include "include/openasm.h"

#define DEFAULT_SECTION_CAP ((size_t) 32)
#define DEFAULT_SYMTABLE_CAP ((size_t) 128)
#define DEFAULT_POOL_CAP ((size_t) 512)

void openasm_buffer(OpenasmBuffer *buf) {
    size_t cap = DEFAULT_SECTION_CAP;
    buf->cap = cap;
    buf->len = 0;
    buf->sections = malloc(cap * sizeof(struct OpenasmSection));

    cap = DEFAULT_POOL_CAP;
    buf->pool.gen = 0;
    buf->pool.cap = cap;
    buf->pool.len = 0;
    buf->pool.buffer = malloc(cap * sizeof(uint64_t));

    openasm_section(buf, "rodata");
    openasm_section(buf, "data");
    openasm_section(buf, "bss");
    openasm_section(buf, "text");

    buf->sym = 0;
    cap = DEFAULT_SYMTABLE_CAP;
    buf->symtable.cap = cap;
    buf->symtable.len = 0;
    buf->symtable.table = malloc(cap * sizeof(struct OpenasmSymbol));
}

void openasm_del_buffer(OpenasmBuffer *buf) {
    for (size_t i = 0; i < buf->len; i++) {
        free(buf->sections[i].buffer);
    }
    free(buf->symtable.table);
    free(buf->sections);
    free(buf->pool.buffer);
}

void openasm_write(OpenasmBuffer *buf, uint32_t instr) {
    if (buf->sections[buf->section].len + sizeof(uint32_t) >= buf->sections[buf->section].cap) {
        buf->sections[buf->section].cap *= 2;
        buf->sections[buf->section].buffer = realloc(buf->sections[buf->section].buffer, buf->sections[buf->section].cap);
    }

    uint32_t *buffer = buf->sections[buf->section].buffer;
    uint32_t *dest = buffer + buf->sections[buf->section].len;
    *dest = instr;
    ++buf->sections[buf->section].len;
}

size_t openasm_pool(OpenasmBuffer *buf, uint64_t value) {
    if (buf->pool.len + sizeof(uint64_t) >= buf->pool.cap) {
        buf->pool.cap *= 2;
        buf->pool.buffer = realloc(buf->pool.buffer, buf->pool.cap);
    }

    size_t index = buf->pool.len;

    buf->pool.buffer[buf->pool.len++] = value;

    return index;
}

void openasm_flush_pool(OpenasmBuffer *buf) {
    for (size_t i = 0; i < buf->pool.len; i++) {
        size_t llen = 40;
        char name[41];
        snprintf(name, llen, "__pool_%u_%u", buf->pool.gen, (uint32_t) i);
        name[llen] = 0;
        uint64_t addr = openasm_current_addr(buf);
        openasm_symbol(buf, buf->sections[buf->section].name, name, addr);
        openasm_data(buf, sizeof(uint64_t), buf->pool.buffer + i);
    }

    buf->pool.len = 0;
    buf->pool.gen += 1;
}

uint64_t openasm_data(OpenasmBuffer *buf, size_t len, void *ptr) {
    if (buf->sections[buf->section].len + len >= buf->sections[buf->section].cap) {
        buf->sections[buf->section].cap *= 2;
        buf->sections[buf->section].buffer = realloc(buf->sections[buf->section].buffer, buf->sections[buf->section].cap);
    }

    uint32_t *buffer = buf->sections[buf->section].buffer;
    uint32_t *dest = buffer + buf->sections[buf->section].len;
    memcpy(dest, ptr, len);
    buf->sections[buf->section].len += len;

    return (uint64_t) dest - (uint64_t) buffer;
}

uint64_t openasm_res(OpenasmBuffer *buf, size_t len) {
    if (buf->sections[buf->section].len + len >= buf->sections[buf->section].cap) {
        buf->sections[buf->section].cap *= 2;
        buf->sections[buf->section].buffer = realloc(buf->sections[buf->section].buffer, buf->sections[buf->section].cap);
    }

    uint32_t *buffer = buf->sections[buf->section].buffer;
    uint32_t *dest = buffer + buf->sections[buf->section].len;
    memset(dest, 0, len);
    buf->sections[buf->section].len += len;

    return (uint64_t) dest - (uint64_t) buffer;
}

#define OPENASM_SYMBOL(mask, shift) \
    do { \
        if (buf->sym) { \
            buf->symtable.table[buf->symtable.len - 1].offset = buf->sections[buf->section].len * sizeof(uint32_t); \
            buf->symtable.table[buf->symtable.len - 1].bits = 32; \
            buf->symtable.table[buf->symtable.len - 1].func = OPENASM_SYM_FUNC_SHIFT_MASK; \
            buf->symtable.table[buf->symtable.len - 1].mask1 = mask; \
            buf->symtable.table[buf->symtable.len - 1].shift1 = shift; \
            buf->sym = 0; \
        } \
    } while (0)

int openasm_adr_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    if (buf->sym) {
        buf->symtable.table[buf->symtable.len - 1].offset = buf->sections[buf->section].len * sizeof(uint32_t);
        buf->symtable.table[buf->symtable.len - 1].bits = 32;
        buf->symtable.table[buf->symtable.len - 1].func = OPENASM_SYM_FUNC_SPLIT_SHIFT_MASK;
        buf->symtable.table[buf->symtable.len - 1].mask1 = 0x3;
        buf->symtable.table[buf->symtable.len - 1].shift1 = 29;
        buf->symtable.table[buf->symtable.len - 1].mask2 = 0x7ffff << 2;
        buf->symtable.table[buf->symtable.len - 1].shift2 = 5;
        buf->sym = 0;
    }
    
    openasm_write(buf, OPENASM_ENCODE_DPIMM_REL(OPENASM_DPIMM_ADR, imm, rd));
    return 0;
}

int openasm_adrp_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    if (buf->sym) {
        buf->symtable.table[buf->symtable.len - 1].offset = buf->sections[buf->section].len * sizeof(uint32_t);
        buf->symtable.table[buf->symtable.len - 1].bits = 32;
        buf->symtable.table[buf->symtable.len - 1].func = OPENASM_SYM_FUNC_SPLIT_SHIFT_MASK;
        buf->symtable.table[buf->symtable.len - 1].mask1 = 0x3;
        buf->symtable.table[buf->symtable.len - 1].shift1 = 29;
        buf->symtable.table[buf->symtable.len - 1].mask2 = 0x7ffff << 2;
        buf->symtable.table[buf->symtable.len - 1].shift2 = 5;
        buf->sym = 0;
    }
    
    openasm_write(buf, OPENASM_ENCODE_DPIMM_REL(OPENASM_DPIMM_ADRP, imm, rd));
    return 0;
}

int openasm_add32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_ADD32, sh, imm, rn, rd));
    return 0;
}

int openasm_adds32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_ADDS32, sh, imm, rn, rd));
    return 0;
}

int openasm_sub32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_SUB32, sh, imm, rn, rd));
    return 0;
}

int openasm_subs32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_SUBS32, sh, imm, rn, rd));
    return 0;
}

int openasm_add64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_ADD64, sh, imm, rn, rd));
    return 0;
}

int openasm_adds64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_ADDS64, sh, imm, rn, rd));
    return 0;
}

int openasm_sub64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_SUB64, sh, imm, rn, rd));
    return 0;
}

int openasm_subs64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_SUBS64, sh, imm, rn, rd));
    return 0;
}

int openasm_and32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_AND32, imm, rn, rd));
    return 0;
}

int openasm_orr32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_ORR32, imm, rn, rd));
    return 0;
}

int openasm_eor32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_EOR32, imm, rn, rd));
    return 0;
}

int openasm_ands32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_ANDS32, imm, rn, rd));
    return 0;
}

int openasm_and64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_AND64, imm, rn, rd));
    return 0;
}

int openasm_orr64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_ORR64, imm, rn, rd));
    return 0;
}

int openasm_eor64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_EOR64, imm, rn, rd));
    return 0;
}

int openasm_ands64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_ANDS64, imm, rn, rd));
    return 0;
}

int openasm_movn32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVN32, imm, rd));
    return 0;
}

int openasm_movz32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVZ32, imm, rd));
    return 0;
}

int openasm_movk32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVK32, imm, rd));
    return 0;
}

int openasm_movn64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVN64, imm, rd));
    return 0;
}

int openasm_movz64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVZ64, imm, rd));
    return 0;
}

int openasm_movk64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVK64, imm, rd));
    return 0;
}

int openasm_sbfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_SBFM32, imm, rn, rd));
    return 0;
}

int openasm_bfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_BFM32, imm, rn, rd));
    return 0;
}

int openasm_ubfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0xfff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_UBFM32, imm, rn, rd));
    return 0;
}

int openasm_sbfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0x1fff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_SBFM64, imm, rn, rd));
    return 0;
}

int openasm_bfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0x1fff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_BFM64, imm, rn, rd));
    return 0;
}

int openasm_ubfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm) {
    OPENASM_SYMBOL(0x1fff, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_UBFM64, imm, rn, rd));
    return 0;
}

int openasm_extr32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint8_t rm, uint32_t imms) {
    OPENASM_SYMBOL(0x3f, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_EXT(OPENASM_DPIMM_EXTR32, rm, imms, rn, rd));
    return 0;
}

int openasm_extr64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint8_t rm, uint32_t imms) {
    OPENASM_SYMBOL(0x3f, 10);
    openasm_write(buf, OPENASM_ENCODE_DPIMM_EXT(OPENASM_DPIMM_EXTR64, rm, imms, rn, rd));
    return 0;
}

int openasm_b_cond(OpenasmBuffer *buf, uint8_t cond, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, cond));
    return 0;
}

int openasm_bl_cond(OpenasmBuffer *buf, uint8_t cond, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, cond));
    return 0;
}

int openasm_svc(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_SVC, imm));
    return 0;
}

int openasm_hvc(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_HVC, imm));
    return 0;
}

int openasm_smc(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_SMC, imm));
    return 0;
}

int openasm_brk(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_BRK, imm));
    return 0;
}

int openasm_hlt(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_HLT, imm));
    return 0;
}

int openasm_dcps1(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_DCPS1, imm));
    return 0;
}

int openasm_dcps2(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_DCPS2, imm));
    return 0;
}

int openasm_dcps3(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0xffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_DCPS3, imm));
    return 0;
}

int openasm_br(OpenasmBuffer *buf, uint8_t rn) {
    openasm_write(buf, OPENASM_ENCODE_BR_UNCOND1(OPENASM_BR_BR, rn));
    return 0;
}

int openasm_ret(OpenasmBuffer *buf, uint8_t rn) {
    openasm_write(buf, OPENASM_ENCODE_BR_UNCOND1(OPENASM_BR_RET, rn));
    return 0;
}

int openasm_b(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x3ffffff, 0);
    openasm_write(buf, OPENASM_ENCODE_BR_UNCOND2(OPENASM_BR_B, imm));
    return 0;
}

int openasm_bl(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x3ffffff, 0);
    openasm_write(buf, OPENASM_ENCODE_BR_UNCOND2(OPENASM_BR_BL, imm));
    return 0;
}

int openasm_ldr32(OpenasmBuffer *buf, uint8_t rt, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_LS_LDLIT(OPENASM_LS_LDR32, imm, rt));
    return 0;
}

int openasm_ldr32v(OpenasmBuffer *buf, uint8_t rt, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_LS_LDLIT(OPENASM_LS_LDR32V, imm, rt));
    return 0;
}

int openasm_ldr64(OpenasmBuffer *buf, uint8_t rt, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_LS_LDLIT(OPENASM_LS_LDR64, imm, rt));
    return 0;
}

int openasm_ldr64v(OpenasmBuffer *buf, uint8_t rt, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_LS_LDLIT(OPENASM_LS_LDR64V, imm, rt));
    return 0;
}

int openasm_ldrsw(OpenasmBuffer *buf, uint8_t rt, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_LS_LDLIT(OPENASM_LS_LDRSW, imm, rt));
    return 0;
}

int openasm_ldr128v(OpenasmBuffer *buf, uint8_t rt, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_LS_LDLIT(OPENASM_LS_LDR128V, imm, rt));
    return 0;
}

int openasm_prfm(OpenasmBuffer *buf, uint8_t rt, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_LS_LDLIT(OPENASM_LS_PRFM, imm, rt));
    return 0;
}

int openasm_stnp32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_NAPO(OPENASM_LS_STNP32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldnp32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_NAPO(OPENASM_LS_LDNP32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stnp32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_NAPO(OPENASM_LS_STNP32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldnp32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_NAPO(OPENASM_LS_LDNP32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stnp64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_NAPO(OPENASM_LS_STNP64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldnp64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_NAPO(OPENASM_LS_LDNP64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stnp64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_NAPO(OPENASM_LS_STNP64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldnp64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_NAPO(OPENASM_LS_LDNP64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stnp128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_NAPO(OPENASM_LS_STNP128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldnp128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_NAPO(OPENASM_LS_LDNP128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp32_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_STP32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp32_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_LDP32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp32v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_STP32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp32v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_LDP32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stgp_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_STGP, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldpsw_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_LDPSW, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp64v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_STP64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp64v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_LDP64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp64_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_STP64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp64_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_LDP64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp128v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_STP128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp128v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPOST(OPENASM_LS_LDP128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_STP32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_LDP32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_STP32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_LDP32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stgp(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_STGP, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldpsw(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_LDPSW, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_STP64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_LDP64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_STP64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_LDP64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_STP128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPO(OPENASM_LS_LDP128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp32_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_STP32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp32_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_LDP32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp32v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_STP32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp32v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_LDP32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stgp_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_STGP, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldpsw_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_LDPSW, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp64v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_STP64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp64v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_LDP64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp64_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_STP64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp64_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_LDP64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stp128v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_STP128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldp128v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RPPRE(OPENASM_LS_LDP128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_sturb(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_STURB, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldurb(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDURB, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldursb64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDURSB64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldursb32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDURSB32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stur8v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_STUR8V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldur8v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDUR8V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stur128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_STUR128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldur128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDUR128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_sturh(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_STURH, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldurh(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDURH, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldursh64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDURSH64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldursh32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDURSH32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stur16v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_STUR16V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldur16v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDUR16V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stur32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_STUR32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldur32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDUR32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldursw(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDURSW, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stur32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_STUR32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldur32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDUR32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stur64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_STUR64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldur64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDUR64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_prfum(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_PRFUM, imm, rn, rt1, rt2));
    return 0;
}

int openasm_stur64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_STUR64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldur64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RUI(OPENASM_LS_LDUR64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_strb_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_STRB, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrb_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDRB, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrsb64_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDRSB64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrsb32_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDRSB32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str8v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_STR8V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr8v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDR8V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str128v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_STR128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr128v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDR128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_strh_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_STRH, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrh_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDRH, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrsh64_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDRSH64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrsh32_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDRSH32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str16v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_STR16V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr16v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDR16V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str32_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_STR32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr32_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDR32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrsw_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDRSW, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str32v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_STR32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr32v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDR32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str64_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_STR64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr64_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDR64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str64v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_STR64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr64v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPOST(OPENASM_LS_I_LDR64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_strb_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_STRB, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrb_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDRB, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrsb64_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDRSB64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrsb32_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDRSB32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str8v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_STR8V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr8v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDR8V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str128v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_STR128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr128v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDR128V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_strh_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_STRH, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrh_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDRH, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrsh64_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDRSH64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrsh32_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDRSH32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str16v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_STR16V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr16v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDR16V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str32_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_STR32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr32_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDR32, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldrsw_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDRSW, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str32v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_STR32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr32v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDR32V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str64_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_STR64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr64_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDR64, imm, rn, rt1, rt2));
    return 0;
}

int openasm_str64v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_STR64V, imm, rn, rt1, rt2));
    return 0;
}

int openasm_ldr64v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm) {
    OPENASM_SYMBOL(0x7f, 15);
    openasm_write(buf, OPENASM_ENCODE_LS_RIPRE(OPENASM_LS_I_LDR64V, imm, rn, rt1, rt2));
    return 0;
}

/* aliases */
int openasm_cmp32_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm, int sh) {
    return openasm_subs32_imm(buf, OPENASM_R32_WZR, rn, sh, imm);
}

int openasm_cmp64_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm, int sh) {
    return openasm_subs32_imm(buf, OPENASM_R64_XZR, rn, sh, imm);
}

int openasm_mov32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    return openasm_movz32_imm(buf, rd, imm);
}

int openasm_mov32_r(OpenasmBuffer *buf, uint8_t rd, uint8_t rn) {
    return openasm_orr32_imm(buf, rd, rn, 0);
}

int openasm_tst32_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm) {
    return openasm_ands32_imm(buf, OPENASM_R32_WZR, rn, imm);
}

int openasm_mov64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    return openasm_movz64_imm(buf, rd, imm);
}

int openasm_mov64_r(OpenasmBuffer *buf, uint8_t rd, uint8_t rn) {
    return openasm_orr64_imm(buf, rd, rn, 0);
}

int openasm_tst64_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm) {
    return openasm_ands64_imm(buf, OPENASM_R64_XZR, rn, imm);
}

/* static aliases */
static int openasm_beq(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_EQ));
    return 0;
}

static int openasm_bleq(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_EQ));
    return 0;
}

static int openasm_bne(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_NE));
    return 0;
}

static int openasm_blne(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_NE));
    return 0;
}

static int openasm_bcs(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_CS));
    return 0;
}

static int openasm_blcs(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_CS));
    return 0;
}

static int openasm_bcc(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_CC));
    return 0;
}

static int openasm_blcc(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_CC));
    return 0;
}

static int openasm_bmi(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_MI));
    return 0;
}

static int openasm_blmi(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_MI));
    return 0;
}

static int openasm_bpl(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_PL));
    return 0;
}

static int openasm_blpl(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_PL));
    return 0;
}

static int openasm_bhi(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_HI));
    return 0;
}

static int openasm_blhi(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_HI));
    return 0;
}

static int openasm_bls(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_LS));
    return 0;
}

static int openasm_blls(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_LS));
    return 0;
}

static int openasm_bge(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_GE));
    return 0;
}

static int openasm_blge(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_GE));
    return 0;
}

static int openasm_blt(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_LT));
    return 0;
}

static int openasm_bllt(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_LT));
    return 0;
}

static int openasm_bgt(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_GT));
    return 0;
}

static int openasm_blgt(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_GT));
    return 0;
}

static int openasm_ble(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_LE));
    return 0;
}

static int openasm_blle(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_LE));
    return 0;
}

static int openasm_bal(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_AL));
    return 0;
}

static int openasm_blal(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_AL));
    return 0;
}

static int openasm_bnv(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_NV));
    return 0;
}

static int openasm_blnv(OpenasmBuffer *buf, uint32_t imm) {
    OPENASM_SYMBOL(0x7ffff, 5);
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_NV));
    return 0;
}

#define Rd OPENASM_OP_REG
#define Rn OPENASM_OP_REG
#define Rm OPENASM_OP_REG
#define Rt OPENASM_OP_REG
#define imm OPENASM_OP_IMM
#define imms OPENASM_OP_IMM
#define immr OPENASM_OP_IMM

static int (*openasm_inst_add[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_add32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_add64_imm,
};

static int (*openasm_inst_adds[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_adds32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_adds64_imm,
};

static int (*openasm_inst_sub[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_sub32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_sub64_imm,
};

static int (*openasm_inst_subs[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_subs32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_subs64_imm,
};

static int (*openasm_inst_and[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_and32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_and64_imm,
};

static int (*openasm_inst_orr[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_orr32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_orr64_imm,
};

static int (*openasm_inst_eor[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_eor32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_eor64_imm,
};

static int (*openasm_inst_ands[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_ands32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_ands64_imm,
};

static int (*openasm_inst_movn[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP2(32, Rd, imm)] = (int (*)()) openasm_movn32_imm,
    [OPENASM_OP2(64, Rd, imm)] = (int (*)()) openasm_movn64_imm,
};

static int (*openasm_inst_movz[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP2(32, Rd, imm)] = (int (*)()) openasm_movz32_imm,
    [OPENASM_OP2(64, Rd, imm)] = (int (*)()) openasm_movz64_imm,
};

static int (*openasm_inst_movk[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP2(32, Rd, imm)] = (int (*)()) openasm_movk32_imm,
    [OPENASM_OP2(64, Rd, imm)] = (int (*)()) openasm_movk64_imm,
};

static int (*openasm_inst_sbfm[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_sbfm32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_sbfm64_imm,
};

static int (*openasm_inst_bfm[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_bfm32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_bfm64_imm,
};

static int (*openasm_inst_ubfm[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, Rn, imm)] = (int (*)()) openasm_ubfm32_imm,
    [OPENASM_OP3(64, Rd, Rn, imm)] = (int (*)()) openasm_ubfm64_imm,
};

static int (*openasm_inst_extr[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rd, Rn, Rm, imms)] = (int (*)()) openasm_extr32_imm,
    [OPENASM_OP4(64, Rd, Rn, Rm, imms)] = (int (*)()) openasm_extr64_imm,
};

static int (*openasm_inst_beq[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_beq,
};

static int (*openasm_inst_bleq[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bleq,
};

static int (*openasm_inst_bne[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bne,
};

static int (*openasm_inst_blne[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blne,
};

static int (*openasm_inst_bcs[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bcs,
};

static int (*openasm_inst_blcs[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blcs,
};

static int (*openasm_inst_bcc[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bcc,
};

static int (*openasm_inst_blcc[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blcc,
};

static int (*openasm_inst_bmi[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bmi,
};

static int (*openasm_inst_blmi[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blmi,
};

static int (*openasm_inst_bpl[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bpl,
};

static int (*openasm_inst_blpl[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blpl,
};

static int (*openasm_inst_bhi[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bhi,
};

static int (*openasm_inst_blhi[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blhi,
};

static int (*openasm_inst_bls[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bls,
};

static int (*openasm_inst_blls[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blls,
};

static int (*openasm_inst_bge[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bge,
};

static int (*openasm_inst_blge[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blge,
};

static int (*openasm_inst_blt[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blt,
};

static int (*openasm_inst_bllt[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bllt,
};

static int (*openasm_inst_bgt[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bgt,
};

static int (*openasm_inst_blgt[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blgt,
};

static int (*openasm_inst_ble[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_ble,
};

static int (*openasm_inst_blle[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blle,
};

static int (*openasm_inst_bal[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bal,
};

static int (*openasm_inst_blal[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blal,
};

static int (*openasm_inst_bnv[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bnv,
};

static int (*openasm_inst_blnv[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_blnv,
};

static int (*openasm_inst_svc[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_svc,
};

static int (*openasm_inst_hvc[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_hvc,
};

static int (*openasm_inst_smc[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_smc,
};

static int (*openasm_inst_brk[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_brk,
};

static int (*openasm_inst_hlt[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_hlt,
};

static int (*openasm_inst_dcps1[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_dcps1,
};

static int (*openasm_inst_dcps2[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_dcps2,
};

static int (*openasm_inst_dcps3[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_dcps3,
};

static int (*openasm_inst_br[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(64, Rn)] = (int (*)()) openasm_br,
};

static int (*openasm_inst_ret[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(64, Rn)] = (int (*)()) openasm_ret,
};

static int (*openasm_inst_b[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_b,
};

static int (*openasm_inst_bl[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP1(0, imm)] = (int (*)()) openasm_bl,
};

static int (*openasm_inst_cmp[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rn, imm, imms)] = (int (*)()) openasm_cmp32_imm,
    [OPENASM_OP3(64, Rn, imm, imms)] = (int (*)()) openasm_cmp64_imm,
};

static int (*openasm_inst_tst[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP2(32, Rn, imm)] = (int (*)()) openasm_tst32_imm,
    [OPENASM_OP2(64, Rn, imm)] = (int (*)()) openasm_tst64_imm,
};

static int (*openasm_inst_mov[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP2(32, Rd, imm)] = (int (*)()) openasm_mov32_imm,
    [OPENASM_OP2(64, Rd, imm)] = (int (*)()) openasm_mov64_imm,
    [OPENASM_OP2(32, Rd, Rn)] = (int (*)()) openasm_mov32_r,
    [OPENASM_OP2(64, Rd, Rn)] = (int (*)()) openasm_mov64_r,
};

static int (*openasm_inst_ldnp[])(/* OpenasmBuffer * */) = {
    /* openasm_ldnp128v, */
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldnp32,
    /* openasm_ldnp32v, */
    [OPENASM_OP4(64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldnp64,
    /* openasm_ldnp64v, */
};

static int (*openasm_inst_ldp[])(/* OpenasmBuffer * */) = {
    /* openasm_ldp128v, */
    /* openasm_ldp128v_post, */
    /* openasm_ldp128v_pre, */
    [OPENASM_OP4_IDX(OPENASM_OPOFF, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldp32,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldp32_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldp32_pre,
    /* openasm_ldp32v, */
    /* openasm_ldp32v_post, */
    /* openasm_ldp32v_pre, */
    [OPENASM_OP4_IDX(OPENASM_OPOFF, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldp64,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldp64_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldp64_pre,
    /* openasm_ldp64v, */
    /* openasm_ldp64v_post, */
    /* openasm_ldp64v_pre, */
};

static int (*openasm_inst_ldpsw[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldpsw,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldpsw_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldpsw_pre,
};

static int (*openasm_inst_ldr[])(/* OpenasmBuffer * */) = {
    /* openasm_ldr128v, */
    /* openasm_ldr128v_imm_post, */
    /* openasm_ldr128v_imm_pre, */
    /* openasm_ldr16v_imm_post, */
    /* openasm_ldr16v_imm_pre, */
    [OPENASM_OP2(32, Rt, imm)] = (int (*)()) openasm_ldr32,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldr32_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldr32_imm_pre,
    /* openasm_ldr32v, */
    /* openasm_ldr32v_imm_post, */
    /* openasm_ldr32v_imm_pre, */
    [OPENASM_OP2(64, Rt, imm)] = (int (*)()) openasm_ldr64,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldr64_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldr64_imm_pre,
    /* openasm_ldr64v, */
    /* openasm_ldr64v_imm_post, */
    /* openasm_ldr64v_imm_pre, */
    /* openasm_ldr8v_imm_post, */
    /* openasm_ldr8v_imm_pre, */
};

static int (*openasm_inst_ldrb[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrb_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrb_imm_pre,
};

static int (*openasm_inst_ldrh[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrh_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrh_imm_pre,
};

static int (*openasm_inst_ldrsb[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrsb32_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrsb32_imm_pre,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrsb64_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrsb64_imm_pre,
};

static int (*openasm_inst_ldrsh[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrsh32_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrsh32_imm_pre,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrsh64_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrsh64_imm_pre,
};

static int (*openasm_inst_ldrsw[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP2(32, Rt, imm)] = (int (*)()) openasm_ldrsw,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrsw_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldrsw_imm_pre,
};

static int (*openasm_inst_ldur[])(/* OpenasmBuffer * */) = {
    /* openasm_ldur128v, */
    /* openasm_ldur16v, */
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldur32,
    /* openasm_ldur32v, */
    [OPENASM_OP4(64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldur64,
    /* openasm_ldur64v, */
    /* openasm_ldur8v, */
};

static int (*openasm_inst_ldurb[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldurb,
};

static int (*openasm_inst_ldurh[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldurh,
};

static int (*openasm_inst_ldursb[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldursb32,
    [OPENASM_OP4(64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldursb64,
};

static int (*openasm_inst_ldursh[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldursh32,
    [OPENASM_OP4(64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldursh64,
};

static int (*openasm_inst_ldursw[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_ldursw,
};

static int (*openasm_inst_prfm[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP2(64, Rt, imm)] = (int (*)()) openasm_prfm,
};

static int (*openasm_inst_prfum[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_prfum,
};

static int (*openasm_inst_stgp[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stgp,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stgp_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stgp_pre,
};

static int (*openasm_inst_stnp[])(/* OpenasmBuffer * */) = {
    /* openasm_stnp128v, */
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stnp32,
    /* openasm_stnp32v, */
    [OPENASM_OP4(64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stnp64,
    /* openasm_stnp64v, */
    /* openasm_stp128v, */
    /* openasm_stp128v_post, */
    /* openasm_stp128v_pre, */
};

static int (*openasm_inst_stp[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stp32,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stp32_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stp32_pre,
    /* openasm_stp32v, */
    /* openasm_stp32v_post, */
    /* openasm_stp32v_pre, */
    [OPENASM_OP4(64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stp64,
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stp64_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stp64_pre,
    /* openasm_stp64v, */
    /* openasm_stp64v_post, */
    /* openasm_stp64v_pre, */
};

static int (*openasm_inst_str[])(/* OpenasmBuffer * */) = {
    /* openasm_str128v_imm_post, */
    /* openasm_str128v_imm_pre, */
    /* openasm_str16v_imm_post, */
    /* openasm_str16v_imm_pre, */
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_str32_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_str32_imm_pre,
    /* openasm_str32v_imm_post, */
    /* openasm_str32v_imm_pre, */
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_str64_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_str64_imm_pre,
    /* openasm_str64v_imm_post, */
    /* openasm_str64v_imm_pre, */
    /* openasm_str8v_imm_post, */
    /* openasm_str8v_imm_pre, */
};

static int (*openasm_inst_strb[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_strb_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_strb_imm_pre,
};

static int (*openasm_inst_strh[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4_IDX(OPENASM_OPPOST, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_strh_imm_post,
    [OPENASM_OP4_IDX(OPENASM_OPPRE, 32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_strh_imm_pre,
};

static int (*openasm_inst_stur[])(/* OpenasmBuffer * */) = {
    /* openasm_stur128v, */
    /* openasm_stur16v, */
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stur32,
    /* openasm_stur32v, */
    [OPENASM_OP4(64, Rn, Rt, Rt, imm)] = (int (*)()) openasm_stur64,
    /* openasm_stur64v, */
    /* openasm_stur8v, */
};

static int (*openasm_inst_sturb[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_sturb,
};

static int (*openasm_inst_sturh[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rn, Rt, Rt, imm)] = (int (*)()) openasm_sturh,
};

struct OpenasmEntry openasm_inst[] = {
    { "add", openasm_inst_add },
    { "adds", openasm_inst_adds },
    { "sub", openasm_inst_sub },
    { "subs", openasm_inst_subs },
    { "and", openasm_inst_and },
    { "orr", openasm_inst_orr },
    { "eor", openasm_inst_eor },
    { "ands", openasm_inst_ands },
    { "movn", openasm_inst_movn },
    { "movz", openasm_inst_movz },
    { "movk", openasm_inst_movk },
    { "sbfm", openasm_inst_sbfm },
    { "bfm", openasm_inst_bfm },
    { "ubfm", openasm_inst_ubfm },
    { "extr", openasm_inst_extr },
    { "svc", openasm_inst_svc },
    { "hvc", openasm_inst_hvc },
    { "smc", openasm_inst_smc },
    { "brk", openasm_inst_brk },
    { "hlt", openasm_inst_hlt },
    { "dcps1", openasm_inst_dcps1 },
    { "dcps2", openasm_inst_dcps2 },
    { "dcps3", openasm_inst_dcps3 },
    { "br", openasm_inst_br },
    { "ret", openasm_inst_ret },
    { "b", openasm_inst_b },
    { "bl", openasm_inst_bl },
    { "ldnp", openasm_inst_ldnp },
    { "ldp", openasm_inst_ldp },
    { "ldpsw", openasm_inst_ldpsw },
    { "ldr", openasm_inst_ldr },
    { "ldrb", openasm_inst_ldrb },
    { "ldrh", openasm_inst_ldrh },
    { "ldrsb", openasm_inst_ldrsb },
    { "ldrsh", openasm_inst_ldrsh },
    { "ldrsw", openasm_inst_ldrsw },
    { "ldur", openasm_inst_ldur },
    { "ldurb", openasm_inst_ldurb },
    { "ldurh", openasm_inst_ldurh },
    { "ldursb", openasm_inst_ldursb },
    { "ldursh", openasm_inst_ldursh },
    { "ldursw", openasm_inst_ldursw },
    { "prfm", openasm_inst_prfm },
    { "prfum", openasm_inst_prfum },
    { "stgp", openasm_inst_stgp },
    { "stnp", openasm_inst_stnp },
    { "stp", openasm_inst_stp },
    { "str", openasm_inst_str },
    { "strb", openasm_inst_strb },
    { "strh", openasm_inst_strh },
    { "stur", openasm_inst_stur },
    { "sturb", openasm_inst_sturb },
    { "sturh", openasm_inst_sturh },
    /* aliases */
    { "cmp", openasm_inst_cmp },
    { "tst", openasm_inst_tst },
    { "mov", openasm_inst_mov },
    /* static aliases */
    { "b.eq", openasm_inst_beq },
    { "bl.eq", openasm_inst_bleq },
    { "b.ne", openasm_inst_bne },
    { "bl.ne", openasm_inst_blne },
    { "b.cs", openasm_inst_bcs },
    { "bl.cs", openasm_inst_blcs },
    { "b.cc", openasm_inst_bcc },
    { "bl.cc", openasm_inst_blcc },
    { "b.mi", openasm_inst_bmi },
    { "bl.mi", openasm_inst_blmi },
    { "b.pl", openasm_inst_bpl },
    { "bl.pl", openasm_inst_blpl },
    { "b.hi", openasm_inst_bhi },
    { "bl.hi", openasm_inst_blhi },
    { "b.ls", openasm_inst_bls },
    { "bl.ls", openasm_inst_blls },
    { "b.ge", openasm_inst_bge },
    { "bl.ge", openasm_inst_blge },
    { "b.lt", openasm_inst_blt },
    { "bl.lt", openasm_inst_bllt },
    { "b.gt", openasm_inst_bgt },
    { "bl.gt", openasm_inst_blgt },
    { "b.le", openasm_inst_ble },
    { "bl.le", openasm_inst_blle },
    { "b.al", openasm_inst_bal },
    { "bl.al", openasm_inst_blal },
    { "b.nv", openasm_inst_bnv },
    { "bl.nv", openasm_inst_blnv },
};
