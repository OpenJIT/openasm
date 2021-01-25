#define OPENASM_ARCH_AARCH64 1
#include "include/openasm.h"

#define DEFAULT_SECTION_CAP ((size_t) 32)
#define DEFAULT_SYMTABLE_CAP ((size_t) 128)

void openasm_buffer(OpenasmBuffer *buf) {
    size_t cap = DEFAULT_SECTION_CAP;
    buf->cap = cap;
    buf->len = 0;
    buf->sections = malloc(cap * sizeof(struct OpenasmSection));

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

int openasm_adr_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_REL(OPENASM_DPIMM_ADR, imm, rd));
    return 0;
}

int openasm_adrp_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_REL(OPENASM_DPIMM_ADRP, imm, rd));
    return 0;
}

int openasm_add32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_ADD32, sh, imm, rn, rd));
    return 0;
}

int openasm_adds32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_ADDS32, sh, imm, rn, rd));
    return 0;
}

int openasm_sub32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_SUB32, sh, imm, rn, rd));
    return 0;
}

int openasm_subs32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_SUBS32, sh, imm, rn, rd));
    return 0;
}

int openasm_add64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_ADD64, sh, imm, rn, rd));
    return 0;
}

int openasm_adds64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_ADDS64, sh, imm, rn, rd));
    return 0;
}

int openasm_sub64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_SUB64, sh, imm, rn, rd));
    return 0;
}

int openasm_subs64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_ADD(OPENASM_DPIMM_SUBS64, sh, imm, rn, rd));
    return 0;
}

int openasm_and32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_AND32, immr, imms, rn, rd));
    return 0;
}

int openasm_orr32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_ORR32, immr, imms, rn, rd));
    return 0;
}

int openasm_eor32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_EOR32, immr, imms, rn, rd));
    return 0;
}

int openasm_ands32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_ANDS32, immr, imms, rn, rd));
    return 0;
}

int openasm_and64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_AND64, immr, imms, rn, rd));
    return 0;
}

int openasm_orr64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_ORR64, immr, imms, rn, rd));
    return 0;
}

int openasm_eor64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_EOR64, immr, imms, rn, rd));
    return 0;
}

int openasm_ands64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_LOG(OPENASM_DPIMM_ANDS64, immr, imms, rn, rd));
    return 0;
}

int openasm_movn32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVN32(0), imm, rd));
    return 0;
}

int openasm_movz32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVZ32(0), imm, rd));
    return 0;
}

int openasm_movk32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVK32(0), imm, rd));
    return 0;
}

int openasm_movn64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVN64, imm, rd));
    return 0;
}

int openasm_movz64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVZ64, imm, rd));
    return 0;
}

int openasm_movk64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_MOV(OPENASM_DPIMM_MOVK64, imm, rd));
    return 0;
}

int openasm_sbfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_SBFM32, immr, imms, rn, rd));
    return 0;
}

int openasm_bfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_BFM32, immr, imms, rn, rd));
    return 0;
}

int openasm_ubfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_UBFM32, immr, imms, rn, rd));
    return 0;
}

int openasm_sbfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_SBFM64, immr, imms, rn, rd));
    return 0;
}

int openasm_bfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_BFM64, immr, imms, rn, rd));
    return 0;
}

int openasm_ubfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_BIT(OPENASM_DPIMM_UBFM64, immr, imms, rn, rd));
    return 0;
}

int openasm_extr32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint8_t rm, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_EXT(OPENASM_DPIMM_EXTR32, rm, imms, rn, rd));
    return 0;
}

int openasm_extr64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint8_t rm, uint32_t imms) {
    openasm_write(buf, OPENASM_ENCODE_DPIMM_EXT(OPENASM_DPIMM_EXTR64, rm, imms, rn, rd));
    return 0;
}

int openasm_b_cond(OpenasmBuffer *buf, uint8_t cond, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, cond));
    return 0;
}

int openasm_bl_cond(OpenasmBuffer *buf, uint8_t cond, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, cond));
    return 0;
}

int openasm_svc(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_SVC, imm));
    return 0;
}

int openasm_hvc(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_HVC, imm));
    return 0;
}

int openasm_smc(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_SMC, imm));
    return 0;
}

int openasm_brk(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_BRK, imm));
    return 0;
}

int openasm_hlt(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_HLT, imm));
    return 0;
}

int openasm_dcps1(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_DCPS1, imm));
    return 0;
}

int openasm_dcps2(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_EXCEPT(OPENASM_BR_DCPS2, imm));
    return 0;
}

int openasm_dcps3(OpenasmBuffer *buf, uint32_t imm) {
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
    openasm_write(buf, OPENASM_ENCODE_BR_UNCOND2(OPENASM_BR_B, imm));
    return 0;
}

int openasm_bl(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_UNCOND2(OPENASM_BR_BL, imm));
    return 0;
}

/* aliases */
int openasm_cmp32_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm, int sh) {
    return openasm_subs32_imm(buf, OPENASM_R32_WZR, rn, sh, imm);
}

int openasm_cmp64_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm, int sh) {
    return openasm_subs32_imm(buf, OPENASM_R64_XZR, rn, sh, imm);
}

int openasm_mov32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t immr, uint32_t imms) {
    return openasm_orr32_imm(buf, rd, OPENASM_R32_WZR, immr, imms);
}

int openasm_mov32_r(OpenasmBuffer *buf, uint8_t rd, uint8_t rn) {
    return openasm_orr32_imm(buf, rd, rn, 0, 0);
}

int openasm_tst32_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t immr, uint32_t imms) {
    return openasm_ands32_imm(buf, OPENASM_R32_WZR, rn, immr, imms);
}

int openasm_mov64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t immr, uint32_t imms) {
    return openasm_orr64_imm(buf, rd, OPENASM_R64_XZR, immr, imms);
}

int openasm_mov64_r(OpenasmBuffer *buf, uint8_t rd, uint8_t rn) {
    return openasm_orr64_imm(buf, rd, rn, 0, 0);
}

int openasm_tst64_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t immr, uint32_t imms) {
    return openasm_ands64_imm(buf, OPENASM_R64_XZR, rn, immr, imms);
}

/* static aliases */
static int openasm_beq(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_EQ));
    return 0;
}

static int openasm_bleq(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_EQ));
    return 0;
}

static int openasm_bne(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_NE));
    return 0;
}

static int openasm_blne(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_NE));
    return 0;
}

static int openasm_bcs(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_CS));
    return 0;
}

static int openasm_blcs(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_CS));
    return 0;
}

static int openasm_bcc(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_CC));
    return 0;
}

static int openasm_blcc(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_CC));
    return 0;
}

static int openasm_bmi(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_MI));
    return 0;
}

static int openasm_blmi(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_MI));
    return 0;
}

static int openasm_bpl(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_PL));
    return 0;
}

static int openasm_blpl(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_PL));
    return 0;
}

static int openasm_bhi(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_HI));
    return 0;
}

static int openasm_blhi(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_HI));
    return 0;
}

static int openasm_bls(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_LS));
    return 0;
}

static int openasm_blls(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_LS));
    return 0;
}

static int openasm_bge(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_GE));
    return 0;
}

static int openasm_blge(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_GE));
    return 0;
}

static int openasm_blt(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_LT));
    return 0;
}

static int openasm_bllt(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_LT));
    return 0;
}

static int openasm_bgt(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_GT));
    return 0;
}

static int openasm_blgt(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_GT));
    return 0;
}

static int openasm_ble(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_LE));
    return 0;
}

static int openasm_blle(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_LE));
    return 0;
}

static int openasm_bal(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_AL));
    return 0;
}

static int openasm_blal(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_AL));
    return 0;
}

static int openasm_bnv(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_B_COND, imm, OPENASM_COND_NV));
    return 0;
}

static int openasm_blnv(OpenasmBuffer *buf, uint32_t imm) {
    openasm_write(buf, OPENASM_ENCODE_BR_COND(OPENASM_BR_BL_COND, imm, OPENASM_COND_NV));
    return 0;
}

#define Rd OPENASM_OP_REG
#define Rn OPENASM_OP_REG
#define Rm OPENASM_OP_REG
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
    [OPENASM_OP4(32, Rd, Rn, immr, imms)] = (int (*)()) openasm_and32_imm,
    [OPENASM_OP4(64, Rd, Rn, immr, imms)] = (int (*)()) openasm_and64_imm,
};

static int (*openasm_inst_orr[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rd, Rn, immr, imms)] = (int (*)()) openasm_orr32_imm,
    [OPENASM_OP4(64, Rd, Rn, immr, imms)] = (int (*)()) openasm_orr64_imm,
};

static int (*openasm_inst_eor[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rd, Rn, immr, imms)] = (int (*)()) openasm_eor32_imm,
    [OPENASM_OP4(64, Rd, Rn, immr, imms)] = (int (*)()) openasm_eor64_imm,
};

static int (*openasm_inst_ands[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rd, Rn, immr, imms)] = (int (*)()) openasm_ands32_imm,
    [OPENASM_OP4(64, Rd, Rn, immr, imms)] = (int (*)()) openasm_ands64_imm,
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
    [OPENASM_OP4(32, Rd, Rn, immr, imms)] = (int (*)()) openasm_sbfm32_imm,
    [OPENASM_OP4(64, Rd, Rn, immr, imms)] = (int (*)()) openasm_sbfm64_imm,
};

static int (*openasm_inst_bfm[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rd, Rn, immr, imms)] = (int (*)()) openasm_bfm32_imm,
    [OPENASM_OP4(64, Rd, Rn, immr, imms)] = (int (*)()) openasm_bfm64_imm,
};

static int (*openasm_inst_ubfm[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP4(32, Rd, Rn, immr, imms)] = (int (*)()) openasm_ubfm32_imm,
    [OPENASM_OP4(64, Rd, Rn, immr, imms)] = (int (*)()) openasm_ubfm64_imm,
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
    [OPENASM_OP3(32, Rn, immr, imms)] = (int (*)()) openasm_tst32_imm,
    [OPENASM_OP3(64, Rn, immr, imms)] = (int (*)()) openasm_tst64_imm,
};

static int (*openasm_inst_mov[])(/* OpenasmBuffer * */) = {
    [OPENASM_OP3(32, Rd, immr, imms)] = (int (*)()) openasm_mov32_imm,
    [OPENASM_OP3(64, Rd, immr, imms)] = (int (*)()) openasm_mov64_imm,
    [OPENASM_OP2(32, Rd, Rn)] = (int (*)()) openasm_mov32_r,
    [OPENASM_OP2(64, Rd, Rn)] = (int (*)()) openasm_mov64_r,
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
