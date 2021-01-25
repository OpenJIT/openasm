#ifndef OPENASM_ARCH_H
#define OPENASM_ARCH_H 1

#ifndef OPENASM_H
#error "don't include any of the OpenAsm architecture headers on their own"
#endif /* OPENASM_H */

typedef struct OpenasmBuffer OpenasmBuffer;
typedef struct OpenasmProperty OpenasmProperty;
typedef struct OpenasmOperand OpenasmOperand;

struct OpenasmSection {
    const char *name;
    size_t len;
    size_t cap;
    uint32_t *buffer;
};

struct OpenasmBuffer {
    size_t len;
    size_t cap;
    struct OpenasmSection *sections;
    
    size_t section;

    int sym;
    struct OpenasmSymbolTable symtable;
};

struct OpenasmEntry {
    const char *mnem;
    // this inst_table doesn't use `OpenasmBuffer *` to allow the caller to use any arguments
    int (**inst_table)(/* OpenasmBuffer * */);
};

/* useful defines */
#define OPENASM_MAX_SIZE 4
#define OPENASM_OP_REG 0
#define OPENASM_OP_IMM 1
#define OPENASM_OPSIZE(s) ((s >> 5) & 0x3)
#define OPENASM_OPMASK 0x3f
#define OPENASM_MASKOP(x) (x & OPENASM_OPMASK)
#define OPENASM_OP0(s) (OPENASM_OPSIZE(s) << 6)
#define OPENASM_OP1(s, x) ((OPENASM_OPSIZE(s) << 6) | (x & 1))
#define OPENASM_OP2(s, x, y) ((OPENASM_OPSIZE(s) << 6) | ((x & 1) << 1) | (y & 1))
#define OPENASM_OP3(s, x, y, z) ((OPENASM_OPSIZE(s) << 6) | ((x & 1) << 2) | ((y & 1) << 1) | (z & 1))
#define OPENASM_OP4(s, x, y, z, w) \
    ((OPENASM_OPSIZE(s) << 6) | ((x & 1) << 3) | ((y & 1) << 2) | ((z & 1) << 1) | (w & 1))
#define OPENASM_OP5(s, x, y, z, w, u) \
    ((OPENASM_OPSIZE(s) << 6) | ((x & 1) << 4) | ((y & 1) << 3) | ((z & 1) << 2) | ((w & 1) << 1) | (u & 1))
#define OPENASM_OP6(s, x, y, z, w, u, v) \
    ((OPENASM_OPSIZE(s) << 6) | ((x & 1) << 5) | ((y & 1) << 4) | ((z & 1) << 3) \
                      | ((w & 1) << 2) | ((u & 1) << 1) | (v & 1))

/* aarch32/64 registers (5 bits each) */
#define OPENASM_R32_W(n) (n & 0x1f)
#define OPENASM_R64_X(n) (n & 0x1f)
#define OPENASM_R32_WZR OPENASM_R32_W(31) /* only valid in integer instructions */
#define OPENASM_R64_XZR OPENASM_R64_X(31) /* only valid in integer instructions */
#define OPENASM_R64_FP OPENASM_R64_X(29)
#define OPENASM_R64_LR OPENASM_R64_X(30)
#define OPENASM_R64_SP OPENASM_R64_X(31) /* system register since ARMv8a, but sometimes a valid gpr */
/* aarch32/64 fp/vector registers (5 bits each) */
#define OPENASM_R8_B(n) (n & 0x1f)
#define OPENASM_R16_H(n) (n & 0x1f)
#define OPENASM_R32_S(n) (n & 0x1f)
#define OPENASM_R64_D(n) (n & 0x1f)
#define OPENASM_R128_Q(n) (n & 0x1f)
#define OPENASM_R128_V(n) (n & 0x1f)

/* condition codes */
#define OPENASM_COND_EQ 0x0
#define OPENASM_COND_NE 0x1
#define OPENASM_COND_CS 0x2
#define OPENASM_COND_HS 0x2
#define OPENASM_COND_CC 0x3
#define OPENASM_COND_LO 0x3
#define OPENASM_COND_MI 0x4
#define OPENASM_COND_PL 0x5
#define OPENASM_COND_VS 0x6
#define OPENASM_COND_VC 0x7
#define OPENASM_COND_HI 0x8
#define OPENASM_COND_LS 0x9
#define OPENASM_COND_GE 0xa
#define OPENASM_COND_LT 0xb
#define OPENASM_COND_GT 0xc
#define OPENASM_COND_LE 0xd
#define OPENASM_COND_AL 0xe
#define OPENASM_COND_NV 0xf

/* opcodes */
// shift these left by 25
#define OPENASM_OP0_RESERVED 0x0
#define OPENASM_OP0_UNALLOCATED0 0x1
#define OPENASM_OP0_SVE 0x2
#define OPENASM_OP0_UNALLOCATED1 0x3
#define OPENASM_OP0_DPIMM(x) (0x8 | (x & 1))
#define OPENASM_OP0_BR(x) (0xa | (x & 1))
#define OPENASM_OP0_LS(x1, x2) (0x4 | ((x1 & 1) << 3) | (x2 & 1))
#define OPENASM_OP0_DPREG(x) (0x5 | ((x & 1) << 3))
#define OPENASM_OP0_DPFP(x) (0x7 | ((x & 1) << 3))
/* opcodes: data processing immediate */
// shift these left by 23
#define OPENASM_DPIMM_REL(x) (0x0 | (x & 1))
#define OPENASM_DPIMM_ADD 0x2
#define OPENASM_DPIMM_ADT 0x3
#define OPENASM_DPIMM_LOG 0x4
#define OPENASM_DPIMM_MOV 0x5
#define OPENASM_DPIMM_BIT 0x6
#define OPENASM_DPIMM_EXT 0x7
/* opcodes: data processing immediate: PC-rel. addresing */
#define OPENASM_DPIMM_ADR 0
#define OPENASM_DPIMM_ADRP 1
#define OPENASM_ENCODE_DPIMM_REL(op, imm, rd) \
  (((op & 1) << 31) \
  | ((imm & 0x3) << 29) \
  | (OPENASM_OP0_DPIMM(0) << 25) \
  | (OPENASM_DPIMM_REL(0) << 23) \
  | (((imm >> 2) & 0x7ffff) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: add/subtract (immediate) */
#define OPENASM_DPIMM_ADD32 0x0
#define OPENASM_DPIMM_ADDS32 0x1
#define OPENASM_DPIMM_SUB32 0x2
#define OPENASM_DPIMM_SUBS32 0x3
#define OPENASM_DPIMM_ADD64 0x4
#define OPENASM_DPIMM_ADDS64 0x5
#define OPENASM_DPIMM_SUB64 0x6
#define OPENASM_DPIMM_SUBS64 0x7
#define OPENASM_ENCODE_DPIMM_ADD(op, sh, imm, rn, rd) \
  (((op & 0x7) < 29) \
  | (OPENASM_OP0_DPIMM(0) << 25) \
  | (OPENASM_DPIMM_ADD << 23) \
  | ((sh & 1) << 22) \
  | ((imm & 0xfff) << 10) \
  | (OPENASM_R64_X(rn) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: add/subtract (immediate, with tags) */
// these two require FEAT_MTE
#define OPENASM_DPIMM_ADDG64 0x8
#define OPENASM_DPIMM_SUBG64 0xc
#define OPENASM_ENCODE_DPIMM_ADT(op, uimm6, op3, uimm4, rn, rd)	\
  ((((op >> 1) & 0x7) < 29) \
  | (OPENASM_OP0_DPIMM(0) << 25) \
  | (OPENASM_DPIMM_ADT << 23) \
  | ((op & 1) << 22) \
  | ((uimm6 & 0x3f) << 16) \
  | ((op3 & 0x3) << 14) \
  | ((uimm4 & 0xf) << 10) \
  | (OPENASM_R64_X(rn) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: logical (immediate) */
#define OPENASM_DPIMM_AND32 0x0
#define OPENASM_DPIMM_ORR32 0x2
#define OPENASM_DPIMM_EOR32 0x4
#define OPENASM_DPIMM_ANDS32 0x6
#define OPENASM_DPIMM_AND64 0x8
#define OPENASM_DPIMM_ORR64 0xa
#define OPENASM_DPIMM_EOR64 0xc
#define OPENASM_DPIMM_ANDS64 0xe
#define OPENASM_ENCODE_DPIMM_LOG(op, immr, imms, rn, rd) \
  ((((op >> 1) & 0x7) < 29) \
  | (OPENASM_OP0_DPIMM(0) << 25) \
  | (OPENASM_DPIMM_LOG << 23) \
  | ((op & 1) << 22) \
  | ((immr & 0x3f) << 16) \
  | ((imms & 0x3f) << 10) \
  | (OPENASM_R64_X(rn) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: move wide (immediate) */
#define OPENASM_DPIMM_MOVN32(x) (0x0 | (x & 1))
#define OPENASM_DPIMM_MOVZ32(x) (0x8 | (x & 1))
#define OPENASM_DPIMM_MOVK32(x) (0xc | (x & 1))
#define OPENASM_DPIMM_MOVN64 0x10
#define OPENASM_DPIMM_MOVZ64 0x18
#define OPENASM_DPIMM_MOVK64 0x1c
#define OPENASM_ENCODE_DPIMM_MOV(op, imm16, rd) \
  ((((op >> 1) & 0x7) < 29) \
  | (OPENASM_OP0_DPIMM(0) << 25) \
  | (OPENASM_DPIMM_LOG << 23) \
  | ((op & 1) << 22) \
  | ((imm16 & 0xffff) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: bitfield */
#define OPENASM_DPIMM_SBFM32 0x0
#define OPENASM_DPIMM_BFM32 0x2
#define OPENASM_DPIMM_UBFM32 0x4
#define OPENASM_DPIMM_SBFM64 0x9
#define OPENASM_DPIMM_BFM64 0xb
#define OPENASM_DPIMM_UBFM64 0xd
#define OPENASM_ENCODE_DPIMM_BIT(op, immr, imms, rn, rd) \
  ((((op >> 1) & 0x7) < 29) \
  | (OPENASM_OP0_DPIMM(0) << 25) \
  | (OPENASM_DPIMM_BIT << 23) \
  | ((op & 1) << 22) \
  | ((immr & 0x3f) << 16) \
  | ((imms & 0x3f) << 10) \
  | (OPENASM_R64_X(rn) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: extract */
#define OPENASM_DPIMM_EXTR32 0x0
#define OPENASM_DPIMM_EXTR64 0x12
#define OPENASM_ENCODE_DPIMM_EXT(op, rm, imms, rn, rd) \
  ((((op >> 1) & 0x7) < 29) \
  | (OPENASM_OP0_DPIMM(0) << 25) \
  | (OPENASM_DPIMM_BIT << 23) \
  | ((op & 0x3) << 21)	      \
  | (OPENASM_R64_X(rm) << 16) \
  | ((imms & 0x3f) << 10) \
  | (OPENASM_R64_X(rn) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: branches and exceptions */
// shift these left by 12
#define OPENASM_BR_COND(x) (0x8000 | (x & 0x1fff))
#define OPENASM_BR_EXCEPT(x) (0x18000 | (x & 0xfff))
#define OPENASM_BR_SYS1 0x19031
#define OPENASM_BR_HINT 0x19032
#define OPENASM_BR_HINT_OP2 0x1f
#define OPENASM_BR_BARR 0x19033
#define OPENASM_BR_PSTATE(x) (0x19004 | ((x & 0x7) << 4))
#define OPENASM_BR_SYS2(x1, x2) (0x19080 | ((x1 & 1) << 9) | (x2 & 0x7f))
#define OPENASM_BR_SYS3(x1, x2) (0x19100 | ((x1 & 1) << 9) | (x2 & 0xff))
#define OPENASM_BR_UNCOND1(x) (0x1a000 | (x & 0x1ffff))
#define OPENASM_BR_UNCOND2(x) ((x & 1) << 16)
#define OPENASM_BR_CMP(x) (0x4000 | ((x & 1) << 16))
#define OPENASM_BR_TEST(x) (0x6000 | ((x & 1) << 16))
/* opcodes: branches and exceptions: conditional branches */
#define OPENASM_BR_B_COND 0
#define OPENASM_BR_BL_COND 1
#define OPENASM_ENCODE_BR_COND(op, imm19, cond) \
  ((((OPENASM_BR_COND(0) >> 13) & 0x7) << 28)	\
  | (OPENASM_OP0_BR(0) << 25) \
  | (((op >> 1) & 0x1) << 24) \
  | ((imm19 & 0x7ffff) << 5) \
  | ((op & 1) << 4) \
  | (cond & 0xf))
/* opcodes: branches and exceptions: exceptions */
#define OPENASM_BR_SVC 0x1
#define OPENASM_BR_HVC 0x2
#define OPENASM_BR_SMC 0x3
#define OPENASM_BR_BRK 0x20
#define OPENASM_BR_HLT 0x40
#define OPENASM_BR_DCPS1 0xa1
#define OPENASM_BR_DCPS2 0xa2
#define OPENASM_BR_DCPS3 0xa3
#define OPENASM_ENCODE_BR_EXCEPT(op, imm16) \
  ((((OPENASM_BR_EXCEPT(0) >> 13) & 0x7) << 28)	\
  | (OPENASM_OP0_BR(0) << 25) \
  | (((op >> 5) & 0x7) << 21) \
  | ((imm16 & 0xffff) << 5) \
  | (op & 0x1f))
/* opcodes: branches and exceptions: system instructions with register arguments */
/* NOTE: skipped */

/* opcodes: branches and exceptions: hints */
/* NOTE: skipped */

/* opcodes: branches and exceptions: barriers */
/* NOTE: skipped */

/* opcodes: branches and exceptions: system instructions */
/* NOTE: skipped */

/* opcodes: branches and exceptions: system register move */
/* NOTE: skipped */

/* opcodes: branches and exceptions: unconditional branches (register) */
/* NOTE: some instructions where skipped */
#define OPENASM_BR_BR 0x0f800
#define OPENASM_BR_RET 0x2f800
#define OPENASM_ENCODE_BR_UNCOND1(op, rn) \
  ((((OPENASM_BR_UNCOND1(0) >> 13) & 0x7) << 28) \
  | (OPENASM_OP0_BR(0) << 25) \
  | (((op >> 5) & 0x7fff) << 10) \
  | (op & 0x1f) \
  | (OPENASM_R64_X(rn)))

/* opcodes: branches and exceptions: unconditional branches (immediate) */
#define OPENASM_BR_B 0
#define OPENASM_BR_BL 1
#define OPENASM_ENCODE_BR_UNCOND2(op, imm26) \
  ((((OPENASM_BR_UNCOND2(0) >> 13) & 0x7) << 28) \
  | ((op & 1) << 31) \
  | (OPENASM_OP0_BR(0) << 25) \
  | (imm26 & 0x3ffffff))

/* opcodes: branches and exceptions: compare and branch (immediate) */
/* NOTE: skipped */

/* opcodes: branches and exceptions: test and branch (immediate) */
/* NOTE: skipped */

/* function declarations */
void openasm_buffer(OpenasmBuffer *buf);
void openasm_del_buffer(OpenasmBuffer *buf);

void openasm_write(OpenasmBuffer *buf, uint32_t instr);

int openasm_instf(OpenasmBuffer *buf, const char *fmt, ...);
int openasm_instfv(OpenasmBuffer *buf, const char *fmt, va_list args);
uint64_t openasm_data(OpenasmBuffer *buf, size_t len, void *ptr);
uint64_t openasm_res(OpenasmBuffer *buf, size_t len);

void openasm_section(OpenasmBuffer *buf, const char *section);

uint64_t openasm_addr_of(OpenasmBuffer *buf, uint32_t *inst);
uint64_t openasm_current_addr(OpenasmBuffer *buf);
// `openasm_symbol` returns whether that symbol was used, not whether that symbol is valid.
// Must be used after all uses of the symbol were emitted, or it will otherwise create
// erroneous results.
bool openasm_symbol(OpenasmBuffer *buf, const char *section, const char *sym, uint64_t addr);
// Returns 1 if some symbol was not defined, but only emits a warning if one wasn't.
int openasm_link(OpenasmBuffer *buf);
int openasm_elfdump(FILE *fileout, int flags, OpenasmBuffer *buf);
int openasm_rawdump(FILE *fileout, OpenasmBuffer *buf);

OpenasmProc openasm_jit_proc(OpenasmBuffer *buf);
OpenasmFni openasm_jit_fni(OpenasmBuffer *buf);
OpenasmFnl openasm_jit_fnl(OpenasmBuffer *buf);
OpenasmFnll openasm_jit_fnll(OpenasmBuffer *buf);
OpenasmFnf openasm_jit_fnf(OpenasmBuffer *buf);
OpenasmFnd openasm_jit_fnd(OpenasmBuffer *buf);
OpenasmFnvp openasm_jit_fnvp(OpenasmBuffer *buf);

/* real instructions */
int openasm_adr_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_adrp_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_add32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh);
int openasm_adds32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh);
int openasm_sub32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh);
int openasm_subs32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh);
int openasm_add64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh);
int openasm_adds64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh);
int openasm_sub64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh);
int openasm_subs64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm, int sh);
/* int openasm_addg64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, int sh, uint32_t uimm6, uint32_t uimm4); */
/* int openasm_subg64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, int sh, uint32_t uimm6, uint32_t uimm4); */
int openasm_and32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_orr32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_eor32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_ands32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_and64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_orr64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_eor64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_ands64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_movn32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_movz32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_movk32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_movn64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_movz64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_movk64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_sbfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_bfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_ubfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_sbfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_bfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_ubfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t immr, uint32_t imms);
int openasm_extr32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint8_t rm, uint32_t imms);
int openasm_extr64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint8_t rm, uint32_t imms);
int openasm_b_cond(OpenasmBuffer *buf, uint8_t cond, uint32_t imm);
int openasm_bl_cond(OpenasmBuffer *buf, uint8_t cond, uint32_t imm);
int openasm_svc(OpenasmBuffer *buf, uint32_t imm);
int openasm_hvc(OpenasmBuffer *buf, uint32_t imm);
int openasm_smc(OpenasmBuffer *buf, uint32_t imm);
int openasm_brk(OpenasmBuffer *buf, uint32_t imm);
int openasm_hlt(OpenasmBuffer *buf, uint32_t imm);
int openasm_dcps1(OpenasmBuffer *buf, uint32_t imm);
int openasm_dcps2(OpenasmBuffer *buf, uint32_t imm);
int openasm_dcps3(OpenasmBuffer *buf, uint32_t imm);
int openasm_br(OpenasmBuffer *buf, uint8_t rn);
int openasm_ret(OpenasmBuffer *buf, uint8_t rn);
int openasm_b(OpenasmBuffer *buf, uint32_t imm);
int openasm_bl(OpenasmBuffer *buf, uint32_t imm);

/* aliases */
int openasm_cmp32_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm, int sh); /* subs32_imm alias */
int openasm_cmp64_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm, int sh); /* subs64_imm alias */
int openasm_mov32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t immr, uint32_t imms); /* orr32_imm alias */ 
int openasm_mov32_r(OpenasmBuffer *buf, uint8_t rd, uint8_t rn); /* orr32_imm alias */ 
int openasm_tst32_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t immr, uint32_t imms); /* ands32_imm alias */
int openasm_mov64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t immr, uint32_t imms); /* orr64_imm alias */ 
int openasm_mov64_r(OpenasmBuffer *buf, uint8_t rd, uint8_t rn); /* orr64_imm alias */ 
int openasm_tst64_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t immr, uint32_t imms); /* ands64_imm alias */

extern struct OpenasmEntry openasm_inst[];

#endif /* OPENASM_ARCH_H */
