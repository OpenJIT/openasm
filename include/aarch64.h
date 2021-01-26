#ifndef OPENASM_ARCH_H
#define OPENASM_ARCH_H 1

#ifndef OPENASM_H
#error "don't include any of the OpenAsm architecture headers on their own"
#endif /* OPENASM_H */

typedef struct OpenasmBuffer OpenasmBuffer;
typedef struct OpenasmProperty OpenasmProperty;
typedef union OpenasmOperand OpenasmOperand;

struct OpenasmSection {
    const char *name;
    size_t len;
    size_t cap;
    uint32_t *buffer;
};

struct OpenasmPoolQueue {
    uint32_t gen;
    size_t len;
    size_t cap;
    uint64_t *buffer;
};

struct OpenasmBuffer {
    size_t len;
    size_t cap;
    struct OpenasmSection *sections;

    size_t section;
    
    struct OpenasmPoolQueue pool;

    int sym;
    struct OpenasmSymbolTable symtable;
};

struct OpenasmEntry {
    const char *mnem;
    // this inst_table doesn't use `OpenasmBuffer *` to allow the caller to use any arguments
    int (**inst_table)(/* OpenasmBuffer * */);
};

enum {
    OPENASM_OP_REG,
    OPENASM_OP_IMM,
};

union OpenasmOperand {
    uint32_t tag;
    uint64_t bytes;
    struct {
	uint32_t _pad1;
	uint8_t reg;
    };
    struct {
	uint32_t _pad2;
	uint32_t imm;
    };
};

/* useful defines */
#define OPENASM_MAX_SIZE 4
#define OPENASM_OPPRE (0x1 << 8)
#define OPENASM_OPOFF (0x0 << 8)
#define OPENASM_OPPOST (0x3 << 8)
#define OPENASM_OPSIZE(s) ((s >> 5) & ((uint32_t) 0x3))
#define OPENASM_OPMASK ((uint32_t) 0x3f)
#define OPENASM_MASKOP(x) (x & OPENASM_OPMASK)
#define OPENASM_OP0(s) (OPENASM_OPSIZE(s) << 6)
#define OPENASM_OP1(s, x) ((OPENASM_OPSIZE(s) << 6) | (x & 1))
#define OPENASM_OP2(s, x, y) ((OPENASM_OPSIZE(s) << 6) | ((x & 1) << 1) | (y & 1))
#define OPENASM_OP3(s, x, y, z) ((OPENASM_OPSIZE(s) << 6) | ((x & 1) << 2) | ((y & 1) << 1) | (z & 1))
#define OPENASM_OP4(s, x, y, z, w) \
    ((OPENASM_OPSIZE(s) << 6) | ((x & 1) << 3) | ((y & 1) << 2) | ((z & 1) << 1) | (w & 1))
#define OPENASM_OP4_IDX(idx, s, x, y, z, w) \
    (idx | (OPENASM_OPSIZE(s) << 6) | ((x & 1) << 3) | ((y & 1) << 2) | ((z & 1) << 1) | (w & 1))
#define OPENASM_OP5(s, x, y, z, w, u) \
    ((OPENASM_OPSIZE(s) << 6) | ((x & 1) << 4) | ((y & 1) << 3) | ((z & 1) << 2) | ((w & 1) << 1) | (u & 1))
#define OPENASM_OP6(s, x, y, z, w, u, v) \
    ((OPENASM_OPSIZE(s) << 6) | ((x & 1) << 5) | ((y & 1) << 4) | ((z & 1) << 3) \
                      | ((w & 1) << 2) | ((u & 1) << 1) | (v & 1))

/* aarch32/64 registers (5 bits each) */
#define OPENASM_R32_W(n) (n & ((uint32_t) 0x1f))
#define OPENASM_R64_X(n) (n & ((uint32_t) 0x1f))
#define OPENASM_R32_WZR OPENASM_R32_W(31) /* only valid in integer instructions */
#define OPENASM_R64_XZR OPENASM_R64_X(31) /* only valid in integer instructions */
#define OPENASM_R64_FP OPENASM_R64_X(29)
#define OPENASM_R64_LR OPENASM_R64_X(30)
#define OPENASM_R64_SP OPENASM_R64_X(31) /* system register since ARMv8a, but sometimes a valid gpr */
/* aarch32/64 fp/vector registers (5 bits each) */
#define OPENASM_R8_B(n) (n & ((uint32_t) 0x1f))
#define OPENASM_R16_H(n) (n & ((uint32_t) 0x1f))
#define OPENASM_R32_S(n) (n & ((uint32_t) 0x1f))
#define OPENASM_R64_D(n) (n & ((uint32_t) 0x1f))
#define OPENASM_R128_Q(n) (n & ((uint32_t) 0x1f))
#define OPENASM_R128_V(n) (n & ((uint32_t) 0x1f))

/* condition codes */
#define OPENASM_COND_EQ ((uint32_t) 0x0)
#define OPENASM_COND_NE ((uint32_t) 0x1)
#define OPENASM_COND_CS ((uint32_t) 0x2)
#define OPENASM_COND_HS ((uint32_t) 0x2)
#define OPENASM_COND_CC ((uint32_t) 0x3)
#define OPENASM_COND_LO ((uint32_t) 0x3)
#define OPENASM_COND_MI ((uint32_t) 0x4)
#define OPENASM_COND_PL ((uint32_t) 0x5)
#define OPENASM_COND_VS ((uint32_t) 0x6)
#define OPENASM_COND_VC ((uint32_t) 0x7)
#define OPENASM_COND_HI ((uint32_t) 0x8)
#define OPENASM_COND_LS ((uint32_t) 0x9)
#define OPENASM_COND_GE ((uint32_t) 0xa)
#define OPENASM_COND_LT ((uint32_t) 0xb)
#define OPENASM_COND_GT ((uint32_t) 0xc)
#define OPENASM_COND_LE ((uint32_t) 0xd)
#define OPENASM_COND_AL ((uint32_t) 0xe)
#define OPENASM_COND_NV ((uint32_t) 0xf)

/* opcodes */
// shift these left by 25
#define OPENASM_OP0_RESERVED ((uint32_t) 0x0)
#define OPENASM_OP0_UNALLOCATED0 ((uint32_t) 0x1)
#define OPENASM_OP0_SVE ((uint32_t) 0x2)
#define OPENASM_OP0_UNALLOCATED1 ((uint32_t) 0x3)
#define OPENASM_OP0_DPIMM ((uint32_t) 0x8)
#define OPENASM_OP0_BR ((uint32_t) 0xa)
#define OPENASM_OP0_LS ((uint32_t) 0x4)
#define OPENASM_OP0_DPREG ((uint32_t) 0x5)
#define OPENASM_OP0_DPFP ((uint32_t) 0x7)
/* opcodes: data processing immediate */
// shift these left by 23
#define OPENASM_DPIMM_REL ((uint32_t) 0x0)
#define OPENASM_DPIMM_ADD ((uint32_t) 0x2)
#define OPENASM_DPIMM_ADT ((uint32_t) 0x3)
#define OPENASM_DPIMM_LOG ((uint32_t) 0x4)
#define OPENASM_DPIMM_MOV ((uint32_t) 0x5)
#define OPENASM_DPIMM_BIT ((uint32_t) 0x6)
#define OPENASM_DPIMM_EXT ((uint32_t) 0x7)
/* opcodes: data processing immediate: PC-rel. addresing */
#define OPENASM_DPIMM_ADR 0
#define OPENASM_DPIMM_ADRP 1
#define OPENASM_ENCODE_DPIMM_REL(op, imm, rd) \
  (((((uint32_t) (op)) & 1) << 31) \
  | ((((uint32_t) (imm)) & ((uint32_t) 0x3)) << 29) \
  | (OPENASM_OP0_DPIMM << 25) \
  | (OPENASM_DPIMM_REL << 23) \
  | (((((uint32_t) (imm)) >> 2) & ((uint32_t) 0x7ffff)) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: add/subtract (immediate) */
#define OPENASM_DPIMM_ADD32 ((uint32_t) 0x0)
#define OPENASM_DPIMM_ADDS32 ((uint32_t) 0x1)
#define OPENASM_DPIMM_SUB32 ((uint32_t) 0x2)
#define OPENASM_DPIMM_SUBS32 ((uint32_t) 0x3)
#define OPENASM_DPIMM_ADD64 ((uint32_t) 0x4)
#define OPENASM_DPIMM_ADDS64 ((uint32_t) 0x5)
#define OPENASM_DPIMM_SUB64 ((uint32_t) 0x6)
#define OPENASM_DPIMM_SUBS64 ((uint32_t) 0x7)
#define OPENASM_ENCODE_DPIMM_ADD(op, sh, imm, rn, rd) \
  (((((uint32_t) (op)) & ((uint32_t) 0x7)) << 29) \
  | (OPENASM_OP0_DPIMM << 25) \
  | (OPENASM_DPIMM_ADD << 23) \
  | ((sh & 1) << 22) \
  | ((((uint32_t) (imm)) & ((uint32_t) 0xfff)) << 10) \
  | (OPENASM_R64_X(rn) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: add/subtract (immediate, with tags) */
// these two require FEAT_MTE
#define OPENASM_DPIMM_ADDG64 ((uint32_t) 0x8)
#define OPENASM_DPIMM_SUBG64 ((uint32_t) 0xc)
#define OPENASM_ENCODE_DPIMM_ADT(op, uimm6, op3, uimm4, rn, rd)	\
  ((((((uint32_t) (op)) >> 1) & ((uint32_t) 0x7)) << 29) \
  | (OPENASM_OP0_DPIMM << 25) \
  | (OPENASM_DPIMM_ADT << 23) \
  | ((((uint32_t) (op)) & 1) << 22) \
  | ((uimm6 & ((uint32_t) 0x3f)) << 16) \
  | ((op3 & ((uint32_t) 0x3)) << 14) \
  | ((uimm4 & ((uint32_t) 0xf)) << 10) \
  | (OPENASM_R64_X(rn) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: logical (immediate) */
#define OPENASM_DPIMM_AND32 ((uint32_t) 0x0)
#define OPENASM_DPIMM_ORR32 ((uint32_t) 0x2)
#define OPENASM_DPIMM_EOR32 ((uint32_t) 0x4)
#define OPENASM_DPIMM_ANDS32 ((uint32_t) 0x6)
#define OPENASM_DPIMM_AND64 ((uint32_t) 0x8)
#define OPENASM_DPIMM_ORR64 ((uint32_t) 0xa)
#define OPENASM_DPIMM_EOR64 ((uint32_t) 0xc)
#define OPENASM_DPIMM_ANDS64 ((uint32_t) 0xe)
#define OPENASM_ENCODE_DPIMM_LOG(op, imm, rn, rd) \
  ((((((uint32_t) (op)) >> 1) & ((uint32_t) 0x7)) << 29) \
  | (OPENASM_OP0_DPIMM << 25) \
  | (OPENASM_DPIMM_LOG << 23) \
  | ((((uint32_t) (op)) & ((uint32_t) 0x8))? (((uint32_t) (imm)) & ((uint32_t) 0x1000)) : 0) \
  | ((((uint32_t) (imm)) & ((uint32_t) 0xfff)) << 10) \
  | (OPENASM_R64_X(rn) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: move wide (immediate) */
#define OPENASM_DPIMM_MOVN32 ((uint32_t) 0x0)
#define OPENASM_DPIMM_MOVZ32 ((uint32_t) 0x8)
#define OPENASM_DPIMM_MOVK32 ((uint32_t) 0xc)
#define OPENASM_DPIMM_MOVN64 ((uint32_t) 0x10)
#define OPENASM_DPIMM_MOVZ64 ((uint32_t) 0x18)
#define OPENASM_DPIMM_MOVK64 ((uint32_t) 0x1c)
#define OPENASM_ENCODE_DPIMM_MOV(op, imm16, rd) \
  ((((((uint32_t) (op)) >> 2) & ((uint32_t) 0x7)) << 29) \
  | (OPENASM_OP0_DPIMM << 25) \
  | (OPENASM_DPIMM_MOV << 23) \
  | ((((uint32_t) (op)) & 0x3) << 21) \
  | ((imm16 & ((uint32_t) 0xffff)) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: bitfield */
#define OPENASM_DPIMM_SBFM32 ((uint32_t) 0x0)
#define OPENASM_DPIMM_BFM32 ((uint32_t) 0x2)
#define OPENASM_DPIMM_UBFM32 ((uint32_t) 0x4)
#define OPENASM_DPIMM_SBFM64 ((uint32_t) 0x9)
#define OPENASM_DPIMM_BFM64 ((uint32_t) 0xb)
#define OPENASM_DPIMM_UBFM64 ((uint32_t) 0xd)
#define OPENASM_ENCODE_DPIMM_BIT(op, imm, rn, rd) \
  ((((((uint32_t) (op)) >> 1) & ((uint32_t) 0x7)) << 29) \
  | (OPENASM_OP0_DPIMM << 25) \
  | (OPENASM_DPIMM_BIT << 23) \
  | ((((uint32_t) (op)) & ((uint32_t) 0x8))? (((uint32_t) (imm)) & ((uint32_t) 0x1000)) : 0) \
  | ((((uint32_t) (imm)) & ((uint32_t) 0xfff)) << 10) \
  | (OPENASM_R64_X(rn) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: data processing immediate: extract */
#define OPENASM_DPIMM_EXTR32 ((uint32_t) 0x0)
#define OPENASM_DPIMM_EXTR64 ((uint32_t) 0x12)
#define OPENASM_ENCODE_DPIMM_EXT(op, rm, imms, rn, rd) \
  ((((((uint32_t) (op)) >> 1) & ((uint32_t) 0x7)) << 29) \
  | (OPENASM_OP0_DPIMM << 25) \
  | (OPENASM_DPIMM_EXT << 23) \
  | ((((uint32_t) (op)) & ((uint32_t) 0x3)) << 21) \
  | (OPENASM_R64_X(rm) << 16) \
  | ((imms & ((uint32_t) 0x3f)) << 10) \
  | (OPENASM_R64_X(rn) << 5) \
  | (OPENASM_R64_X(rd)))
/* opcodes: branches and exceptions */
// shift these left by 12
#define OPENASM_BR_COND ((uint32_t) 0x8000)
#define OPENASM_BR_EXCEPT ((uint32_t) 0x18000)
#define OPENASM_BR_SYS1 ((uint32_t) 0x19031)
#define OPENASM_BR_HINT ((uint32_t) 0x19032)
#define OPENASM_BR_HINT_OP2 ((uint32_t) 0x1f)
#define OPENASM_BR_BARR ((uint32_t) 0x19033)
#define OPENASM_BR_PSTATE ((uint32_t) 0x19004)
#define OPENASM_BR_SYS2 ((uint32_t) 0x19080)
#define OPENASM_BR_SYS3 ((uint32_t) 0x19100)
#define OPENASM_BR_UNCOND1 ((uint32_t) 0x1a000)
#define OPENASM_BR_UNCOND2 ((uint32_t) 0x0)
#define OPENASM_BR_CMP ((uint32_t) 0x4000)
#define OPENASM_BR_TEST ((uint32_t) 0x6000)
/* opcodes: branches and exceptions: conditional branches */
#define OPENASM_BR_B_COND 0
#define OPENASM_BR_BL_COND 1
#define OPENASM_ENCODE_BR_COND(op, imm19, cond) \
  ((((OPENASM_BR_COND >> 13) & ((uint32_t) 0xe)) << 28) \
  | (((OPENASM_BR_COND >> 13) & ((uint32_t) 0x1)) << 25) \
  | (OPENASM_OP0_BR << 25) \
  | (((((uint32_t) (op)) >> 1) & ((uint32_t) 0x1)) << 24) \
  | ((imm19 & ((uint32_t) 0x7ffff)) << 5) \
  | ((((uint32_t) (op)) & 1) << 4) \
  | (cond & ((uint32_t) 0xf)))
/* opcodes: branches and exceptions: exceptions */
#define OPENASM_BR_SVC ((uint32_t) 0x1)
#define OPENASM_BR_HVC ((uint32_t) 0x2)
#define OPENASM_BR_SMC ((uint32_t) 0x3)
#define OPENASM_BR_BRK ((uint32_t) 0x20)
#define OPENASM_BR_HLT ((uint32_t) 0x40)
#define OPENASM_BR_DCPS1 ((uint32_t) 0xa1)
#define OPENASM_BR_DCPS2 ((uint32_t) 0xa2)
#define OPENASM_BR_DCPS3 ((uint32_t) 0xa3)
#define OPENASM_ENCODE_BR_EXCEPT(op, imm16) \
  ((((OPENASM_BR_EXCEPT >> 13) & ((uint32_t) 0xe)) << 28) \
  | (((OPENASM_BR_EXCEPT >> 13) & ((uint32_t) 0x1)) << 25) \
  | (OPENASM_OP0_BR << 25) \
  | (((((uint32_t) (op)) >> 5) & ((uint32_t) 0x7)) << 21) \
  | ((imm16 & ((uint32_t) 0xffff)) << 5) \
  | (((uint32_t) (op)) & ((uint32_t) 0x1f)))
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
#define OPENASM_BR_BR ((uint32_t) 0x0f800)
#define OPENASM_BR_RET ((uint32_t) 0x2f800)
#define OPENASM_ENCODE_BR_UNCOND1(op, rn) \
  ((((OPENASM_BR_UNCOND1 >> 13) & ((uint32_t) 0xe)) << 28) \
  | (((OPENASM_BR_UNCOND1 >> 13) & ((uint32_t) 0x1)) << 25) \
  | (OPENASM_OP0_BR << 25) \
  | (((((uint32_t) (op)) >> 5) & ((uint32_t) 0x7fff)) << 10) \
  | (((uint32_t) (op)) & ((uint32_t) 0x1f)) \
  | (OPENASM_R64_X(rn) << 5))

/* opcodes: branches and exceptions: unconditional branches (immediate) */
#define OPENASM_BR_B 0
#define OPENASM_BR_BL 1
#define OPENASM_ENCODE_BR_UNCOND2(op, imm26) \
  ((((OPENASM_BR_UNCOND2 >> 13) & ((uint32_t) 0xe)) << 28) \
  | (((OPENASM_BR_UNCOND2 >> 13) & ((uint32_t) 0x1)) << 25) \
  | ((((uint32_t) (op)) & 1) << 31) \
  | (OPENASM_OP0_BR << 25) \
  | (imm26 & ((uint32_t) 0x3ffffff)))

/* opcodes: branches and exceptions: compare and branch (immediate) */
/* NOTE: skipped */

/* opcodes: branches and exceptions: test and branch (immediate) */
/* NOTE: skipped */

/* opcodes: loads and stores */
/* NOTE: SIMD was skipped */
#define OPENASM_LS_LSTAG 0x6a80
#define OPENASM_LS_LSEX 0x0
#define OPENASM_LS_LSUI 0xa00
#define OPENASM_LS_LDLIT 0x800
#define OPENASM_LS_LSNAPO 0x1000
#define OPENASM_LS_LSRPPOST 0x1200
#define OPENASM_LS_LSRPO 0x1400
#define OPENASM_LS_LSRPPRE 0x1600
#define OPENASM_LS_LSRUI 0x1800
#define OPENASM_LS_LSRIPOST 0x1801
#define OPENASM_LS_LSRUNP 0x1802
#define OPENASM_LS_LSRIPRE 0x1803
#define OPENASM_LS_ATOM 0x1880
#define OPENASM_LS_LSRRO 0x1882
#define OPENASM_LS_LSRPAC 0x1881
#define OPENASM_LS_LSRUSI 0x1a00

/* NOTE: some instructions where skipped */

/* opcodes: loads and stores: load register (literal) */
#define OPENASM_LS_LDR32 0x0
#define OPENASM_LS_LDR32V 0x1
#define OPENASM_LS_LDR64 0x2
#define OPENASM_LS_LDR64V 0x3
#define OPENASM_LS_LDRSW 0x4
#define OPENASM_LS_LDR128V 0x5
#define OPENASM_LS_PRFM 0x6
#define OPENASM_ENCODE_LS_LDLIT(op, imm19, rt) \
    ((((op >> 1) & 0x3) << 30) \
    | ((op & 1) << 26) \
    | (OPENASM_OP0_LS << 25) \
    | (((OPENASM_LS_LDLIT >> 11) & 0xf) << 28) \
    | (((OPENASM_LS_LDLIT >> 10) & 1) << 26) \
    | (((OPENASM_LS_LDLIT >> 8) & 0x3) << 23) \
    | (((OPENASM_LS_LDLIT >> 2) & 0x3f) << 16) \
    | ((OPENASM_LS_LDLIT & 0x3) << 10) \
    | ((imm19 & 0x7ffff) << 5) \
    | (OPENASM_R64_X(rt)))
/* opcodes: loads and stores: load/store no-allocate pair (offset) */
#define OPENASM_LS_STNP32 0x0
#define OPENASM_LS_LDNP32 0x1
#define OPENASM_LS_STNP32V 0x2
#define OPENASM_LS_LDNP32V 0x3
#define OPENASM_LS_STNP64V 0x6
#define OPENASM_LS_LDNP64V 0x7
#define OPENASM_LS_STNP64 0x8
#define OPENASM_LS_LDNP64 0x9
#define OPENASM_LS_STNP128V 0xa
#define OPENASM_LS_LDNP128V 0xb
#define OPENASM_ENCODE_LS_NAPO(op, imm7, rn, rt1, rt2) \
    ((((op >> 2) & 0x3) << 30) \
    | (((op >> 1) & 1) << 26) \
    | ((op & 1) << 22) \
    | (OPENASM_OP0_LS << 25) \
    | (((OPENASM_LS_LSNAPO >> 11) & 0xf) << 28) \
    | (((OPENASM_LS_LSNAPO >> 10) & 1) << 26) \
    | (((OPENASM_LS_LSNAPO >> 8) & 0x3) << 23) \
    | (((OPENASM_LS_LSNAPO >> 2) & 0x3f) << 16) \
    | ((OPENASM_LS_LSNAPO & 0x3) << 10) \
    | ((imm7 & 0x7f) << 15) \
    | (OPENASM_R64_X(rn) << 5) \
    | (OPENASM_R64_X(rt1) << 10) \
    | (OPENASM_R64_X(rt2)))
/* opcodes: loads and stores: load/store register pair (post-indexed) */
#define OPENASM_LS_STP32 0x0
#define OPENASM_LS_LDP32 0x1
#define OPENASM_LS_STP32V 0x2
#define OPENASM_LS_LDP32V 0x3
#define OPENASM_LS_STGP 0x4 /* FEAT_MTE */
#define OPENASM_LS_LDPSW 0x5
#define OPENASM_LS_STP64V 0x6
#define OPENASM_LS_LDP64V 0x7
#define OPENASM_LS_STP64 0x8
#define OPENASM_LS_LDP64 0x9
#define OPENASM_LS_STP128V 0xa
#define OPENASM_LS_LDP128V 0xb
#define OPENASM_ENCODE_LS_RPPOST(op, imm7, rn, rt1, rt2) \
    ((((op >> 2) & 0x3) << 30) \
    | (((op >> 1) & 1) << 26) \
    | ((op & 1) << 22) \
    | (OPENASM_OP0_LS << 25) \
    | (((OPENASM_LS_LSRPPOST >> 11) & 0xf) << 28) \
    | (((OPENASM_LS_LSRPPOST >> 10) & 1) << 26) \
    | (((OPENASM_LS_LSRPPOST >> 8) & 0x3) << 23) \
    | (((OPENASM_LS_LSRPPOST >> 2) & 0x3f) << 16) \
    | ((OPENASM_LS_LSRPPOST & 0x3) << 10) \
    | ((imm7 & 0x7f) << 15) \
    | (OPENASM_R64_X(rn) << 5) \
    | (OPENASM_R64_X(rt2) << 10) \
    | (OPENASM_R64_X(rt1)))
/* opcodes: loads and stores: load/store register pair (offset) */
/* NOTE: identical opcodes to load/store register pair (post-indexed) */
/* #define OPENASM_LS_STP32 0x0 */
/* #define OPENASM_LS_LDP32 0x1 */
/* #define OPENASM_LS_STP32V 0x2 */
/* #define OPENASM_LS_LDP32V 0x3 */
/* #define OPENASM_LS_STGP 0x4 /\* FEAT_MTE *\/ */
/* #define OPENASM_LS_LDPSW 0x5 */
/* #define OPENASM_LS_STP64V 0x6 */
/* #define OPENASM_LS_LDP64V 0x7 */
/* #define OPENASM_LS_STP64 0x8 */
/* #define OPENASM_LS_LDP64 0x9 */
/* #define OPENASM_LS_STP128V 0xa */
/* #define OPENASM_LS_LDP128V 0xb */
#define OPENASM_ENCODE_LS_RPO(op, imm7, rn, rt1, rt2) \
    ((((op >> 2) & 0x3) << 30) \
    | (((op >> 1) & 1) << 26) \
    | ((op & 1) << 22) \
    | (OPENASM_OP0_LS << 25) \
    | (((OPENASM_LS_LSRPO >> 11) & 0xf) << 28) \
    | (((OPENASM_LS_LSRPO >> 10) & 1) << 26) \
    | (((OPENASM_LS_LSRPO >> 8) & 0x3) << 23) \
    | (((OPENASM_LS_LSRPO >> 2) & 0x3f) << 16) \
    | ((OPENASM_LS_LSRPO & 0x3) << 10) \
    | ((imm7 & 0x7f) << 15) \
    | (OPENASM_R64_X(rn) << 5) \
    | (OPENASM_R64_X(rt2) << 10) \
    | (OPENASM_R64_X(rt1)))
/* opcodes: loads and stores: load/store register pair (pre-indexed) */
/* NOTE: identical opcodes to load/store register pair (post-indexed) */
/* #define OPENASM_LS_STP32 0x0 */
/* #define OPENASM_LS_LDP32 0x1 */
/* #define OPENASM_LS_STP32V 0x2 */
/* #define OPENASM_LS_LDP32V 0x3 */
/* #define OPENASM_LS_STGP 0x4 /\* FEAT_MTE *\/ */
/* #define OPENASM_LS_LDPSW 0x5 */
/* #define OPENASM_LS_STP64V 0x6 */
/* #define OPENASM_LS_LDP64V 0x7 */
/* #define OPENASM_LS_STP64 0x8 */
/* #define OPENASM_LS_LDP64 0x9 */
/* #define OPENASM_LS_STP128V 0xa */
/* #define OPENASM_LS_LDP128V 0xb */
#define OPENASM_ENCODE_LS_RPPRE(op, imm7, rn, rt1, rt2) \
    ((((op >> 2) & 0x3) << 30) \
    | (((op >> 1) & 1) << 26) \
    | ((op & 1) << 22) \
    | (OPENASM_OP0_LS << 25) \
    | (((OPENASM_LS_LSRPPRE >> 11) & 0xf) << 28) \
    | (((OPENASM_LS_LSRPPRE >> 10) & 1) << 26) \
    | (((OPENASM_LS_LSRPPRE >> 8) & 0x3) << 23) \
    | (((OPENASM_LS_LSRPPRE >> 2) & 0x3f) << 16) \
    | ((OPENASM_LS_LSRPPRE & 0x3) << 10) \
    | ((imm7 & 0x7f) << 15) \
    | (OPENASM_R64_X(rn) << 5) \
    | (OPENASM_R64_X(rt2) << 10) \
    | (OPENASM_R64_X(rt1)))
/* opcodes: loads and stores: load/store register (unscaled immediate) */
#define OPENASM_LS_STURB 0x0
#define OPENASM_LS_LDURB 0x1
#define OPENASM_LS_LDURSB64 0x2
#define OPENASM_LS_LDURSB32 0x3
#define OPENASM_LS_STUR8V 0x4
#define OPENASM_LS_LDUR8V 0x5
#define OPENASM_LS_STUR128V 0x6
#define OPENASM_LS_LDUR128V 0x7
#define OPENASM_LS_STURH 0x8
#define OPENASM_LS_LDURH 0x9
#define OPENASM_LS_LDURSH64 0xa
#define OPENASM_LS_LDURSH32 0xb
#define OPENASM_LS_STUR16V 0xc
#define OPENASM_LS_LDUR16V 0xd
#define OPENASM_LS_STUR32 0x10
#define OPENASM_LS_LDUR32 0x11
#define OPENASM_LS_LDURSW 0x12
#define OPENASM_LS_STUR32V 014
#define OPENASM_LS_LDUR32V 0x15
#define OPENASM_LS_STUR64 0x18
#define OPENASM_LS_LDUR64 0x19
#define OPENASM_LS_PRFUM 0x1a
#define OPENASM_LS_STUR64V 0x1c
#define OPENASM_LS_LDUR64V 0x1d
#define OPENASM_ENCODE_LS_RUI(op, imm7, rn, rt1, rt2) \
    ((((op >> 3) & 0x3) << 30) \
    | (((op >> 2) & 1) << 26) \
    | ((op & 0x3) << 22) \
    | (OPENASM_OP0_LS << 25) \
    | (((OPENASM_LS_LSRUI >> 11) & 0xf) << 28) \
    | (((OPENASM_LS_LSRUI >> 10) & 1) << 26) \
    | (((OPENASM_LS_LSRUI >> 8) & 0x3) << 23) \
    | (((OPENASM_LS_LSRUI >> 2) & 0x3f) << 16) \
    | ((OPENASM_LS_LSRUI & 0x3) << 10) \
    | ((imm7 & 0x7f) << 15) \
    | (OPENASM_R64_X(rn) << 5) \
    | (OPENASM_R64_X(rt2) << 10) \
    | (OPENASM_R64_X(rt1)))
/* opcodes: loads and stores: load/store register (immediate post-indexed) */
#define OPENASM_LS_I_STRB 0x0
#define OPENASM_LS_I_LDRB 0x1
#define OPENASM_LS_I_LDRSB64 0x2
#define OPENASM_LS_I_LDRSB32 0x3
#define OPENASM_LS_I_STR8V 0x4
#define OPENASM_LS_I_LDR8V 0x5
#define OPENASM_LS_I_STR128V 0x6
#define OPENASM_LS_I_LDR128V 0x7
#define OPENASM_LS_I_STRH 0x8
#define OPENASM_LS_I_LDRH 0x9
#define OPENASM_LS_I_LDRSH64 0xa
#define OPENASM_LS_I_LDRSH32 0xb
#define OPENASM_LS_I_STR16V 0xc
#define OPENASM_LS_I_LDR16V 0xd
#define OPENASM_LS_I_STR32 0x10
#define OPENASM_LS_I_LDR32 0x11
#define OPENASM_LS_I_LDRSW 0x12
#define OPENASM_LS_I_STR32V 014
#define OPENASM_LS_I_LDR32V 0x15
#define OPENASM_LS_I_STR64 0x18
#define OPENASM_LS_I_LDR64 0x19
#define OPENASM_LS_I_STR64V 0x1c
#define OPENASM_LS_I_LDR64V 0x1d
#define OPENASM_ENCODE_LS_RIPOST(op, imm7, rn, rt1, rt2) \
    ((((op >> 3) & 0x3) << 30) \
    | (((op >> 2) & 1) << 26) \
    | ((op & 0x3) << 22) \
    | (OPENASM_OP0_LS << 25) \
    | (((OPENASM_LS_LSRIPOST >> 11) & 0xf) << 28) \
    | (((OPENASM_LS_LSRIPOST >> 10) & 1) << 26) \
    | (((OPENASM_LS_LSRIPOST >> 8) & 0x3) << 23) \
    | (((OPENASM_LS_LSRIPOST >> 2) & 0x3f) << 16) \
    | ((OPENASM_LS_LSRIPOST & 0x3) << 10) \
    | ((imm7 & 0x7f) << 15) \
    | (OPENASM_R64_X(rn) << 5) \
    | (OPENASM_R64_X(rt2) << 10) \
    | (OPENASM_R64_X(rt1)))
/* opcodes: loads and stores: load/store register (unprivileged) */
/* NOTE: skipped */
/* opcodes: loads and stores: load/store register (immediate pre-indexed) */
/* NOTE: identical opcodes to load/store register (immediate post-indexed) */
/* #define OPENASM_LS_I_STRB 0x0 */
/* #define OPENASM_LS_I_LDRB 0x1 */
/* #define OPENASM_LS_I_LDRSB64 0x2 */
/* #define OPENASM_LS_I_LDRSB32 0x3 */
/* #define OPENASM_LS_I_STR8V 0x4 */
/* #define OPENASM_LS_I_LDR8V 0x5 */
/* #define OPENASM_LS_I_STR128V 0x6 */
/* #define OPENASM_LS_I_LDR128V 0x7 */
/* #define OPENASM_LS_I_STRH 0x8 */
/* #define OPENASM_LS_I_LDRH 0x9 */
/* #define OPENASM_LS_I_LDRSH64 0xa */
/* #define OPENASM_LS_I_LDRSH32 0xb */
/* #define OPENASM_LS_I_STR16V 0xc */
/* #define OPENASM_LS_I_LDR16V 0xd */
/* #define OPENASM_LS_I_STR32 0x10 */
/* #define OPENASM_LS_I_LDR32 0x11 */
/* #define OPENASM_LS_I_LDRSW 0x12 */
/* #define OPENASM_LS_I_STR32V 014 */
/* #define OPENASM_LS_I_LDR32V 0x15 */
/* #define OPENASM_LS_I_STR64 0x18 */
/* #define OPENASM_LS_I_LDR64 0x19 */
/* #define OPENASM_LS_I_STR64V 0x1c */
/* #define OPENASM_LS_I_LDR64V 0x1d */
#define OPENASM_ENCODE_LS_RIPRE(op, imm7, rn, rt1, rt2) \
    ((((op >> 3) & 0x3) << 30) \
    | (((op >> 2) & 1) << 26) \
    | ((op & 0x3) << 22) \
    | (OPENASM_OP0_LS << 25) \
    | (((OPENASM_LS_LSRIPRE >> 11) & 0xf) << 28) \
    | (((OPENASM_LS_LSRIPRE >> 10) & 1) << 26) \
    | (((OPENASM_LS_LSRIPRE >> 8) & 0x3) << 23) \
    | (((OPENASM_LS_LSRIPRE >> 2) & 0x3f) << 16) \
    | ((OPENASM_LS_LSRIPRE & 0x3) << 10) \
    | ((imm7 & 0x7f) << 15) \
    | (OPENASM_R64_X(rn) << 5) \
    | (OPENASM_R64_X(rt2) << 10) \
    | (OPENASM_R64_X(rt1)))
/* opcodes: loads and stores: atomic memory operations */
/* NOTE: skipped */

/* function declarations */
// NOTE: should void.h also declare openasm_buffer and openasm_del_buffer?
void openasm_buffer(OpenasmBuffer *buf);
void openasm_del_buffer(OpenasmBuffer *buf);

void openasm_write(OpenasmBuffer *buf, uint32_t instr);

int openasm_instf(OpenasmBuffer *buf, const char *fmt, ...);
int openasm_instfv(OpenasmBuffer *buf, const char *fmt, va_list args);
size_t openasm_pool(OpenasmBuffer *buf, uint64_t value);
void openasm_flush_pool(OpenasmBuffer *buf);
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
int openasm_and32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_orr32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_eor32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_ands32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_and64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_orr64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_eor64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_ands64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_movn32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_movz32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_movk32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_movn64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_movz64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_movk64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm);
int openasm_sbfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_bfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_ubfm32_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_sbfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_bfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
int openasm_ubfm64_imm(OpenasmBuffer *buf, uint8_t rd, uint8_t rn, uint32_t imm);
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

int openasm_ldr32(OpenasmBuffer *buf, uint8_t rt, uint32_t imm);
int openasm_ldr32v(OpenasmBuffer *buf, uint8_t rt, uint32_t imm);
int openasm_ldr64(OpenasmBuffer *buf, uint8_t rt, uint32_t imm);
int openasm_ldr64v(OpenasmBuffer *buf, uint8_t rt, uint32_t imm);
int openasm_ldrsw(OpenasmBuffer *buf, uint8_t rt, uint32_t imm);
int openasm_ldr128v(OpenasmBuffer *buf, uint8_t rt, uint32_t imm);
int openasm_prfm(OpenasmBuffer *buf, uint8_t rt, uint32_t imm);

int openasm_stnp32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldnp32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stnp32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldnp32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stnp64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldnp64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stnp64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldnp64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stnp128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldnp128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
    
int openasm_stp32_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp32_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp32v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp32v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stgp_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldpsw_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp64v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp64v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp64_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp64_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp128v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp128v_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
    
int openasm_stp32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stgp(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldpsw(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
    
int openasm_stp32_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp32_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp32v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp32v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stgp_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldpsw_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp64v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp64v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp64_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp64_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stp128v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldp128v_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
    
int openasm_sturb(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldurb(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldursb64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldursb32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stur8v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldur8v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stur128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldur128v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_sturh(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldurh(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldursh64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldursh32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stur16v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldur16v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stur32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldur32(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldursw(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stur32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldur32v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stur64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldur64(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_prfum(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_stur64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldur64v(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);

int openasm_strb_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrb_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrsb64_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrsb32_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str8v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr8v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str128v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr128v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_strh_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrh_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrsh64_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrsh32_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str16v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr16v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str32_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr32_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrsw_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str32v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr32v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str64_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr64_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str64v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr64v_imm_post(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);

int openasm_strb_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrb_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrsb64_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrsb32_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str8v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr8v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str128v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr128v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_strh_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrh_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrsh64_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrsh32_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str16v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr16v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str32_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr32_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldrsw_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str32v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr32v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str64_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr64_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_str64v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);
int openasm_ldr64v_imm_pre(OpenasmBuffer *buf, uint8_t rn, uint8_t rt1, uint8_t rt2, uint32_t imm);

/* aliases */
int openasm_cmp32_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm, int sh); /* subs32_imm alias */
int openasm_cmp64_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm, int sh); /* subs64_imm alias */
int openasm_mov32_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm); /* orr32_imm alias */ 
int openasm_mov32_r(OpenasmBuffer *buf, uint8_t rd, uint8_t rn); /* orr32_imm alias */ 
int openasm_tst32_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm); /* ands32_imm alias */
int openasm_mov64_imm(OpenasmBuffer *buf, uint8_t rd, uint32_t imm); /* orr64_imm alias */ 
int openasm_mov64_r(OpenasmBuffer *buf, uint8_t rd, uint8_t rn); /* orr64_imm alias */ 
int openasm_tst64_imm(OpenasmBuffer *buf, uint8_t rn, uint32_t imm); /* ands64_imm alias */

extern struct OpenasmEntry openasm_inst[];

#endif /* OPENASM_ARCH_H */
