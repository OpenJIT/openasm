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
    uint8_t *buffer;
};

struct OpenasmBuffer {
    size_t len;
    size_t cap;
    struct OpenasmSection *sections;
    
    size_t section;

    int sym;
    struct OpenasmSymbolTable symtable;
    struct OpenasmSymbolTable export;
    
    int has_legacy_prefix;
    int has_rex_prefix;
    int has_opcode;
    int has_modrm;
    int has_sib;
    int has_disp;
    int has_imm;
    size_t size;
};

struct OpenasmProperty {
    // the mnemonic for an instruction
    const char *mnemonic;
    // size of the opcode
    size_t size;
    // is this opcode an escape character?
    int escape;
    // does this opcode require a ModR/M?
    int modrm;
    // does this opcode have an immediate value?
    int imm;
};

enum {
    OPENASM_OP_AL,
    OPENASM_OP_AX,
    OPENASM_OP_EAX,
    OPENASM_OP_RAX,
    OPENASM_OP_REG8,
    OPENASM_OP_REG16,
    OPENASM_OP_REG32,
    OPENASM_OP_REG64,
    OPENASM_OP_IMM8,
    OPENASM_OP_IMM16,
    OPENASM_OP_IMM32,
    OPENASM_OP_IMM64,
    OPENASM_OP_MEMORY8,
    OPENASM_OP_MEMORY16,
    OPENASM_OP_MEMORY32,
    OPENASM_OP_MEMORY64,
};

enum {
    OPENASM_AUX_NONE = 0x0,
    OPENASM_AUX_REXR = 0x1,
    OPENASM_AUX_REXB = 0x2,
    OPENASM_AUX_REXX = 0x4,
};

struct OpenasmReg {
    const char *reg;
    int rexw;
    int rexr;
};

struct OpenasmMemory {
    struct OpenasmReg base;
    struct OpenasmReg index;
    uint64_t scale;
    int64_t disp;
};

struct OpenasmOperand {
    unsigned int tag;
    union {
        struct OpenasmReg reg;
        uint64_t imm;
        struct OpenasmMemory mem;
    };
};

struct OpenasmEntry {
    const char *mnem;
    int (**inst_table)(OpenasmBuffer *, OpenasmOperand *);
};

struct OpenasmRegister {
    const char *key;
    uint32_t val;
    uint32_t bits;
    int ext;
};

/* useful defines */
#define OPENASM_MAX_SIZE 15
#define OPENASM_MEM(b, i, s, d) ((struct OpenasmMemory) { .base.reg = b, .index.reg = i, .scale = s, .disp = d })
#define OPENASM_CONS1(tag) (tag & 0xf)
#define OPENASM_CONS2(tag1, tag2) (((tag1 & 0xf) << 4) | (tag2 & 0xf))

/* prefixes */
// group 1 prefixes
#define OPENASM_PREFIX1_LOCK 0xf0
#define OPENASM_PREFIX1_REPNZ 0xf2
#define OPENASM_PREFIX1_REPNE 0xf2
#define OPENASM_PREFIX1_REPZ 0xf3
#define OPENASM_PREFIX1_REPE 0xf3
#define OPENASM_PREFIX1_REP 0xf3
// group 2 prefixes
#define OPENASM_PREFIX2_CS_OR 0x2e /* cs segment override */
#define OPENASM_PREFIX2_SS_OR 0x36 /* ss segment override */
#define OPENASM_PREFIX2_DS_OR 0x3e /* ds segment override */
#define OPENASM_PREFIX2_ES_OR 0x26 /* es segment override */
#define OPENASM_PREFIX2_FS_OR 0x64 /* fs segment override */
#define OPENASM_PREFIX2_GS_OR 0x65 /* gs segment override */
#define OPENASM_PREFIX2_BR_NT 0x2e /* branch not taken */
#define OPENASM_PREFIX2_BR_T 0x3e /* branch taken */
// group 3 prefixes
#define OPENASM_PREFIX3_OP_SIZE 0x66 /* operand size override */
// group 4 prefixes
#define OPENASM_PREFIX4_ADDR_SIZE 0x67 /* address size override */
// ia-32e prefixes
#define OPENASM_PREFIX64_REX(w, r, x, b) (0x40 | ((w & 1) << 3) | ((r & 1) << 2) | ((x & 1) << 1) | (b & 1))
#define OPENASM_PREFIX64_REX0 OPENASM_PREFIX64_REX(0, 0, 0, 0)
#define OPENASM_PREFIX64_REXW OPENASM_PREFIX64_REX(1, 0, 0, 0)
#define OPENASM_PREFIX64_REXR OPENASM_PREFIX64_REX(0, 1, 0, 0)
#define OPENASM_PREFIX64_REXX OPENASM_PREFIX64_REX(0, 0, 1, 0)
#define OPENASM_PREFIX64_REXB OPENASM_PREFIX64_REX(0, 0, 0, 1)

/* x86 register numbers (3-bit each) */
#define OPENASM_R8_AL 0x0
#define OPENASM_R8_CL 0x1
#define OPENASM_R8_DL 0x2
#define OPENASM_R8_BL 0x3
#define OPENASM_R8_AH 0x4
#define OPENASM_R8_CH 0x5
#define OPENASM_R8_DH 0x6
#define OPENASM_R8_BH 0x7
#define OPENASM_R16_AX 0x0
#define OPENASM_R16_CX 0x1
#define OPENASM_R16_DX 0x2
#define OPENASM_R16_BX 0x3
#define OPENASM_R16_SP 0x4
#define OPENASM_R16_BP 0x5
#define OPENASM_R16_SI 0x6
#define OPENASM_R16_DI 0x7
#define OPENASM_R32_EAX 0x0
#define OPENASM_R32_ECX 0x1
#define OPENASM_R32_EDX 0x2
#define OPENASM_R32_EBX 0x3
#define OPENASM_R32_ESP 0x4
#define OPENASM_R32_EBP 0x5
#define OPENASM_R32_ESI 0x6
#define OPENASM_R32_EDI 0x7
#define OPENASM_MM_MM0 0x0
#define OPENASM_MM_MM1 0x1
#define OPENASM_MM_MM2 0x2
#define OPENASM_MM_MM3 0x3
#define OPENASM_MM_MM4 0x4
#define OPENASM_MM_MM5 0x5
#define OPENASM_MM_MM6 0x6
#define OPENASM_MM_MM7 0x7
#define OPENASM_XMM_XMM0 0x0
#define OPENASM_XMM_XMM1 0x1
#define OPENASM_XMM_XMM2 0x2
#define OPENASM_XMM_XMM3 0x3
#define OPENASM_XMM_XMM4 0x4
#define OPENASM_XMM_XMM5 0x5
#define OPENASM_XMM_XMM6 0x6
#define OPENASM_XMM_XMM7 0x7

/* ia-32e registers (3-bit each) (require REX.W) */
#define OPENASM_R64_RAX 0x0
#define OPENASM_R64_RCX 0x1
#define OPENASM_R64_RDX 0x2
#define OPENASM_R64_RBX 0x3
#define OPENASM_R64_RSP 0x4
#define OPENASM_R64_RBP 0x5
#define OPENASM_R64_RSI 0x6
#define OPENASM_R64_RDI 0x7
/* (require REX.R, X or B) */
#define OPENASM_R64_R8 0x0
#define OPENASM_R64_R9 0x1
#define OPENASM_R64_R10 0x2
#define OPENASM_R64_R11 0x3
#define OPENASM_R64_R12 0x4
#define OPENASM_R64_R13 0x5
#define OPENASM_R64_R14 0x6
#define OPENASM_R64_R15 0x7

/* ModR/M and SIB specifiers */
#define OPENASM_MODRM_MOD_EA_MEM 0x0
#define OPENASM_MODRM_MOD_EA_SIB 0x0
#define OPENASM_MODRM_MOD_EA_DISP32 0x0
#define OPENASM_MODRM_MOD_EA_MEM_DISP8 0x1
#define OPENASM_MODRM_MOD_EA_SIB_DISP8 0x1
#define OPENASM_MODRM_MOD_EA_MEM_DISP32 0x2
#define OPENASM_MODRM_MOD_EA_SIB_DISP32 0x2
#define OPENASM_MODRM_MOD_EA_REG 0x3
#define OPENASM_MODRM_RM_EA_SIB 0x4
#define OPENASM_MODRM_RM_EA_DISP32 0x5
#define OPENASM_MODRM(mod, reg, rm) (((mod & 0x3) << 6) | ((reg & 0x7) << 3) | (rm & 0x7))
#define OPENASM_MODRM_MODMASK (0x3 << 6)
#define OPENASM_MODRM_REGMASK (0x7 << 3)
#define OPENASM_MODRM_RMMASK 0x7
#define OPENASM_SCALE_1 0x0
#define OPENASM_SCALE_2 0x1
#define OPENASM_SCALE_4 0x2
#define OPENASM_SCALE_8 0x3
#define OPENASM_INDEX_NONE 0x4
#define OPENASM_BASE_DISP 0x5
#define OPENASM_SIB(s, i, b) (((s & 0x3) << 6) | ((i & 0x7) << 3) | (b & 0x7))
#define OPENASM_DISP1(x) (x & 0xff)
#define OPENASM_DISP2(x) (x & 0xffff)
#define OPENASM_DISP4(x) (x & 0xffffffff)

/* opcode constructors */
#define OPENASM_OPCODE1(op) op
#define OPENASM_OPCODE2_ESCAPE 0x0f
#define OPENASM_OPCODE2(op2) ((op2 << 8) | OPENASM_OPCODE2_ESCAPE)
#define OPENASM_OPCODE2_66H(op2) ((OPENASM_OPCODE2(op2) << 8) | 0x66)
#define OPENASM_OPCODE2_F2H(op2) ((OPENASM_OPCODE2(op2) << 8) | 0xf2)
#define OPENASM_OPCODE2_F3H(op2) ((OPENASM_OPCODE2(op2) << 8) | 0xf3)
#define OPENASM_OPCODE3_ESCAPE1 0x38
#define OPENASM_OPCODE3_ESCAPE2 0x3a
#define OPENASM_OPCODE3(op2, op3) ((op3 << 16) | (op2 << 8) | OPENASM_OPCODE2_ESCAPE)
#define OPENASM_OPCODE3_66H(op2, op3) ((OPENASM_OPCODE3(op2, op3) << 8) | 0x66)
#define OPENASM_OPCODE3_F2H(op2, op3) ((OPENASM_OPCODE3(op2, op3) << 8) | 0xf2)
#define OPENASM_OPCODE3_F3H(op2, op3) ((OPENASM_OPCODE3(op2, op3) << 8) | 0xf3)

#define OPENASM_OPCODE2_REX(rex, op2) ((OPENASM_OPCODE2(op2) << 8) | rex)
#define OPENASM_OPCODE2_66H_REX(rex, op2) ((OPENASM_OPCODE2(op2) << 16) | (rex << 8) | 0x66)
#define OPENASM_OPCODE2_F2H_REX(rex, op2) ((OPENASM_OPCODE2(op2) << 16) | (rex << 8) | 0xf2)
#define OPENASM_OPCODE2_F3H_REX(rex, op2) ((OPENASM_OPCODE2(op2) << 16) | (rex << 8) | 0xf3)

#define OPENASM_OPCODE3_REX(rex, op2, op3) ((OPENASM_OPCODE3(op2, op3) << 8) | rex)
#define OPENASM_OPCODE3_66H_REX(rex, op2, op3) ((OPENASM_OPCODE3(op2, op3) << 16) | (rex << 8) | 0x66)
#define OPENASM_OPCODE3_F2H_REX(rex, op2, op3) ((OPENASM_OPCODE3(op2, op3) << 16) | (rex << 8) | 0xf2)
#define OPENASM_OPCODE3_F3H_REX(rex, op2, op3) ((OPENASM_OPCODE3(op2, op3) << 16) | (rex << 8) | 0xf3)

/* complete instruction constructors */
#define OPENASM_INSTR(op) op
#define OPENASM_INSTR_MODRM(op, modrm) ((op << 8) | modrm)
#define OPENASM_INSTR_SIB(op, sib) ((op << 8) | sib)
#define OPENASM_INSTR_MODRM_SIB(op, modrm, sib) ((op << 16) | (modrm << 8) | sib)

/* displacement and immediate constructors */
#define OPENASM_DISP8(x) (x & 0xff)
#define OPENASM_DISP16(x) (x & 0xffff)
#define OPENASM_DISP32(x) (x & 0xffffffff)
#define OPENASM_IMM8(x) (x & 0xff)
#define OPENASM_IMM16(x) (x & 0xffff)
#define OPENASM_IMM32(x) (x & 0xffffffff)

/* opcode sizes */
#define OPENASM_SIZE_OPCODE1 1
#define OPENASM_SIZE_OPCODE2 2
#define OPENASM_SIZE_OPCODE2_66H 3
#define OPENASM_SIZE_OPCODE2_F2H 3
#define OPENASM_SIZE_OPCODE2_F3H 3
#define OPENASM_SIZE_OPCODE3 3
#define OPENASM_SIZE_OPCODE3_66H 4
#define OPENASM_SIZE_OPCODE3_F2H 4
#define OPENASM_SIZE_OPCODE3_F3H 4
    
#define OPENASM_SIZE_OPCODE2_REX 3
#define OPENASM_SIZE_OPCODE2_66H_REX 4
#define OPENASM_SIZE_OPCODE2_F2H_REX 4
#define OPENASM_SIZE_OPCODE2_F3H_REX 4

#define OPENASM_SIZE_OPCODE3_REX 4
#define OPENASM_SIZE_OPCODE3_66H_REX 5
#define OPENASM_SIZE_OPCODE3_F2H_REX 5
#define OPENASM_SIZE_OPCODE3_F3H_REX 5

/* opcodes */
// add and add-like opcodes
#define OPENASM_ADD_AL_IMM8 0x04
#define OPENASM_ADD_AX_IMM16 0x05 /* requires 66h prefix */
#define OPENASM_ADD_EAX_IMM32 0x05
#define OPENASM_ADDSX_RAX_IMM32 0x05 /* requires REX.W */
#define OPENASM_ADD_RM8_IMM8 0x80 /* requires REX and reg=0 */
#define OPENASM_ADD_RM16_IMM16 0x81 /* requires 66h prefix annd reg=0 */
#define OPENASM_ADD_RM32_IMM32 0x81 /* requires reg=0 */
#define OPENASM_ADDSX_RM64_IMM32 0x81 /* requires REX.W and reg=0 */
#define OPENASM_ADDSX_RM16_IMM8 0x83 /* requires 66h prefix annd reg=0 */
#define OPENASM_ADDSX_RM32_IMM8 0x83 /* requires reg=0 */
#define OPENASM_ADDSX_RM64_IMM8 0x83 /* requires REX.W and reg=0 */
#define OPENASM_ADD_RM8_R8 0x00
#define OPENASM_ADD_RM16_R16 0x01 /* requires 66h prefix */
#define OPENASM_ADD_RM32_R32 0x01
#define OPENASM_ADD_RM64_R64 0x01 /* requires REX.W */
#define OPENASM_ADD_R8_RM8 0x02 /* requires REX */
#define OPENASM_ADD_R16_RM16 0x03 /* requires 66h prefix */
#define OPENASM_ADD_R32_RM32 0x03
#define OPENASM_ADD_R64_RM64 0x03 /* requires REX.W */

#define OPENASM_ADC_AL_IMM8 0x14
#define OPENASM_ADC_AX_IMM16 0x15 /* requires 66h prefix */
#define OPENASM_ADC_EAX_IMM32 0x15
#define OPENASM_ADCSX_RAX_IMM32 0x15 /* requires REX.W */
#define OPENASM_ADC_RM8_IMM8 0x80 /* requires REX and reg=2 */
#define OPENASM_ADC_RM16_IMM16 0x81 /* requires 66h prefix annd reg=2 */
#define OPENASM_ADC_RM32_IMM32 0x81 /* requires reg=2 */
#define OPENASM_ADCSX_RM64_IMM32 0x81 /* requires REX.W and reg=2 */
#define OPENASM_ADCSX_RM16_IMM8 0x83 /* requires 66h prefix annd reg=2 */
#define OPENASM_ADCSX_RM32_IMM8 0x83 /* requires reg=2 */
#define OPENASM_ADCSX_RM64_IMM8 0x83 /* requires REX.W and reg=2 */
#define OPENASM_ADC_RM8_R8 0x10
#define OPENASM_ADC_RM16_R16 0x11 /* requires 66h prefix */
#define OPENASM_ADC_RM32_R32 0x11
#define OPENASM_ADC_RM64_R64 0x11 /* requires REX.W */
#define OPENASM_ADC_R8_RM8 0x12 /* requires REX */
#define OPENASM_ADC_R16_RM16 0x13 /* requires 66h prefix */
#define OPENASM_ADC_R32_RM32 0x13
#define OPENASM_ADC_R64_RM64 0x13 /* requires REX.W */

#define OPENASM_AND_AL_IMM8 0x24
#define OPENASM_AND_AX_IMM16 0x25 /* requires 66h prefix */
#define OPENASM_AND_EAX_IMM32 0x25
#define OPENASM_ANDSX_RAX_IMM32 0x25 /* requires REX.W */
#define OPENASM_AND_RM8_IMM8 0x80 /* requires REX and reg=4 */
#define OPENASM_AND_RM16_IMM16 0x81 /* requires 66h prefix annd reg=4 */
#define OPENASM_AND_RM32_IMM32 0x81 /* requires reg=4 */
#define OPENASM_ANDSX_RM64_IMM32 0x81 /* requires REX.W and reg=4 */
#define OPENASM_ANDSX_RM16_IMM8 0x83 /* requires 66h prefix annd reg=4 */
#define OPENASM_ANDSX_RM32_IMM8 0x83 /* requires reg=4 */
#define OPENASM_ANDSX_RM64_IMM8 0x83 /* requires REX.W and reg=4 */
#define OPENASM_AND_RM8_R8 0x20
#define OPENASM_AND_RM16_R16 0x21 /* requires 66h prefix */
#define OPENASM_AND_RM32_R32 0x21
#define OPENASM_AND_RM64_R64 0x21 /* requires REX.W */
#define OPENASM_AND_R8_RM8 0x22 /* requires REX */
#define OPENASM_AND_R16_RM16 0x23 /* requires 66h prefix */
#define OPENASM_AND_R32_RM32 0x23
#define OPENASM_AND_R64_RM64 0x23 /* requires REX.W */

#define OPENASM_OR_AL_IMM8 0x0c
#define OPENASM_OR_AX_IMM16 0x0d /* requires 66h prefix */
#define OPENASM_OR_EAX_IMM32 0x0d
#define OPENASM_ORSX_RAX_IMM32 0x0d /* requires REX.W */
#define OPENASM_OR_RM8_IMM8 0x80 /* requires REX and reg=1 */
#define OPENASM_OR_RM16_IMM16 0x81 /* requires 66h prefix annd reg=1 */
#define OPENASM_OR_RM32_IMM32 0x81 /* requires reg=1 */
#define OPENASM_ORSX_RM64_IMM32 0x81 /* requires REX.W and reg=1 */
#define OPENASM_ORSX_RM16_IMM8 0x83 /* requires 66h prefix annd reg=1 */
#define OPENASM_ORSX_RM32_IMM8 0x83 /* requires reg=1 */
#define OPENASM_ORSX_RM64_IMM8 0x83 /* requires REX.W and reg=1 */
#define OPENASM_OR_RM8_R8 0x08
#define OPENASM_OR_RM16_R16 0x09 /* requires 66h prefix */
#define OPENASM_OR_RM32_R32 0x09
#define OPENASM_OR_RM64_R64 0x09 /* requires REX.W */
#define OPENASM_OR_R8_RM8 0x0a /* requires REX */
#define OPENASM_OR_R16_RM16 0x0b /* requires 66h prefix */
#define OPENASM_OR_R32_RM32 0x0b
#define OPENASM_OR_R64_RM64 0x0b /* requires REX.W */

#define OPENASM_XOR_AL_IMM8 0x34
#define OPENASM_XOR_AX_IMM16 0x35 /* requires 66h prefix */
#define OPENASM_XOR_EAX_IMM32 0x35
#define OPENASM_XORSX_RAX_IMM32 0x35 /* requires REX.W */
#define OPENASM_XOR_RM8_IMM8 0x80 /* requires REX and reg=6 */
#define OPENASM_XOR_RM16_IMM16 0x81 /* requires 66h prefix annd reg=6 */
#define OPENASM_XOR_RM32_IMM32 0x81 /* requires reg=6 */
#define OPENASM_XORSX_RM64_IMM32 0x81 /* requires REX.W and reg=6 */
#define OPENASM_XORSX_RM16_IMM8 0x83 /* requires 66h prefix annd reg=6 */
#define OPENASM_XORSX_RM32_IMM8 0x83 /* requires reg=6 */
#define OPENASM_XORSX_RM64_IMM8 0x83 /* requires REX.W and reg=6 */
#define OPENASM_XOR_RM8_R8 0x30
#define OPENASM_XOR_RM16_R16 0x31 /* requires 66h prefix */
#define OPENASM_XOR_RM32_R32 0x31
#define OPENASM_XOR_RM64_R64 0x31 /* requires REX.W */
#define OPENASM_XOR_R8_RM8 0x32 /* requires REX */
#define OPENASM_XOR_R16_RM16 0x33 /* requires 66h prefix */
#define OPENASM_XOR_R32_RM32 0x33
#define OPENASM_XOR_R64_RM64 0x33 /* requires REX.W */

#define OPENASM_SUB_AL_IMM8 0x2c
#define OPENASM_SUB_AX_IMM16 0x2d /* requires 66h prefix */
#define OPENASM_SUB_EAX_IMM32 0x2d
#define OPENASM_SUBSX_RAX_IMM32 0x2d /* requires REX.W */
#define OPENASM_SUB_RM8_IMM8 0x80 /* requires REX and reg=5 */
#define OPENASM_SUB_RM16_IMM16 0x81 /* requires 66h prefix annd reg=5 */
#define OPENASM_SUB_RM32_IMM32 0x81 /* requires reg=5 */
#define OPENASM_SUBSX_RM64_IMM32 0x81 /* requires REX.W and reg=5 */
#define OPENASM_SUBSX_RM16_IMM8 0x83 /* requires 66h prefix annd reg=5 */
#define OPENASM_SUBSX_RM32_IMM8 0x83 /* requires reg=5 */
#define OPENASM_SUBSX_RM64_IMM8 0x83 /* requires REX.W and reg=5 */
#define OPENASM_SUB_RM8_R8 0x28
#define OPENASM_SUB_RM16_R16 0x29 /* requires 66h prefix */
#define OPENASM_SUB_RM32_R32 0x29
#define OPENASM_SUB_RM64_R64 0x29 /* requires REX.W */
#define OPENASM_SUB_R8_RM8 0x2a /* requires REX */
#define OPENASM_SUB_R16_RM16 0x2b /* requires 66h prefix */
#define OPENASM_SUB_R32_RM32 0x2b
#define OPENASM_SUB_R64_RM64 0x2b /* requires REX.W */

#define OPENASM_CMP_AL_IMM8 0x3c
#define OPENASM_CMP_AX_IMM16 0x3d /* requires 66h prefix */
#define OPENASM_CMP_EAX_IMM32 0x3d
#define OPENASM_CMPSX_RAX_IMM32 0x3d /* requires REX.W */
#define OPENASM_CMP_RM8_IMM8 0x80 /* requires REX and reg=7 */
#define OPENASM_CMP_RM16_IMM16 0x81 /* requires 66h prefix annd reg=7 */
#define OPENASM_CMP_RM32_IMM32 0x81 /* requires reg=7 */
#define OPENASM_CMPSX_RM64_IMM32 0x81 /* requires REX.W and reg=7 */
#define OPENASM_CMPSX_RM16_IMM8 0x83 /* requires 66h prefix annd reg=7 */
#define OPENASM_CMPSX_RM32_IMM8 0x83 /* requires reg=7 */
#define OPENASM_CMPSX_RM64_IMM8 0x83 /* requires REX.W and reg=7 */
#define OPENASM_CMP_RM8_R8 0x38
#define OPENASM_CMP_RM16_R16 0x39 /* requires 66h prefix */
#define OPENASM_CMP_RM32_R32 0x39
#define OPENASM_CMP_RM64_R64 0x39 /* requires REX.W */
#define OPENASM_CMP_R8_RM8 0x3a /* requires REX */
#define OPENASM_CMP_R16_RM16 0x3b /* requires 66h prefix */
#define OPENASM_CMP_R32_RM32 0x3b
#define OPENASM_CMP_R64_RM64 0x3b /* requires REX.W */

#define OPENASM_MUL_AL_RM8 0xf6 /* requires REX, reg=4 */
#define OPENASM_MUL_AX_RM16 0xf7 /* requires 66h prefix, reg=4 */
#define OPENASM_MUL_EAX_RM32 0xf7 /* requires reg=4 */
#define OPENASM_MUL_RAX_RM64 0xf7 /* requires REX.W, reg=4 */

#define OPENASM_IMUL_AL_RM8 0xf6 /* requires REX, reg=5 */
#define OPENASM_IMUL_AX_RM16 0xf7 /* requires 66h prefix, reg=5 */
#define OPENASM_IMUL_EAX_RM32 0xf7 /* requires reg=5 */
#define OPENASM_IMUL_RAX_RM64 0xf7 /* requires REX.W, reg=5 */

#define OPENASM_DIV_AL_RM8 0xf6 /* requires REX, reg=6 */
#define OPENASM_DIV_AX_RM16 0xf7 /* requires 66h prefix, reg=6 */
#define OPENASM_DIV_EAX_RM32 0xf7 /* requires reg=6 */
#define OPENASM_DIV_RAX_RM64 0xf7 /* requires REX.W, reg=6 */

#define OPENASM_IDIV_AL_RM8 0xf6 /* requires REX, reg=7 */
#define OPENASM_IDIV_AX_RM16 0xf7 /* requires 66h prefix, reg=7 */
#define OPENASM_IDIV_EAX_RM32 0xf7 /* requires reg=7 */
#define OPENASM_IDIV_RAX_RM64 0xf7 /* requires REX.W, reg=7 */

#define OPENASM_MOV_RM8_R8 0x88 /* requires REX */
#define OPENASM_MOV_RM16_R16 0x89 /* requires 66h prefix */
#define OPENASM_MOV_RM32_R32 0x89
#define OPENASM_MOV_RM64_R64 0x89 /* requires REX.W */
#define OPENASM_MOV_R8_RM8 0x8a /* requires REX */
#define OPENASM_MOV_R16_RM16 0x8b /* requires 66h prefix */
#define OPENASM_MOV_R32_RM32 0x8b
#define OPENASM_MOV_R64_RM64 0x8b /* requires REX.W */
#define OPENASM_MOV_R8_IMM8 0xb0 /* requires REX */
#define OPENASM_MOV_R16_IMM16 0xb8 /* requires 66h prefix */
#define OPENASM_MOV_R32_IMM32 0xb8
#define OPENASM_MOV_R64_IMM64 0xb8 /* requires REX.W */
#define OPENASM_MOV_RM8_IMM8 0xc6 /* requires REX */
#define OPENASM_MOV_RM16_IMM16 0xc7 /* requires 66h prefix */
#define OPENASM_MOV_RM32_IMM32 0xc7
#define OPENASM_MOVSX_RM64_IMM32 0xc7 /* requires REX.W */

#define OPENASM_MOVZX_R16_RM8 0xb6 /* requires 66h prefix 0fh escape */
#define OPENASM_MOVZX_R32_RM8 0xb6 /* requires 0fh escape */
#define OPENASM_MOVZX_R32_RM16 0xb7 /* requires 0fh escape */
#define OPENASM_MOVZX_R64_RM16 0xb7 /* requires REX.W and 0fh escape */

#define OPENASM_MOVSX_R16_RM8 0xbe /* requires 66h prefix 0fh escape */
#define OPENASM_MOVSX_R32_RM8 0xbe /* requires 0fh escape */
#define OPENASM_MOVSX_R32_RM16 0xbf /* requires 0fh escape */
#define OPENASM_MOVSX_R64_RM16 0xbf /* requires REX.W and 0fh escape */
#define OPENASM_MOVSX_R64_RM32 0x63 /* requires REX.W */

#define OPENASM_LEA_R64_M64 0x8d

#define OPENASM_POP_RM64 0x8f /* requires reg=0 */
#define OPENASM_POP_R64 0x58

#define OPENASM_PUSH_RM64 0xff /* requires reg=6 */
#define OPENASM_PUSH_R64 0x50
#define OPENASM_PUSH_IMM8 0x6a
#define OPENASM_PUSH_IMM32 0x68

#define OPENASM_CALL_REL32 0xe8
#define OPENASM_SYSCALL 0x05 /* requires 0fh escape */

#define OPENASM_RET_NEAR 0xc3
#define OPENASM_RET_FAR 0xcb

#define OPENASM_JMP_NEAR 0xe9

#define OPENASM_JC_SHORT 0x72
#define OPENASM_JCXZ_SHORT 0xe3
#define OPENASM_JE_SHORT 0x74
#define OPENASM_JNE_SHORT 0x75
#define OPENASM_JG_SHORT 0x7f
#define OPENASM_JGE_SHORT 0x7d
#define OPENASM_JL_SHORT 0x7c
#define OPENASM_JLE_SHORT 0x7e
// all of these require a 2-byte escape
#define OPENASM_JC_NEAR 0x82
#define OPENASM_JE_NEAR 0x84
#define OPENASM_JNE_NEAR 0x85
#define OPENASM_JG_NEAR 0x8f
#define OPENASM_JGE_NEAR 0x8d
#define OPENASM_JL_NEAR 0x8c
#define OPENASM_JLE_NEAR 0x8e

void openasm_buffer(OpenasmBuffer *buf);
void openasm_del_buffer(OpenasmBuffer *buf);

uint8_t *openasm_new(OpenasmBuffer *buf);
uint8_t *openasm_legacy_prefix(OpenasmBuffer *buf, uint8_t *ptr, uint8_t prefix);
uint8_t *openasm_rex_prefix(OpenasmBuffer *buf, uint8_t *ptr, uint8_t prefix);
uint8_t *openasm_opcode1(OpenasmBuffer *buf, uint8_t *ptr, uint8_t op);
uint8_t *openasm_opcode2(OpenasmBuffer *buf, uint8_t *ptr, uint8_t op);
uint8_t *openasm_opcode3a(OpenasmBuffer *buf, uint8_t *ptr, uint8_t op);
uint8_t *openasm_opcode3b(OpenasmBuffer *buf, uint8_t *ptr, uint8_t op);
uint8_t *openasm_modrm(OpenasmBuffer *buf, uint8_t *ptr, uint8_t modrm);
uint8_t *openasm_sib(OpenasmBuffer *buf, uint8_t *ptr, uint8_t sib);
uint8_t *openasm_disp8(OpenasmBuffer *buf, uint8_t *ptr, uint8_t disp);
uint8_t *openasm_disp16(OpenasmBuffer *buf, uint8_t *ptr, uint16_t disp);
uint8_t *openasm_disp32(OpenasmBuffer *buf, uint8_t *ptr, uint32_t disp);
uint8_t *openasm_imm8(OpenasmBuffer *buf, uint8_t *ptr, uint8_t imm);
uint8_t *openasm_imm16(OpenasmBuffer *buf, uint8_t *ptr, uint16_t imm);
uint8_t *openasm_imm32(OpenasmBuffer *buf, uint8_t *ptr, uint32_t imm);
uint8_t *openasm_imm64(OpenasmBuffer *buf, uint8_t *ptr, uint64_t imm);
int openasm_build(OpenasmBuffer *buf, uint8_t *start, uint8_t *end);

int openasm_instf(OpenasmBuffer *buf, const char *fmt, ...);
int openasm_instfv(OpenasmBuffer *buf, const char *fmt, va_list args);
uint64_t openasm_data(OpenasmBuffer *buf, size_t len, void *ptr);
uint64_t openasm_res(OpenasmBuffer *buf, size_t len);

void openasm_section(OpenasmBuffer *buf, const char *section);
bool openasm_section_exists(OpenasmBuffer *buf, const char *section);
    
uint64_t openasm_addr_of(OpenasmBuffer *buf, uint8_t *inst);
uint64_t openasm_current_addr(OpenasmBuffer *buf);
void openasm_reserve_symbol(OpenasmBuffer *buf, const char *src_section, const char *addr_section, const char *sym, uint64_t offset, size_t bits, int rel, int func);
// `openasm_symbol` returns whether that symbol was used, not whether that symbol is valid.
// Must be used after all uses of the symbol were emitted, or it will otherwise create
// erroneous results.
bool openasm_symbol(OpenasmBuffer *buf, const char *section, const char *sym, int binding, uint64_t addr, uint64_t size);
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

int openasm_add_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_addsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_addsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_addsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_addsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_addsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_add_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_adc_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adcsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adcsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adcsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adcsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adcsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_adc_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_and_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_andsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_andsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_andsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_andsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_andsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_and_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_or_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_orsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_orsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_orsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_orsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_orsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_or_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_xor_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xorsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xorsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xorsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xorsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xorsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_xor_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_sub_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_subsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_subsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_subsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_subsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_subsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_sub_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_cmp_al_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_ax_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_eax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmpsx_rax_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmpsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmpsx_rm16_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmpsx_rm32_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmpsx_rm64_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_cmp_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_mul_al_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mul_ax_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mul_eax_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mul_rax_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_imul_al_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_imul_ax_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_imul_eax_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_imul_rax_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_div_al_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_div_ax_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_div_eax_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_div_rax_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_idiv_al_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_idiv_ax_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_idiv_eax_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_idiv_rax_rm64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_mov_rm8_r8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_rm16_r16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_rm32_r32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_rm64_r64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_r8_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_r16_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_r32_rm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_r64_rm64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_r8_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_r16_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_r32_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_r64_imm64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_rm8_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_rm16_imm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_mov_rm32_imm32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_movsx_rm64_imm32(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_movzx_r16_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_movzx_r32_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_movzx_r32_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_movzx_r64_rm16(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_movsx_r16_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_movsx_r32_rm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_movsx_r32_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_movsx_r64_rm16(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_movsx_r64_rm32(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_lea_r64_m64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_pop_rm64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_pop_r64(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_push_rm64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_push_r64(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_push_imm8(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_push_imm32(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_call_rel32(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_syscall(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_ret_near(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_ret_far(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_jmp_short(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jmp_near(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_jc_short(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jcxz_short(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_je_short(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jne_short(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jg_short(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jge_short(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jl_short(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jle_short(OpenasmBuffer *buf, OpenasmOperand *op);

int openasm_jc_near(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_je_near(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jne_near(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jg_near(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jge_near(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jl_near(OpenasmBuffer *buf, OpenasmOperand *op);
int openasm_jle_near(OpenasmBuffer *buf, OpenasmOperand *op);

extern OpenasmProperty openasm_properties1[];
extern OpenasmProperty openasm_properties2[];
extern OpenasmProperty openasm_properties3a[];
extern OpenasmProperty openasm_properties3b[];
extern struct OpenasmEntry openasm_inst[];
extern struct OpenasmRegister openasm_register[];

#endif /* OPENASM_H */
