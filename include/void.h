#ifndef OPENASM_ARCH_H
#define OPENASM_ARCH_H 1

#ifndef OPENASM_H
#error "don't include any of the OpenAsm architecture headers on their own"
#endif /* OPENASM_H */

typedef void OpenasmBuffer;
typedef void OpenasmOperand;

int openasm_elfdump(FILE *fileout, int flags, OpenasmBuffer *buf);
int openasm_rawdump(FILE *fileout, OpenasmBuffer *buf);

OpenasmProc openasm_jit_proc(OpenasmBuffer *buf);
OpenasmFni openasm_jit_fni(OpenasmBuffer *buf);
OpenasmFnl openasm_jit_fnl(OpenasmBuffer *buf);
OpenasmFnll openasm_jit_fnll(OpenasmBuffer *buf);
OpenasmFnf openasm_jit_fnf(OpenasmBuffer *buf);
OpenasmFnd openasm_jit_fnd(OpenasmBuffer *buf);
OpenasmFnvp openasm_jit_fnvp(OpenasmBuffer *buf);

#endif /* OPENASM_ARCH_H */
