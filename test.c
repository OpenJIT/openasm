#include <errno.h>
#include "include/openasm.h"

int main() {
    int status = 0;
    
    OpenasmBuffer buf;
    openasm_buffer(&buf);
    const char *reg0 = "r8";
    const char *reg1 = "r9";
    /* uint64_t _start = openasm_current_addr(&buf); */
    status |= openasm_instf(&buf, "push %r", "rbp");
    status |= openasm_instf(&buf, "mov %r, %r", "rbp", "rsp");
    status |= openasm_instf(&buf, "sub %r, %i32", "rsp", 8);
    status |= openasm_instf(&buf, "call %p", "text", "fun");
    status |= openasm_instf(&buf, "mov %r, %r", "rsp", "rbp");
    status |= openasm_instf(&buf, "pop %r", "rbp");
    status |= openasm_instf(&buf, "ret");

    uint64_t fun = openasm_current_addr(&buf);
    status |= openasm_instf(&buf, "mov %r, %i64", reg0, 42);
    status |= openasm_instf(&buf, "mov %r, %i64", reg1, 69);
    status |= openasm_instf(&buf, "add %r, %r", reg0, reg1);
    status |= openasm_instf(&buf, "mov %r, %r", "rax", reg0);
    status |= openasm_instf(&buf, "ret");

    openasm_symbol(&buf, "text", "fun", fun);
    openasm_link(&buf);

    if (status) {
        return status;
    }

    FILE *fileout = fopen("test", "w");
    openasm_elfdump(fileout, OPENASM_ELF_EXEC, &buf);
    fclose(fileout);

    OpenasmFni fn = openasm_jit_fni(&buf);
    int i = fn();
    printf("%d\n", i);
    
    return 0;
}
