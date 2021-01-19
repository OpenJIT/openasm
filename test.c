#include <errno.h>
#include "include/openasm.h"

int main() {
    int status = 0;
    
    OpenasmBuffer buf;
    openasm_buffer(&buf);
    const char *reg0 = "rax";
    const char *reg1 = "rdx";
    const char *some_var = "some_var";
    status |= openasm_instf(&buf, "push %r", "rbp");
    status |= openasm_instf(&buf, "mov %r, %r", "rbp", "rsp");
    status |= openasm_instf(&buf, "sub %r, %i32", "rsp", 8);
    status |= openasm_instf(&buf, "mov %r, %s64", "rbx", some_var);
    status |= openasm_instf(&buf, "mov %m, %i64", OPENASM_MEM("rbx", NULL, 0, 0), 1);
    status |= openasm_instf(&buf, "mov %r, %i32", reg0, 42);
    status |= openasm_instf(&buf, "mov %r, %i32", reg1, 69);
    status |= openasm_instf(&buf, "add %r, %r", reg0, reg1);
    status |= openasm_instf(&buf, "mov %r, %r", "rsp", "rbp");
    status |= openasm_instf(&buf, "pop %r", "rbp");
    status |= openasm_instf(&buf, "ret");
    uint64_t var = 0;
    void *ptr = &var;
    openasm_symbol(&buf, some_var, (uint64_t) ptr);
    openasm_link(&buf);

    if (status) {
        return status;
    }

    OpenasmFni fn = openasm_jit_fni(&buf);
    int i = fn();
    printf("%d\n", i);
    
    return 0;
}
