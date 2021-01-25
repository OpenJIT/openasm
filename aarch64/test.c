#include <errno.h>
#define OPENASM_ARCH_AARCH64 1
#include "include/openasm.h"

int main() {
    int status = 0;
    
    OpenasmBuffer buf;
    openasm_buffer(&buf);
    const char *reg0 = "x19";
    status |= openasm_instf(&buf, "mov %r, %i, %i", reg0, 42, 0);
    status |= openasm_instf(&buf, "add %r, %r, %i", "x0", reg0, 69);
    status |= openasm_instf(&buf, "ret %r", "x30");

    if (status) {
        return status;
    }

    FILE *fileout = fopen("a.out", "w");
    openasm_rawdump(fileout, &buf);
    fclose(fileout);

    /* OpenasmFni fn = openasm_jit_fni(&buf); */
    /* int i = fn(); */
    /* printf("%d\n", i); */
    
    return 0;
}
