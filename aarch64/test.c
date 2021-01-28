#include <errno.h>
#define OPENASM_ARCH_AARCH64 1
#include "include/openasm.h"

int main() {
    int status = 0;
    
    OpenasmBuffer buf;
    openasm_buffer(&buf);
    const char *reg0 = "x19";
    uint64_t _start = openasm_current_addr(&buf);
    status |= openasm_instf(&buf, "ldr %r, %=", reg0, 42);
    status |= openasm_instf(&buf, "add %r, %r, %i", "x0", reg0, 69);
    status |= openasm_instf(&buf, "mov %r, %i", "x8", 0x5d);
    status |= openasm_instf(&buf, "mov %r, %i", "x0", 0);
    status |= openasm_instf(&buf, "svc %i", 0);
    uint64_t end = openasm_current_addr(&buf);
    openasm_flush_pool(&buf);
    
    openasm_symbol(&buf, "text", "_start", OPENASM_BIND_GLOBAL, _start, end - _start);

    openasm_link(&buf);

    if (status) {
        return status;
    }

    FILE *fileout = fopen("a.out", "w");
    openasm_elfdump(fileout, OPENASM_ELF_EXEC, &buf);
    fclose(fileout);

    return 0;
}
