#include <sys/mman.h>
#include <errno.h>
#include "include/openasm.h"

OpenasmProc openasm_jit_proc(OpenasmBuffer *buf) {
    int status;
    
    void *addr = mmap(NULL, buf->len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_EXECUTABLE, 0, 0);
    if (addr == ((void *) -1)) {
        int err = errno;
        fprintf(stderr, "error: %s\n", strerror(err));
        return NULL;
    }
    
    memcpy(addr, buf->buffer, buf->len);
    
    status = mprotect(addr, buf->len, PROT_READ | PROT_EXEC);
    if (status == -1) {
        int err = errno;
        fprintf(stderr, "error: %s\n", strerror(err));
        return NULL;
    }

    return *(OpenasmProc *) &addr;
}

OpenasmFni openasm_jit_fni(OpenasmBuffer *buf) {
    OpenasmProc proc = openasm_jit_proc(buf);
    return *(OpenasmFni *) &proc;
}

OpenasmFnl openasm_jit_fnl(OpenasmBuffer *buf) {
    OpenasmProc proc = openasm_jit_proc(buf);
    return *(OpenasmFnl *) &proc;
}

OpenasmFnll openasm_jit_fnll(OpenasmBuffer *buf) {
    OpenasmProc proc = openasm_jit_proc(buf);
    return *(OpenasmFnll *) &proc;
}

OpenasmFnf openasm_jit_fnf(OpenasmBuffer *buf) {
    OpenasmProc proc = openasm_jit_proc(buf);
    return *(OpenasmFnf *) &proc;
}

OpenasmFnd openasm_jit_fnd(OpenasmBuffer *buf) {
    OpenasmProc proc = openasm_jit_proc(buf);
    return *(OpenasmFnd *) &proc;
}

OpenasmFnvp openasm_jit_fnvp(OpenasmBuffer *buf) {
    OpenasmProc proc = openasm_jit_proc(buf);
    return *(OpenasmFnvp *) &proc;
}
