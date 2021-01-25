#include <stdarg.h>
#define OPENASM_ARCH_AARCH64 1
#include "include/openasm.h"

uint8_t strtoreg(const char *ptr) {
    // sanity check for null
    if (!*ptr) return 0xff;
    // sanity check for length
    if (strlen(ptr) > 3) return 0xff;
    // named register checks
    if (strcmp(ptr, "fp") == 0) return 0x1d;
    if (strcmp(ptr, "lr") == 0) return 0x1e;
    if (strcmp(ptr, "xzr") == 0) return 0x1f;
    if (strcmp(ptr, "wzr") == 0) return 0x1f;
    if (strcmp(ptr, "sp") == 0) return 0x1f;
    uint8_t reg = 0;
    while (*ptr) {
	if (*ptr >= '0' && *ptr <= '9') {
	    reg *= 10;
	    reg += *ptr - '0';
	} else {
	    return 0xff;
	}
	++ptr;
    }
    return reg;
}

int openasm_instf(OpenasmBuffer *buf, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    int result = openasm_instfv(buf, fmt, args);

    va_end(args);

    return result;
}

int openasm_instfv(OpenasmBuffer *buf, const char *fmt, va_list args) {
    const char *input = fmt;
    
    while (*fmt == ' ' || *fmt == '\t') ++fmt;
    
    const char *ptr = fmt;
    char *mnemonic = malloc(strlen(fmt) + 1);

    while (*fmt && *fmt != ' ') ++fmt;

    size_t len = fmt - ptr;
    strncpy(mnemonic, ptr, len);
    mnemonic[len] = 0;

    uint8_t tag = 0;
    size_t bits = 0;
    size_t regc = 0;
    uint8_t regv[3] = {0x1f, 0x1f, 0x1f}; // RZR
    size_t immc = 0;
    uint32_t immv[3] = {0, 0, 0};
    
    while (*fmt == ' ' || *fmt == '\t') ++fmt;
    ptr = fmt;

    for (size_t i = 0; i < 8; i++) {
        while (*fmt) {
            if (*fmt == ' ' || *fmt == '\t') {
                ++fmt;
                continue;
            }
            if (*fmt == '%') {
                ++fmt;
                switch (*fmt) {
                case 'r': {
		    tag <<= 1;
		    tag |= OPENASM_OP_REG;
                    const char *target = va_arg(args, char *);
		    if (target[0] == 'w') {
			if (bits && bits != 32) {
			    fprintf(stderr, "error: cannot mix 32 and 64 bit registers\n");
			    return 1;
			}
			bits = 32;
			uint8_t reg = strtoreg(target + 1);
			if (reg > 0x1f) {
			    fprintf(stderr, "error: invalid registers: w%u\n", (uint32_t) reg);
			    return 1;
			}
			regv[regc++] = reg;
		    } else if (target[0] == 'x') {
			if (bits && bits != 64) {
			    fprintf(stderr, "error: cannot mix 32 and 64 bit registers\n");
			    return 1;
			}
			bits = 64;
			uint8_t reg = strtoreg(target + 1);
			if (reg > 0x1f) {
			    fprintf(stderr, "error: invalid registers: x%u\n", (uint32_t) reg);
			    return 1;
			}
			regv[regc++] = reg;
		    }
		    // TODO
                } break;
                case 'i': {
		    tag <<= 1;
		    tag |= OPENASM_OP_IMM;
                    uint32_t imm = va_arg(args, uint32_t);
		    immv[immc++] = imm;
		    // TODO
                } break;
                default: {
                    fprintf(stderr, "error: invalid `openasm_instf` parameter: '%c'\n", *fmt);
                    return 1;
                } break;
                }
                break;
            } else {
                fprintf(stderr, "error: invalid `openasm_instf` format: \"%s\"\n", input);
                return 1;
            }
        }
        while (*fmt && *fmt != ',') ++fmt;
        if (!*fmt) {
            break;
        } else if (*fmt == ',') {
            ++fmt;
        }
    }

    tag |= OPENASM_OP0(bits);

    for (struct OpenasmEntry *entry = openasm_inst; entry->mnem; entry++) {
        if (strcmp(mnemonic, entry->mnem) == 0) {
            int (*fn)(/* OpenasmBuffer * */) = entry->inst_table[tag];
            if (!fn) {
		fprintf(stderr, "error: invalid combination of opcode and operands: \"%s\"\n", mnemonic);
		return 1;
            }
	    /* brudah */
	    /* magie */
	    switch (regc + immc) {
	    case 0:
		return fn(buf);
	    case 1:
		switch (OPENASM_MASKOP(tag)) {
		case OPENASM_OP1(0, OPENASM_OP_REG):
		    return fn(buf, regv[0]);
		case OPENASM_OP1(0, OPENASM_OP_IMM):
		    return fn(buf, immv[0]);
		}
		break;
	    case 2:
		switch (OPENASM_MASKOP(tag)) {
		case OPENASM_OP2(0, OPENASM_OP_REG, OPENASM_OP_REG):
		    return fn(buf, regv[0], regv[1]);
		case OPENASM_OP2(0, OPENASM_OP_IMM, OPENASM_OP_REG):
		    return fn(buf, immv[0], regv[0]);
		case OPENASM_OP2(0, OPENASM_OP_REG, OPENASM_OP_IMM):
		    return fn(buf, regv[0], immv[0]);
		case OPENASM_OP2(0, OPENASM_OP_IMM, OPENASM_OP_IMM):
		    return fn(buf, immv[0], immv[1]);
		}
		break;
	    case 3:
		switch (OPENASM_MASKOP(tag)) {
		case OPENASM_OP3(0, OPENASM_OP_REG, OPENASM_OP_REG, OPENASM_OP_REG):
		    return fn(buf, regv[0], regv[1], regv[2]);
		case OPENASM_OP3(0, OPENASM_OP_REG, OPENASM_OP_REG, OPENASM_OP_IMM):
		    return fn(buf, regv[0], regv[1], immv[0]);
		case OPENASM_OP3(0, OPENASM_OP_REG, OPENASM_OP_IMM, OPENASM_OP_REG):
		    return fn(buf, regv[0], immv[0], regv[1]);
		case OPENASM_OP3(0, OPENASM_OP_IMM, OPENASM_OP_REG, OPENASM_OP_REG):
		    return fn(buf, immv[0], regv[0], regv[1]);
		case OPENASM_OP3(0, OPENASM_OP_REG, OPENASM_OP_IMM, OPENASM_OP_IMM):
		    return fn(buf, regv[0], immv[0], regv[1]);
		case OPENASM_OP3(0, OPENASM_OP_IMM, OPENASM_OP_REG, OPENASM_OP_IMM):
		    return fn(buf, immv[0], regv[0], immv[1]);
		case OPENASM_OP3(0, OPENASM_OP_IMM, OPENASM_OP_IMM, OPENASM_OP_REG):
		    return fn(buf, immv[0], immv[1], regv[0]);
		case OPENASM_OP3(0, OPENASM_OP_IMM, OPENASM_OP_IMM, OPENASM_OP_IMM):
		    return fn(buf, immv[0], immv[0], immv[2]);
		}
		break;
	    default:
		// more than 3 operands: unsupported
		fprintf(stderr, "error: invalid combination of opcode and operands: \"%s\"\n", mnemonic);
		return 1;
	    }
        }
    }
    
    fprintf(stderr, "error: unimplemented `openasm_instf` mnemonic: \"%s\"\n", mnemonic);
    return 1;
}
