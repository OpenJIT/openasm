#include <stdarg.h>
#define OPENASM_ARCH_AARCH64 1
#include "include/openasm.h"

uint8_t strtoreg(const char *ptr) {
    // sanity check for null
    if (!*ptr) return 0xff;
    // named register checks
    if (strcmp(ptr, "fp") == 0) return 0x1d;
    if (strcmp(ptr, "lr") == 0) return 0x1e;
    if (strcmp(ptr, "zr") == 0) return 0x1f;
    if (strcmp(ptr, "sp") == 0) return 0x1f;
    // sanity check for length
    if (strlen(ptr) > 2) return 0xff;
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
    uint8_t regv[3] = {0x1f, 0x1f, 0x1f}; // xzr
    size_t immc = 0;
    uint32_t immv[3] = {0, 0, 0};
    
    while (*fmt == ' ' || *fmt == '\t') ++fmt;
    ptr = fmt;

    for (size_t i = 0; i < 6; i++) {
        while (*fmt) {
            if (*fmt == ' ' || *fmt == '\t') {
                ++fmt;
                continue;
            }
            if (*fmt == '%') {
                ++fmt;
                switch (*fmt) {
		case '*': {
		    OpenasmOperand op = va_arg(args, OpenasmOperand);
		    tag <<= 1;
		    tag |= op.tag;
		    if (op.tag == OPENASM_OP_REG) {
			regv[regc++] = op.reg;
		    } else /* if (op.tag == OPENASM_OP_IMM) */ {
			immv[immc++] = op.imm;
		    }
		} break;
                case 'r': {
		    tag <<= 1;
		    tag |= OPENASM_OP_REG;
                    const char *target = va_arg(args, char *);
		    if (target[0] == 'w') {
			if (!bits) {
                            bits = 32;
			}
			uint8_t reg = strtoreg(target + 1);
			if (reg > 0x1f) {
			    fprintf(stderr, "error: invalid registers: %s\n", target);
			    return 1;
			}
			regv[regc++] = reg;
		    } else if (strcmp(target, "fp") == 0
			       || strcmp(target, "lr") == 0
			       || strcmp(target, "sp") == 0) {
			if (!bits) {
                            bits = 64;
			}
			uint8_t reg = strtoreg(target);
			regv[regc++] = reg;
		    } else if (target[0] == 'x') {
			if (!bits) {
                            bits = 64;
			}
			uint8_t reg = strtoreg(target + 1);
			if (reg > 0x1f) {
			    fprintf(stderr, "error: invalid registers: %s\n", target);
			    return 1;
			}
			regv[regc++] = reg;
		    }
                } break;
                case 'i': {
		    tag <<= 1;
		    tag |= OPENASM_OP_IMM;
                    uint32_t imm = va_arg(args, uint32_t);
		    immv[immc++] = imm;
                } break;
                case '=': {
		    tag <<= 1;
		    tag |= OPENASM_OP_IMM;
                    uint64_t imm = va_arg(args, uint64_t);

                    size_t index = openasm_pool(buf, imm);
                    
		    immv[immc++] = 0;
                    if (buf->symtable.len == buf->symtable.cap) {
                        buf->symtable.cap *= 2;
                        buf->symtable.table = realloc(buf->symtable.table, buf->symtable.cap * sizeof(struct OpenasmSymbol));
                    }
                    
                    const char *src_section = buf->sections[buf->section].name;
                    const char *addr_section = src_section;
                    size_t llen = 40;
                    char *name = malloc(llen + 1);
                    snprintf(name, llen, "__pool_%u_%u", buf->pool.gen, (uint32_t) index);
                    name[llen] = 0;
                    buf->sym = 1;
                    buf->symtable.table[buf->symtable.len].src_section = src_section;
                    buf->symtable.table[buf->symtable.len].addr_section = addr_section;
                    buf->symtable.table[buf->symtable.len].sym = name;
                    buf->symtable.table[buf->symtable.len].defined = 0;
                    buf->symtable.table[buf->symtable.len].bits = 0;
                    buf->symtable.table[buf->symtable.len].offset = 0;
                    buf->symtable.table[buf->symtable.len].addr = 0;
                    buf->symtable.table[buf->symtable.len++].rel = 1;
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
	    case 4:
		switch (OPENASM_MASKOP(tag)) {
		case OPENASM_OP4(0, OPENASM_OP_REG, OPENASM_OP_REG, OPENASM_OP_REG, OPENASM_OP_REG):
		    return fn(buf, regv[0], regv[1], regv[2], regv[3]);
		case OPENASM_OP4(0, OPENASM_OP_REG, OPENASM_OP_REG, OPENASM_OP_REG, OPENASM_OP_IMM):
		    return fn(buf, regv[0], regv[1], regv[2], immv[0]);
		case OPENASM_OP4(0, OPENASM_OP_REG, OPENASM_OP_REG, OPENASM_OP_IMM, OPENASM_OP_REG):
		    return fn(buf, regv[0], regv[1], immv[0], regv[2]);
		case OPENASM_OP4(0, OPENASM_OP_REG, OPENASM_OP_IMM, OPENASM_OP_REG, OPENASM_OP_REG):
		    return fn(buf, regv[0], immv[0], regv[1], regv[2]);
		case OPENASM_OP4(0, OPENASM_OP_IMM, OPENASM_OP_REG, OPENASM_OP_REG, OPENASM_OP_REG):
		    return fn(buf, immv[0], regv[0], regv[1], regv[2]);
		case OPENASM_OP4(0, OPENASM_OP_REG, OPENASM_OP_REG, OPENASM_OP_IMM, OPENASM_OP_IMM):
		    return fn(buf, regv[0], regv[1], immv[0], immv[1]);
		case OPENASM_OP4(0, OPENASM_OP_REG, OPENASM_OP_IMM, OPENASM_OP_REG, OPENASM_OP_IMM):
		    return fn(buf, regv[0], immv[0], regv[1], immv[1]);
		case OPENASM_OP4(0, OPENASM_OP_IMM, OPENASM_OP_REG, OPENASM_OP_REG, OPENASM_OP_IMM):
		    return fn(buf, immv[0], regv[0], regv[1], immv[1]);
		case OPENASM_OP4(0, OPENASM_OP_REG, OPENASM_OP_IMM, OPENASM_OP_IMM, OPENASM_OP_REG):
		    return fn(buf, regv[0], immv[0], immv[1], regv[1]);
		case OPENASM_OP4(0, OPENASM_OP_IMM, OPENASM_OP_REG, OPENASM_OP_IMM, OPENASM_OP_REG):
		    return fn(buf, immv[0], regv[0], immv[1], regv[1]);
		case OPENASM_OP4(0, OPENASM_OP_IMM, OPENASM_OP_IMM, OPENASM_OP_REG, OPENASM_OP_REG):
		    return fn(buf, immv[0], immv[1], regv[0], regv[1]);
		case OPENASM_OP4(0, OPENASM_OP_REG, OPENASM_OP_IMM, OPENASM_OP_IMM, OPENASM_OP_IMM):
		    return fn(buf, regv[0], immv[0], immv[1], immv[2]);
		case OPENASM_OP4(0, OPENASM_OP_IMM, OPENASM_OP_REG, OPENASM_OP_IMM, OPENASM_OP_IMM):
		    return fn(buf, immv[0], regv[0], immv[1], immv[2]);
		case OPENASM_OP4(0, OPENASM_OP_IMM, OPENASM_OP_IMM, OPENASM_OP_REG, OPENASM_OP_IMM):
		    return fn(buf, immv[0], immv[1], regv[0], immv[2]);
		case OPENASM_OP4(0, OPENASM_OP_IMM, OPENASM_OP_IMM, OPENASM_OP_IMM, OPENASM_OP_REG):
		    return fn(buf, immv[0], immv[1], immv[2], regv[0]);
                case OPENASM_OP4(0, OPENASM_OP_IMM, OPENASM_OP_IMM, OPENASM_OP_IMM, OPENASM_OP_IMM):
		    return fn(buf, immv[0], immv[1], immv[2], immv[3]);
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
