#include <stdlib.h>
#include <string.h>
#include "include/dwarf.h"

#define DEFAULT_SECT_CAP 1024
#define DEFAULT_ARRAY_CAP 512
#define DEFAULT_LNO_CAP 512

void openasm_dw_debugdata(OpenasmDebugData *debug) {
    for (size_t i = 0; i < 5; i++) {
        debug->dw_sect[i].cap = DEFAULT_SECT_CAP;
        debug->dw_sect[i].len = 0;
        debug->dw_sect[i].ptr = malloc(debug->dw_sect[i].cap);
    }
}

void openasm_dw_at_array(OpenasmDwAtArray *array) {
    array->cap = DEFAULT_ARRAY_CAP;
    array->len = 0;
    array->ptr = malloc(array->cap);
}

void openasm_dw_lno_buffer(OpenasmDwLineInfo *buf) {
    buf->cap = DEFAULT_LNO_CAP;
    buf->len = 0;
    buf->ptr = malloc(buf->cap);
}

void openasm_dw_compunit(OpenasmDebugData *debug, OpenasmDwCu *cu) {
    size_t size = sizeof(OpenasmDwCu) - sizeof(OpenasmDwAtArray);
    if (debug->debug_info.len + size > debug->debug_info.cap) {
        debug->debug_info.cap *= 2;
        debug->debug_info.ptr = realloc(debug->debug_info.ptr, debug->debug_info.cap);
    }
    memcpy((char *) debug->debug_info.ptr + debug->debug_info.len, cu, size);
    debug->debug_info.len += size;

    size = cu->attrs.len;
    if (debug->debug_info.len + size > debug->debug_info.cap) {
        debug->debug_info.cap *= 2;
        debug->debug_info.ptr = realloc(debug->debug_info.ptr, debug->debug_info.cap);
    }
    memcpy((char *) debug->debug_info.ptr + debug->debug_info.len, cu->attrs.ptr, size);
    debug->debug_info.len += size;
}

void openasm_dw_typeunit(OpenasmDebugData *debug, OpenasmDwTu *tu) {
    size_t size = sizeof(OpenasmDwTu) - sizeof(OpenasmDwAtArray);
    if (debug->debug_info.len + size > debug->debug_info.cap) {
        debug->debug_info.cap *= 2;
        debug->debug_info.ptr = realloc(debug->debug_info.ptr, debug->debug_info.cap);
    }
    memcpy((char *) debug->debug_info.ptr + debug->debug_info.len, tu, size);
    debug->debug_info.len += size;

    size = tu->attrs.len;
    if (debug->debug_info.len + size > debug->debug_info.cap) {
        debug->debug_info.cap *= 2;
        debug->debug_info.ptr = realloc(debug->debug_info.ptr, debug->debug_info.cap);
    }
    memcpy((char *) debug->debug_info.ptr + debug->debug_info.len, tu->attrs.ptr, size);
    debug->debug_info.len += size;
}

void openasm_dw_lineinfo(OpenasmDebugData *debug, OpenasmDwLnoHeader *lno) {
    size_t size = OPENASM_DW_LNO_HDR_CNST_SIZE;
    if (debug->debug_line.len + size > debug->debug_line.cap) {
        debug->debug_line.cap *= 2;
        debug->debug_line.ptr = realloc(debug->debug_line.ptr, debug->debug_line.cap);
    }
    memcpy((char *) debug->debug_line.ptr + debug->debug_line.len, lno, size);
    debug->debug_line.len += size;

    size = openasm_dw_lno_hdr_var_size(&lno->var);
    if (debug->debug_line.len + size > debug->debug_line.cap) {
        debug->debug_line.cap *= 2;
        debug->debug_line.ptr = realloc(debug->debug_line.ptr, debug->debug_line.cap);
    }
    size = 1;
    memcpy((char *) debug->debug_line.ptr + debug->debug_line.len, &lno->var.opcode_base, size);
    debug->debug_line.len += size;
    
    size = lno->var.opcode_base - 1;
    memcpy((char *) debug->debug_line.ptr + debug->debug_line.len, lno->var.standard_opcode_lengths, size);
    debug->debug_line.len += size;
    
    size = 1;
    memcpy((char *) debug->debug_line.ptr + debug->debug_line.len, &lno->var.directory_entry_format_count, size);
    debug->debug_line.len += size;

    for (size_t i = 0; i < lno->var.directory_entry_format_count; i++) {
        size = openasm_dw_copy_leb128((char *) debug->debug_line.ptr + debug->debug_line.len, &lno->var.directory_entry_format[i][0]);
        debug->debug_line.len += size;
        size = openasm_dw_copy_leb128((char *) debug->debug_line.ptr + debug->debug_line.len, &lno->var.directory_entry_format[i][1]);
        debug->debug_line.len += size;
    }
    
    size = openasm_dw_copy_leb128((char *) debug->debug_line.ptr + debug->debug_line.len, &lno->var.directories_count);
    debug->debug_line.len += size;
    uint64_t count = openasm_dw_uleb128_to_uint(&lno->var.directories_count);
    for (uint64_t i = 0; i < count; i++) {
        struct OpenasmDwLnoDirEnt *directory = &lno->var.directories[i];
        size = strlen(directory->name) + 1;
        memcpy((char *) debug->debug_line.ptr + debug->debug_line.len, directory->name, size);
        debug->debug_line.len += size;
    }
    
    size = 1;
    memcpy((char *) debug->debug_line.ptr + debug->debug_line.len, &lno->var.file_name_entry_format_count, size);
    debug->debug_line.len += size;
    
    for (size_t i = 0; i < lno->var.file_name_entry_format_count; i++) {
        size = openasm_dw_copy_leb128((char *) debug->debug_line.ptr + debug->debug_line.len, &lno->var.file_name_entry_format[i][0]);
        debug->debug_line.len += size;
        size = openasm_dw_copy_leb128((char *) debug->debug_line.ptr + debug->debug_line.len, &lno->var.file_name_entry_format[i][1]);
        debug->debug_line.len += size;
    }
    
    size = openasm_dw_copy_leb128((char *) debug->debug_line.ptr + debug->debug_line.len, &lno->var.file_names_count);
    debug->debug_line.len += size;
    count = openasm_dw_uleb128_to_uint(&lno->var.file_names_count);
    for (uint64_t i = 0; i < count; i++) {
        struct OpenasmDwLnoFileEnt *file_name = &lno->var.file_names[i];
        
        size = openasm_dw_copy_leb128((char *) debug->debug_line.ptr + debug->debug_line.len, &file_name->dir_idx);
        debug->debug_line.len += size;

        size = strlen(file_name->name) + 1;
        memcpy((char *) debug->debug_line.ptr + debug->debug_line.len, file_name->name, size);
        debug->debug_line.len += size;
    }
}

size_t openasm_dw_lno_hdr_var_size(struct OpenasmDwLnoVar *var) {
    size_t base_size = sizeof(uint8_t)                   
        + sizeof(uint8_t) * (var->opcode_base - 1)
        + sizeof(uint8_t)
        + sizeof(uint8_t);

    for (size_t i = 0; i < var->directory_entry_format_count; i++) {
        base_size += openasm_dw_sizeof_leb128(&var->directory_entry_format[i][0]);
        base_size += openasm_dw_sizeof_leb128(&var->directory_entry_format[i][1]);
    }
    
    base_size += openasm_dw_sizeof_leb128(&var->directories_count);

    uint64_t count = openasm_dw_uleb128_to_uint(&var->directories_count);
    for (uint64_t i = 0; i < count; i++) {
        struct OpenasmDwLnoDirEnt *directory = &var->directories[i];
        
        base_size += strlen(directory->name) + 1;
    }

    for (size_t i = 0; i < var->file_name_entry_format_count; i++) {
        base_size += openasm_dw_sizeof_leb128(&var->file_name_entry_format[i][0]);
        base_size += openasm_dw_sizeof_leb128(&var->file_name_entry_format[i][1]);
    }
    
    base_size += openasm_dw_sizeof_leb128(&var->file_names_count);
    
    count = openasm_dw_uleb128_to_uint(&var->file_names_count);
    for (uint64_t i = 0; i < count; i++) {
        struct OpenasmDwLnoFileEnt *file_name = &var->file_names[i];

        base_size += openasm_dw_sizeof_leb128(&file_name->dir_idx);
        base_size += strlen(file_name->name) + 1;
    }

    return base_size;
}

void openasm_dw_lno_op(OpenasmDwLineInfo *buf, uint8_t opcode) {
    if (buf->len + 1 > buf->cap) {
        buf->cap *= 2;
        buf->ptr = realloc(buf->ptr, buf->cap);
    }
    ((uint8_t *) buf->ptr + buf->len)[0] = opcode;
    buf->len += 1;
}

void openasm_dw_lno_op_ext(OpenasmDwLineInfo *buf, OpenasmLeb128 *size, uint8_t opcode) {
    if (buf->len + 3 > buf->cap) {
        buf->cap *= 2;
        buf->ptr = realloc(buf->ptr, buf->cap);
    }
    ((uint8_t *) buf->ptr + buf->len)[0] = 0;
    size_t len = openasm_dw_copy_leb128((char *) buf->ptr + buf->len + 1, size);
    ((uint8_t *) buf->ptr + buf->len)[len + 1] = opcode;
    buf->len += len + 2;
}

void openasm_dw_lno_arg(OpenasmDwLineInfo *buf, OpenasmLeb128 *arg) {
    if (buf->len + 16 > buf->cap) {
        buf->cap *= 2;
        buf->ptr = realloc(buf->ptr, buf->cap);
    }
    size_t len = openasm_dw_copy_leb128((char *) buf->ptr + buf->len, arg);
    buf->len += len;
}

void openasm_dw_lno_arg8(OpenasmDwLineInfo *buf, uint64_t arg) {
    if (buf->len + 16 > buf->cap) {
        buf->cap *= 2;
        buf->ptr = realloc(buf->ptr, buf->cap);
    }
    size_t len = 8;
    memcpy((char *) buf->ptr + buf->len, &arg, len);
    buf->len += len;
}

uint64_t openasm_dw_abbrev_offset(OpenasmDebugData *debug) {
    return debug->debug_abbrev.len;
}

void openasm_dw_abbrev_leb128(OpenasmDebugData *debug, OpenasmLeb128 *num) {
    if (debug->debug_abbrev.len + 16 > debug->debug_abbrev.cap) {
        debug->debug_abbrev.cap *= 2;
        debug->debug_abbrev.ptr = realloc(debug->debug_abbrev.ptr, debug->debug_abbrev.cap);
    }
    size_t len = openasm_dw_copy_leb128((char *) debug->debug_abbrev.ptr + debug->debug_abbrev.len, num);
    debug->debug_abbrev.len += len;
}

void openasm_dw_abbrev_entry(OpenasmDebugData *debug, OpenasmLeb128 *code, uint8_t children) {
    if (debug->debug_abbrev.len + 17 > debug->debug_abbrev.cap) {
        debug->debug_abbrev.cap *= 2;
        debug->debug_abbrev.ptr = realloc(debug->debug_abbrev.ptr, debug->debug_abbrev.cap);
    }
    size_t len = openasm_dw_copy_leb128((char *) debug->debug_abbrev.ptr + debug->debug_abbrev.len, code);
    debug->debug_abbrev.len += len;
    *((char *) debug->debug_abbrev.ptr + debug->debug_abbrev.len) = children;
    debug->debug_abbrev.len += 1;
}

void openasm_dw_abbrev_tag(OpenasmDebugData *debug, OpenasmLeb128 *name, OpenasmLeb128 *form) {
    if (debug->debug_abbrev.len + 32 > debug->debug_abbrev.cap) {
        debug->debug_abbrev.cap *= 2;
        debug->debug_abbrev.ptr = realloc(debug->debug_abbrev.ptr, debug->debug_abbrev.cap);
    }
    size_t len = openasm_dw_copy_leb128((char *) debug->debug_abbrev.ptr + debug->debug_abbrev.len, name);
    debug->debug_abbrev.len += len;
    len = openasm_dw_copy_leb128((char *) debug->debug_abbrev.ptr + debug->debug_abbrev.len, form);
    debug->debug_abbrev.len += len;
}

void openasm_dw_abbrev_end(OpenasmDebugData *debug) {
    OpenasmLeb128 zero;
    openasm_dw_uleb128(&zero, 0);
    openasm_dw_abbrev_leb128(debug, &zero);
    openasm_dw_abbrev_leb128(debug, &zero);
}

void openasm_dw_abbrev_terminate(OpenasmDebugData *debug) {
    OpenasmLeb128 zero;
    openasm_dw_uleb128(&zero, 0);
    openasm_dw_abbrev_leb128(debug, &zero);
}

void openasm_dw_at_leb128(OpenasmDwAtArray *array, OpenasmLeb128 *num) {
    if (array->len + 16 > array->cap) {
        array->cap *= 2;
        array->ptr = realloc(array->ptr, array->cap);
    }
    size_t len = openasm_dw_copy_leb128((char *) array->ptr + array->len, num);
    array->len += len;
}

void openasm_dw_at_string(OpenasmDwAtArray *array, const char *str) {
    size_t len = strlen(str) + 1;
    if (array->len + len > array->cap) {
        array->cap *= 2;
        array->ptr = realloc(array->ptr, array->cap);
    }
    memcpy((char *) array->ptr + array->len, str, len);
    array->len += len;
}

void openasm_dw_at_data8(OpenasmDwAtArray *array, uint64_t val) {
    size_t len = sizeof(uint64_t);
    if (array->len + len > array->cap) {
        array->cap *= 2;
        array->ptr = realloc(array->ptr, array->cap);
    }
    memcpy((char *) array->ptr + array->len, &val, len);
    array->len += len;
}

void openasm_dw_at_data4(OpenasmDwAtArray *array, uint32_t val) {
    size_t len = sizeof(uint32_t);
    if (array->len + len > array->cap) {
        array->cap *= 2;
        array->ptr = realloc(array->ptr, array->cap);
    }
    memcpy((char *) array->ptr + array->len, &val, len);
    array->len += len;
}

void openasm_dw_at_data2(OpenasmDwAtArray *array, uint16_t val) {
    size_t len = sizeof(uint16_t);
    if (array->len + len > array->cap) {
        array->cap *= 2;
        array->ptr = realloc(array->ptr, array->cap);
    }
    memcpy((char *) array->ptr + array->len, &val, len);
    array->len += len;
}

void openasm_dw_at_data1(OpenasmDwAtArray *array, uint8_t val) {
    size_t len = sizeof(uint8_t);
    if (array->len + len > array->cap) {
        array->cap *= 2;
        array->ptr = realloc(array->ptr, array->cap);
    }
    memcpy((char *) array->ptr + array->len, &val, len);
    array->len += len;
}

size_t openasm_dw_copy_leb128(void *_dst, OpenasmLeb128 *src) {
    unsigned char *dst = _dst;
    size_t i = 0;
    do {
        dst[i] = src->bytes[i];
    } while (src->bytes[i++] & 0x80);
    return i;
}

size_t openasm_dw_sizeof_leb128(OpenasmLeb128 *src) {
    size_t i = 0;
    do {} while (src->bytes[i++] & 0x80);
    return i;
}

OpenasmLeb128 *openasm_dw_uleb128(OpenasmLeb128 *dest, uint64_t value) {
    size_t i = 0;
    do {
        dest->bytes[i] = value & 0x7f;
        value >>= 7;
        ++i;
    } while (value);
    for (size_t j = 0; j < i - 1; j++) {
        dest->bytes[j] |= 0x80;
    }
    return dest;
}

OpenasmLeb128 *openasm_dw_sleb128(OpenasmLeb128 *dest, int64_t value) {
    int64_t signbits = (int64_t) (((uint64_t) value) >> 63) * -1;
    size_t i = 0;
    do {
        dest->bytes[i] = value & 0x7f;
        value >>= 7;
        ++i;
    } while (value != signbits);
    for (size_t j = 0; j < i - 1; j++) {
        dest->bytes[j] |= 0x80;
    }
    return dest;
}

uint64_t openasm_dw_uleb128_to_uint(OpenasmLeb128 *src) {
    uint64_t result = 0;
    size_t i = 0;
    do {
        result <<= 7;
        result |= src->bytes[i] & 0x7f;
    } while (src->bytes[i++] & 0x80);
    return result;
}

int64_t openasm_dw_sleb128_to_int(OpenasmLeb128 *src) {
    return openasm_dw_uleb128_to_uint(src);
}
