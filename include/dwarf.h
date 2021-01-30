#ifndef OPENASM_DWARF_H
#define OPENASM_DWARF_H 1

#include <stddef.h>
#include <stdint.h>
#include <libdwarf/dwarf.h>

typedef struct OpenasmDebugData OpenasmDebugData;
typedef struct OpenasmDebugIndexHeader OpenasmDebugIndexHeader;
typedef struct OpenasmDebugSection OpenasmDebugSection;
typedef struct OpenasmDwAtArray OpenasmDwAtArray;
typedef struct OpenasmDwCu OpenasmDwCu;
typedef struct OpenasmDwTu OpenasmDwTu;
typedef struct OpenasmDwLnoHeader OpenasmDwLnoHeader;
typedef struct OpenasmDwLineInfo OpenasmDwLineInfo;
typedef struct OpenasmLeb128 OpenasmLeb128;

struct OpenasmDebugSection {
    size_t cap;
    size_t len;
    void *ptr;
};

struct OpenasmDwLineInfo {
    size_t cap;
    size_t len;
    void *ptr;
};

#define OPENASM_DW_VERSION 5
#define OPENASM_DW_HT_OFFSET 16
#define OPENASM_DW_PT_OFFSET(s) (16 + 8 * (s))
#define OPENASM_DW_OT_OFFSET(s) (16 + 12 * (s))
#define OPENASM_DW_MASK(k) ((1 << k) - 1)
#define OPENASM_DW_REP(x) ((uint64_t) x)
#define OPENASM_DW_HASH1(x, k) (OPENASM_DW_REP(x) & OPENASM_DW_MASK(k))
#define OPENASM_DW_HASH2(x, k) (((OPENASM_DW_REP(x) >> 32) & OPENASM_DW_MASK(k)) | 1)
#define OPENASM_DW_ADDHASH(h1, h2, s) ((h1 + h2) % s)

#define OPENASM_DW_SPECIAL(m, n) (((m) - -3) + (12 * (n)) + 13)

struct OpenasmDebugIndexHeader {
    uint16_t version;
    uint16_t _pad0;
    uint32_t section_count;
    uint32_t unit_count;
    uint32_t slot_count;
};

struct OpenasmDebugData {
    union {
        OpenasmDebugSection dw_sect[5];
        struct {
            OpenasmDebugSection debug_aranges;
            OpenasmDebugSection debug_info;
            OpenasmDebugSection debug_abbrev;
            OpenasmDebugSection debug_line;
            OpenasmDebugSection debug_str;
        };
    };
};

struct OpenasmDwAtArray {
    size_t cap;
    size_t len;
    void *ptr;
};

struct OpenasmLeb128 {
    uint8_t bytes[16];
};

struct OpenasmDwLnoDirEnt {
    char *name;
};

struct OpenasmDwLnoFileEnt {
    OpenasmLeb128 dir_idx;
    char *name;
};

struct OpenasmDwLnoVar {
    uint8_t opcode_base;
    uint8_t *standard_opcode_lengths;
    
    uint8_t directory_entry_format_count;
    OpenasmLeb128 (*directory_entry_format)[2];
    OpenasmLeb128 directories_count;
    struct OpenasmDwLnoDirEnt *directories;

    uint8_t file_name_entry_format_count;
    OpenasmLeb128 (*file_name_entry_format)[2];
    OpenasmLeb128 file_names_count;
    struct OpenasmDwLnoFileEnt *file_names;
};

#define OPENASM_DW_LNO_HDR_CNST_SIZE 29
#define OPENASM_DW_LNO_HDR_SIZE(hdr) (OPENASM_DW_LNO_HDR_CNST_SIZE + openasm_dw_lno_hdr_var_size(&hdr.var))

#ifdef __GNUC__
struct OpenasmDwCu {
    uint32_t unit_length0 __attribute__((__packed__));
    uint64_t unit_length __attribute__((__packed__));
    uint16_t version __attribute__((__packed__));
    uint8_t unit_type;
    uint8_t address_size;
    uint64_t debug_abbrev_offset __attribute__((__packed__));
    OpenasmDwAtArray attrs;
};

struct OpenasmDwTu {
    uint32_t unit_length0 __attribute__((__packed__));
    uint64_t unit_length __attribute__((__packed__));
    uint16_t version __attribute__((__packed__));
    uint8_t unit_type;
    uint8_t address_size;
    uint64_t debug_abbrev_offset __attribute__((__packed__));
    uint64_t type_signature __attribute__((__packed__));
    uint64_t type_offset __attribute__((__packed__));
    OpenasmDwAtArray attrs;
};

struct OpenasmDwLnoHeader {
    uint32_t unit_length0 __attribute__((__packed__));
    uint64_t unit_length __attribute__((__packed__));
    uint16_t version __attribute__((__packed__));
    uint8_t address_size;
    uint8_t segment_selector_size;
    uint64_t header_length __attribute__((__packed__));
    uint8_t minimum_instruction_length;
    uint8_t maximum_operations_per_instruction;
    uint8_t default_is_stmt;
    int8_t line_base;
    uint8_t line_range;
    struct OpenasmDwLnoVar var;
};

#else /* __GNUC__ */

struct OpenasmDwCu {
    uint8_t unit_length0[4];
    uint8_t unit_length[8];
    uint8_t version[2];
    uint8_t unit_type;
    uint8_t address_size;
    uint8_t debug_abbrev_offset[8];
    OpenasmDwAtArray attrs;
};

struct OpenasmDwTu {
    uint8_t unit_length0[4];
    uint8_t unit_length[8];
    uint8_t version[2];
    uint8_t unit_type;
    uint8_t address_size;
    uint8_t debug_abbrev_offset[8];
    uint8_t type_signature[8];
    uint8_t type_offset[8];
    OpenasmDwAtArray attrs;
};

struct OpenasmDwLnoHeader {
    uint8_t unit_length0[4];
    uint8_t unit_length[8];
    uint8_t version[2];
    uint8_t address_size;
    uint8_t segment_selector_size;
    uint8_t header_length[8];
    uint8_t minimum_instruction_length;
    uint8_t maximum_operations_per_instruction;
    uint8_t default_is_stmt;
    int8_t line_base;
    uint8_t line_range;
    struct OpenasmDwLnoVar var;
};
#endif /* __GNUC__ */

typedef void (*openasm_dw_debugdata_f)(OpenasmDebugData *debug);
typedef void (*openasm_dw_at_array_f)(OpenasmDwAtArray *array);
typedef void (*openasm_dw_lno_buffer_f)(OpenasmDwLineInfo *buf);
typedef void (*openasm_dw_compunit_f)(OpenasmDebugData *debug, OpenasmDwCu *cu);
typedef void (*openasm_dw_typeunit_f)(OpenasmDebugData *debug, OpenasmDwTu *tu);
typedef void (*openasm_dw_lineinfo_f)(OpenasmDebugData *debug, OpenasmDwLnoHeader *lno);
typedef size_t (*openasm_dw_lno_hdr_var_size_f)(struct OpenasmDwLnoVar *var);
typedef void (*openasm_dw_lno_op_f)(OpenasmDwLineInfo *buf, uint8_t opcode);
typedef void (*openasm_dw_lno_op_ext_f)(OpenasmDwLineInfo *buf, OpenasmLeb128 *size, uint8_t opcode);
typedef void (*openasm_dw_lno_arg_f)(OpenasmDwLineInfo *buf, OpenasmLeb128 *arg);
typedef void (*openasm_dw_lno_arg8_f)(OpenasmDwLineInfo *buf, uint64_t arg);
typedef uint64_t (*openasm_dw_abbrev_offset_f)(OpenasmDebugData *debug);
typedef void (*openasm_dw_abbrev_leb128_f)(OpenasmDebugData *debug, OpenasmLeb128 *num);
typedef void (*openasm_dw_abbrev_entry_f)(OpenasmDebugData *debug, OpenasmLeb128 *code, uint8_t children);
typedef void (*openasm_dw_abbrev_tag_f)(OpenasmDebugData *debug, OpenasmLeb128 *name, OpenasmLeb128 *form);
typedef void (*openasm_dw_abbrev_end_f)(OpenasmDebugData *debug);
typedef void (*openasm_dw_abbrev_terminate_f)(OpenasmDebugData *debug);
typedef void (*openasm_dw_at_leb128_f)(OpenasmDwAtArray *array, OpenasmLeb128 *num);
typedef void (*openasm_dw_at_string_f)(OpenasmDwAtArray *array, const char *str);
typedef void (*openasm_dw_at_data8_f)(OpenasmDwAtArray *array, uint64_t val);
typedef void (*openasm_dw_at_data4_f)(OpenasmDwAtArray *array, uint32_t val);
typedef void (*openasm_dw_at_data2_f)(OpenasmDwAtArray *array, uint16_t val);
typedef void (*openasm_dw_at_data1_f)(OpenasmDwAtArray *array, uint8_t val);
typedef size_t (*openasm_dw_copy_leb128_f)(void *dst, OpenasmLeb128 *src);
typedef size_t (*openasm_dw_sizeof_leb128_f)(OpenasmLeb128 *src);
typedef OpenasmLeb128 *(*openasm_dw_uleb128_f)(OpenasmLeb128 *dest, uint64_t value);
typedef OpenasmLeb128 *(*openasm_dw_sleb128_f)(OpenasmLeb128 *dest, int64_t value);
typedef uint64_t (*openasm_dw_uleb128_to_uint_f)(OpenasmLeb128 *dest);
typedef int64_t (*openasm_dw_sleb128_to_int_f)(OpenasmLeb128 *dest);

void openasm_dw_debugdata(OpenasmDebugData *debug);
void openasm_dw_at_array(OpenasmDwAtArray *array);
void openasm_dw_lno_buffer(OpenasmDwLineInfo *buf);
void openasm_dw_compunit(OpenasmDebugData *debug, OpenasmDwCu *cu);
void openasm_dw_typeunit(OpenasmDebugData *debug, OpenasmDwTu *tu);
void openasm_dw_lineinfo(OpenasmDebugData *debug, OpenasmDwLnoHeader *lno);
size_t openasm_dw_lno_hdr_var_size(struct OpenasmDwLnoVar *var);
void openasm_dw_lno_op(OpenasmDwLineInfo *buf, uint8_t opcode);
void openasm_dw_lno_op_ext(OpenasmDwLineInfo *buf, OpenasmLeb128 *size, uint8_t opcode);
void openasm_dw_lno_arg(OpenasmDwLineInfo *buf, OpenasmLeb128 *arg);
void openasm_dw_lno_arg8(OpenasmDwLineInfo *buf, uint64_t arg);
uint64_t openasm_dw_abbrev_offset(OpenasmDebugData *debug);
void openasm_dw_abbrev_leb128(OpenasmDebugData *debug, OpenasmLeb128 *num);
void openasm_dw_abbrev_entry(OpenasmDebugData *debug, OpenasmLeb128 *code, uint8_t children);
void openasm_dw_abbrev_tag(OpenasmDebugData *debug, OpenasmLeb128 *name, OpenasmLeb128 *form);
void openasm_dw_abbrev_end(OpenasmDebugData *debug);
void openasm_dw_abbrev_terminate(OpenasmDebugData *debug);
void openasm_dw_at_leb128(OpenasmDwAtArray *array, OpenasmLeb128 *num);
void openasm_dw_at_string(OpenasmDwAtArray *array, const char *str);
void openasm_dw_at_data8(OpenasmDwAtArray *array, uint64_t val);
void openasm_dw_at_data4(OpenasmDwAtArray *array, uint32_t val);
void openasm_dw_at_data2(OpenasmDwAtArray *array, uint16_t val);
void openasm_dw_at_data1(OpenasmDwAtArray *array, uint8_t val);
size_t openasm_dw_copy_leb128(void *dst, OpenasmLeb128 *src);
size_t openasm_dw_sizeof_leb128(OpenasmLeb128 *src);
OpenasmLeb128 *openasm_dw_uleb128(OpenasmLeb128 *dest, uint64_t value);
OpenasmLeb128 *openasm_dw_sleb128(OpenasmLeb128 *dest, int64_t value);
uint64_t openasm_dw_uleb128_to_uint(OpenasmLeb128 *dest);
int64_t openasm_dw_sleb128_to_int(OpenasmLeb128 *dest);

#endif /* OPENASM_DWARF_H */
