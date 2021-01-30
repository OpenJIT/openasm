#include <errno.h>
#define OPENASM_ARCH_AMD64 1
#include "include/openasm.h"
#include "include/dwarf.h"

#define PRODUCER "OpenJit/OpenAsm 0.0.0 amd64"

int main() {
    int status = 0;
    
    OpenasmBuffer buf;
    openasm_buffer(&buf);
    const char *reg0 = "r8";
    const char *reg1 = "r9";
    uint64_t _start = openasm_current_addr(&buf);
    status |= openasm_instf(&buf, "mov %r, %i64", "rbp", 0);
    status |= openasm_instf(&buf, "call %p", "text", "fun");
    status |= openasm_instf(&buf, "mov %r, %i64", "rdi", 0);
    status |= openasm_instf(&buf, "mov %r, %i64", "rax", 60);
    status |= openasm_instf(&buf, "syscall");

    uint64_t fun = openasm_current_addr(&buf);
    status |= openasm_instf(&buf, "mov %r, %i64", reg0, 42);
    status |= openasm_instf(&buf, "mov %r, %i64", reg1, 69);
    status |= openasm_instf(&buf, "add %r, %r", reg0, reg1);
    status |= openasm_instf(&buf, "mov %r, %r", "rax", reg0);
    status |= openasm_instf(&buf, "ret");
    uint64_t end = openasm_current_addr(&buf);

    openasm_symbol(&buf, "text", "_start", OPENASM_BIND_GLOBAL, _start, fun - _start);
    openasm_symbol(&buf, "text", "fun", OPENASM_BIND_LOCAL, fun, end - fun);

    OpenasmLeb128 leb[2];
    OpenasmDwLineInfo lnobuf;
    openasm_dw_lno_buffer(&lnobuf);

    openasm_dw_lno_op(&lnobuf, DW_LNS_set_column);
    openasm_dw_lno_arg(&lnobuf, openasm_dw_uleb128(&leb[0], 4));
    openasm_dw_lno_op(&lnobuf, DW_LNS_advance_line);
    openasm_dw_lno_arg(&lnobuf, openasm_dw_uleb128(&leb[0], 15));
    openasm_dw_lno_op_ext(&lnobuf, openasm_dw_uleb128(&leb[0], 9), DW_LNE_set_address);
    openasm_dw_lno_arg8(&lnobuf, 0x400160);
    openasm_dw_lno_op(&lnobuf, OPENASM_DW_SPECIAL(0, 0));
    openasm_dw_lno_op(&lnobuf, OPENASM_DW_SPECIAL(1, 10));
    openasm_dw_lno_op(&lnobuf, OPENASM_DW_SPECIAL(1, 5));
    openasm_dw_lno_op(&lnobuf, OPENASM_DW_SPECIAL(1, 10));
    openasm_dw_lno_op(&lnobuf, OPENASM_DW_SPECIAL(1, 10));
    openasm_dw_lno_op(&lnobuf, OPENASM_DW_SPECIAL(1, 2));
    openasm_dw_lno_op_ext(&lnobuf, openasm_dw_uleb128(&leb[0], 1), DW_LNE_end_sequence);

    OpenasmDwLnoHeader lno;
    lno.var.opcode_base = 13;
    lno.var.standard_opcode_lengths = malloc(12);
    lno.var.standard_opcode_lengths[0] = 0;
    lno.var.standard_opcode_lengths[1] = 1;
    lno.var.standard_opcode_lengths[2] = 1;
    lno.var.standard_opcode_lengths[3] = 1;
    lno.var.standard_opcode_lengths[4] = 1;
    lno.var.standard_opcode_lengths[5] = 0;
    lno.var.standard_opcode_lengths[6] = 0;
    lno.var.standard_opcode_lengths[7] = 0;
    lno.var.standard_opcode_lengths[8] = 1;
    lno.var.standard_opcode_lengths[9] = 0;
    lno.var.standard_opcode_lengths[10] = 0;
    lno.var.standard_opcode_lengths[11] = 1;
    
    lno.var.directory_entry_format_count = 1;
    lno.var.directory_entry_format = malloc(sizeof(OpenasmLeb128) * 2);
    openasm_dw_uleb128(&lno.var.directory_entry_format[0][0], DW_LNCT_path);
    openasm_dw_uleb128(&lno.var.directory_entry_format[0][1], DW_FORM_string);
    openasm_dw_uleb128(&lno.var.directories_count, 1);
    const char *dir = "/home/waltersz/repos/ampersand/openasm/amd64";
    lno.var.directories = malloc(1 * sizeof(struct OpenasmDwLnoDirEnt));
    lno.var.directories[0].name = malloc(strlen(dir) + 1);
    strcpy(lno.var.directories[0].name, dir);
    
    lno.var.file_name_entry_format_count = 2;
    lno.var.file_name_entry_format = malloc(2 * sizeof(OpenasmLeb128) * 2);
    openasm_dw_uleb128(&lno.var.file_name_entry_format[0][0], DW_LNCT_directory_index);
    openasm_dw_uleb128(&lno.var.file_name_entry_format[0][1], DW_FORM_udata);
    openasm_dw_uleb128(&lno.var.file_name_entry_format[1][0], DW_LNCT_path);
    openasm_dw_uleb128(&lno.var.file_name_entry_format[1][1], DW_FORM_string);
    openasm_dw_uleb128(&lno.var.file_names_count, 1);
    lno.var.file_names = malloc(1 * sizeof(struct OpenasmDwLnoFileEnt));
    const char *file = "test.c";
    openasm_dw_uleb128(&lno.var.file_names[0].dir_idx, 0);
    lno.var.file_names[0].name = malloc(strlen(file) + 1);
    strcpy(lno.var.file_names[0].name, file);

    size_t lno_hdr_size = OPENASM_DW_LNO_HDR_SIZE(lno);
    lno.unit_length0 = 0xffffffff;
    lno.unit_length = lno_hdr_size - offsetof(OpenasmDwLnoHeader, version) + lnobuf.len;
    lno.version = 5;
    lno.address_size = 8;
    lno.segment_selector_size = 0;
    lno.header_length = lno_hdr_size - offsetof(OpenasmDwLnoHeader, minimum_instruction_length);
    lno.minimum_instruction_length = 1;
    lno.maximum_operations_per_instruction = 1;
    lno.default_is_stmt = 1;
    lno.line_base = -3;
    lno.line_range = 12;

    OpenasmDebugData debug;
    openasm_dw_debugdata(&debug);

    openasm_dw_lineinfo(&debug, &lno);

    uint64_t offset = openasm_dw_abbrev_offset(&debug);
    openasm_dw_abbrev_leb128(&debug, openasm_dw_uleb128(&leb[0], 1));
    openasm_dw_abbrev_entry(&debug, openasm_dw_uleb128(&leb[0], DW_TAG_compile_unit), DW_CHILDREN_yes);
    openasm_dw_abbrev_tag(&debug, openasm_dw_uleb128(&leb[0], DW_AT_producer), openasm_dw_uleb128(&leb[1], DW_FORM_string));
    openasm_dw_abbrev_tag(&debug, openasm_dw_uleb128(&leb[0], DW_AT_name), openasm_dw_uleb128(&leb[1], DW_FORM_string));
    openasm_dw_abbrev_tag(&debug, openasm_dw_uleb128(&leb[0], DW_AT_comp_dir), openasm_dw_uleb128(&leb[1], DW_FORM_string));
    openasm_dw_abbrev_tag(&debug, openasm_dw_uleb128(&leb[0], DW_AT_stmt_list), openasm_dw_uleb128(&leb[1], DW_FORM_sec_offset));
    openasm_dw_abbrev_end(&debug);

    openasm_dw_abbrev_leb128(&debug, openasm_dw_uleb128(&leb[0], 2));
    openasm_dw_abbrev_entry(&debug, openasm_dw_uleb128(&leb[0], DW_TAG_subprogram), DW_CHILDREN_no);
    openasm_dw_abbrev_tag(&debug, openasm_dw_uleb128(&leb[0], DW_AT_name), openasm_dw_uleb128(&leb[1], DW_FORM_string));
    openasm_dw_abbrev_tag(&debug, openasm_dw_uleb128(&leb[0], DW_AT_decl_file), openasm_dw_uleb128(&leb[1], DW_FORM_udata));
    openasm_dw_abbrev_tag(&debug, openasm_dw_uleb128(&leb[0], DW_AT_decl_line), openasm_dw_uleb128(&leb[1], DW_FORM_udata));
    openasm_dw_abbrev_tag(&debug, openasm_dw_uleb128(&leb[0], DW_AT_decl_column), openasm_dw_uleb128(&leb[1], DW_FORM_udata));
    openasm_dw_abbrev_tag(&debug, openasm_dw_uleb128(&leb[0], DW_AT_low_pc), openasm_dw_uleb128(&leb[1], DW_FORM_addr));
    openasm_dw_abbrev_tag(&debug, openasm_dw_uleb128(&leb[0], DW_AT_high_pc), openasm_dw_uleb128(&leb[1], DW_FORM_addr));
    openasm_dw_abbrev_end(&debug);
    openasm_dw_abbrev_terminate(&debug);

    OpenasmDwCu cu;
    openasm_dw_at_array(&cu.attrs);
    // DW_TAG_compile_unit
    openasm_dw_at_leb128(&cu.attrs, openasm_dw_uleb128(&leb[0], 1));
    openasm_dw_at_string(&cu.attrs, PRODUCER);
    openasm_dw_at_string(&cu.attrs, "test.c");
    openasm_dw_at_string(&cu.attrs, "/home/waltersz/repos/ampersand/openasm/amd64");
    openasm_dw_at_data8(&cu.attrs, 0);
    // DW_TAG_subprogram
    openasm_dw_at_leb128(&cu.attrs, openasm_dw_uleb128(&leb[0], 2));
    openasm_dw_at_string(&cu.attrs, "_start");
    openasm_dw_at_leb128(&cu.attrs, openasm_dw_uleb128(&leb[0], 0));
    openasm_dw_at_leb128(&cu.attrs, openasm_dw_uleb128(&leb[0], 16));
    openasm_dw_at_leb128(&cu.attrs, openasm_dw_uleb128(&leb[0], 4));
    openasm_dw_at_data8(&cu.attrs, 0x400160);
    openasm_dw_at_data8(&cu.attrs, 0x400185);
    // end
    openasm_dw_at_leb128(&cu.attrs, openasm_dw_uleb128(&leb[0], 0));
    cu.unit_length0 = 0xffffffff;
    cu.unit_length = cu.attrs.len + sizeof(OpenasmDwCu) - sizeof(OpenasmDwAtArray) - 12;
    cu.version = 5;
    cu.unit_type = DW_UT_compile;
    cu.address_size = 8;
    cu.debug_abbrev_offset = offset;
    openasm_dw_compunit(&debug, &cu);

    openasm_section(&buf, "debug_info");
    openasm_data(&buf, debug.debug_info.len, debug.debug_info.ptr);
    openasm_section(&buf, "debug_abbrev");
    openasm_data(&buf, debug.debug_abbrev.len, debug.debug_abbrev.ptr);
    openasm_section(&buf, "debug_line");
    openasm_data(&buf, debug.debug_line.len, debug.debug_line.ptr);
    openasm_data(&buf, lnobuf.len, lnobuf.ptr);
    
    openasm_link(&buf);

    if (status) {
        return status;
    }

    FILE *fileout = fopen("a.out", "w");
    openasm_elfdump(fileout, OPENASM_ELF_EXEC, &buf);
    fclose(fileout);

    OpenasmFni fn = openasm_jit_fni(&buf);
    int i = fn();
    printf("%d\n", i);
    
    return 0;
}
