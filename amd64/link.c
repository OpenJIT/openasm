#include <sys/stat.h>
#define OPENASM_ARCH_AMD64 1
#include "include/openasm.h"

#define DEFAULT_BUFFER_CAP ((size_t) 16384)

void openasm_section(OpenasmBuffer *buf, const char *section) {
    for (size_t i = 0; i < buf->len; i++) {
        if (strcmp(buf->sections[i].name, section) == 0) {
            buf->section = i;
            return;
        }
    }

    if (buf->len == buf->cap) {
        buf->cap *= 2;
        buf->sections = realloc(buf->sections, buf->cap * sizeof(struct OpenasmSection));
    }

    size_t cap = DEFAULT_BUFFER_CAP;
    buf->sections[buf->len].name = section;
    buf->sections[buf->len].cap = cap;
    buf->sections[buf->len].len = 0;
    buf->sections[buf->len].buffer = malloc(cap);
    buf->section = buf->len++;
}

bool openasm_section_exists(OpenasmBuffer *buf, const char *section) {
    for (size_t i = 0; i < buf->len; i++) {
        if (strcmp(buf->sections[i].name, section) == 0) {
            return 1;
        }
    }
    
    return 0;
}

uint64_t openasm_addr_of(OpenasmBuffer *buf, uint8_t *inst) {
    return inst - buf->sections[buf->section].buffer;
}

uint64_t openasm_current_addr(OpenasmBuffer *buf) {
    return buf->sections[buf->section].len;
}

bool openasm_symbol(OpenasmBuffer *buf, const char *section, const char *sym, int binding, uint64_t addr, uint64_t size) {
    bool used = 0;
    for (size_t i = 0; i < buf->symtable.len; i++) {
        if (strcmp(buf->symtable.table[i].addr_section, section) == 0
            && strcmp(buf->symtable.table[i].sym, sym) == 0) {
            used = 1;
	    // TODO: set the shift and mask shits
            buf->symtable.table[i].addr = addr;
            buf->symtable.table[i].size = size;
            buf->symtable.table[i].binding = binding;
            buf->symtable.table[i].defined = 1;
        }
    }
    if (binding != OPENASM_BIND_PRIVATE) {
        if (buf->export.len == buf->export.cap) {
            buf->export.cap *= 2;
            buf->export.table = realloc(buf->export.table, buf->export.cap * sizeof(struct OpenasmSymbol));
        }
        buf->export.table[buf->export.len].addr_section = malloc(strlen(section) + 1);
        strcpy((char *) buf->export.table[buf->export.len].addr_section, section);
        buf->export.table[buf->export.len].sym = malloc(strlen(sym) + 1);
        strcpy((char *) buf->export.table[buf->export.len].sym, sym);
        buf->export.table[buf->export.len].addr = addr;
        buf->export.table[buf->export.len].size = size;
        buf->export.table[buf->export.len].binding = binding;
        buf->export.table[buf->export.len].defined = 1;
        ++buf->export.len;
    }
    return used;
}

int openasm_link(OpenasmBuffer *buf) {
    int status = 0;
    for (size_t i = 0; i < buf->symtable.len; i++) {
        if (!buf->symtable.table[i].defined) {
            status = 1;
            fprintf(stderr, "warning: undefined symbol: %s\n", buf->symtable.table[i].sym);
            continue;
        }
        openasm_section(buf, buf->symtable.table[i].src_section);
        int rel = buf->symtable.table[i].rel;
        size_t size = buf->symtable.table[i].bits >> 3;
        uint64_t offset = buf->symtable.table[i].offset;
        uint64_t addr = buf->symtable.table[i].addr;
        if (rel) {
            addr = addr - (offset + size);
        }
        uint8_t *ptr = buf->sections[buf->section].buffer + offset;
        switch (buf->symtable.table[i].bits) {
        case 8:
            *ptr = addr & 0xff;
            break;
        case 16:
            *((uint16_t *) ptr) = addr & 0xffff;
            break;
        case 32:
            *((uint32_t *) ptr) = addr & 0xffffffff;
            break;
        case 64:
            *((uint64_t *) ptr) = addr;
            break;
        default:
            /* unreachable */
            break;
        }
    }
    return status;
}

int openasm_rawdump(FILE *fileout, OpenasmBuffer *buf) {
    openasm_section(buf, "text");
    size_t text_size = buf->sections[buf->section].len;
    void *text_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "data");
    size_t data_size = buf->sections[buf->section].len;
    void *data_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "rodata");
    size_t rodata_size = buf->sections[buf->section].len;
    void *rodata_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "bss");
    size_t bss_size = buf->sections[buf->section].len;
    void *bss_ptr = buf->sections[buf->section].buffer;
    
    fwrite(text_ptr, 1, text_size, fileout);
    fwrite(rodata_ptr, 1, rodata_size, fileout);
    fwrite(data_ptr, 1, data_size, fileout);
    fwrite(bss_ptr, 1, bss_size, fileout);

    /* fchmod(fileno(fileout), 0755); */

    return 0;
}

// this function was written with the help of `dumpelf` from `pax-utils`
int openasm_elfdump(FILE *fileout, int flags, OpenasmBuffer *buf) {
    unsigned char class = ELFCLASS64;
    unsigned char data = ELFDATA2LSB;
    unsigned char version = EV_CURRENT;
    unsigned char osabi = ELFOSABI_NONE;
    unsigned char abiversion = 0;
    Elf64_Half type;
    if ((flags & OPENASM_ELF_TYPE) == OPENASM_ELF_CORE) {
        type = ET_CORE;
    } else if ((flags & OPENASM_ELF_TYPE) == OPENASM_ELF_DYN) {
        type = ET_DYN;
    } else if ((flags & OPENASM_ELF_TYPE) == OPENASM_ELF_EXEC) {
        type = ET_EXEC;
    } else /* if ((flags & OPENASM_ELF_TYPE) == OPENASM_ELF_REL) */ {
        type = ET_REL;
    }
    Elf64_Half machine = EM_X86_64;
    struct OpenasmElf elf = {
        .ehdr = {
            .e_ident = { /* (EI_NIDENT bytes) */
		/* [0] EI_MAG:        */ 0x7F,'E','L','F',
		/* [4] EI_CLASS:      */ class,
		/* [5] EI_DATA:       */ data,
		/* [6] EI_VERSION:    */ version,
		/* [7] EI_OSABI:      */ osabi,
		/* [8] EI_ABIVERSION: */ abiversion,
		/* [9-15] EI_PAD:     */ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            },
            .e_type      = type       ,
            .e_machine   = machine    ,
            .e_version   = 1          ,
            .e_entry     = 0x400000   , /* (start address at runtime) */
            .e_phoff     = 0          , /* (bytes into file) */
            .e_shoff     = 0          , /* (bytes into file) */
            .e_flags     = 0x0        ,
            .e_ehsize    = 64         , /* (bytes) */
            .e_phentsize = 56         , /* (bytes) */
            .e_phnum     = 5          , /* (program headers) */
            .e_shentsize = 64         , /* (bytes) */
            .e_shnum     = 11          , /* (section headers) */
            .e_shstrndx  = 10
        },
        .phdrs = {
            // (elf and program headers)
            {
                .p_type   = PT_LOAD    ,
                .p_offset = 0          , /* (bytes into file) */
                .p_vaddr  = 0x400000   , /* (virtual addr at runtime) */
                .p_paddr  = 0x400000   , /* (physical addr at runtime) */
                .p_filesz = 344        , /* (bytes in file) */
                .p_memsz  = 344        , /* (bytes in mem at runtime) */
                .p_flags  = PF_R       ,
                .p_align  = 4096       , /* (min mem alignment in bytes) */
            },
            // .text
            {
                .p_type   = PT_LOAD    ,
                .p_offset = 0          , /* (bytes into file) */
                .p_vaddr  = 0x400000   , /* (virtual addr at runtime) */
                .p_paddr  = 0x400000   , /* (physical addr at runtime) */
                .p_filesz = 0          , /* (bytes in file) */
                .p_memsz  = 0          , /* (bytes in mem at runtime) */
                .p_flags  = PF_R | PF_X,
                .p_align  = 16         , /* (min mem alignment in bytes) */
            },
            // .rodata
            {
                .p_type   = PT_LOAD    ,
                .p_offset = 0          , /* (bytes into file) */
                .p_vaddr  = 0x400000   , /* (virtual addr at runtime) */
                .p_paddr  = 0x400000   , /* (physical addr at runtime) */
                .p_filesz = 0          , /* (bytes in file) */
                .p_memsz  = 0          , /* (bytes in mem at runtime) */
                .p_flags  = PF_R       ,
                .p_align  = 16         , /* (min mem alignment in bytes) */
            },
            // .data
            {
                .p_type   = PT_LOAD    ,
                .p_offset = 0          , /* (bytes into file) */
                .p_vaddr  = 0x400000   , /* (virtual addr at runtime) */
                .p_paddr  = 0x400000   , /* (physical addr at runtime) */
                .p_filesz = 0          , /* (bytes in file) */
                .p_memsz  = 0          , /* (bytes in mem at runtime) */
                .p_flags  = PF_R | PF_W,
                .p_align  = 16         , /* (min mem alignment in bytes) */
            },
            // .bss
            {
                .p_type   = PT_LOAD    ,
                .p_offset = 0          , /* (bytes into file) */
                .p_vaddr  = 0x400000   , /* (virtual addr at runtime) */
                .p_paddr  = 0x400000   , /* (physical addr at runtime) */
                .p_filesz = 0          , /* (bytes in file) */
                .p_memsz  = 128        , /* (bytes in mem at runtime) */
                .p_flags  = PF_R | PF_W,
                .p_align  = 16         , /* (min mem alignment in bytes) */
            },
        },

        .shdrs = {
            {
                .sh_name      = 0          ,
                .sh_type      = SHT_NULL   ,
                .sh_flags     = 0          ,
                .sh_addr      = 0x0        ,
                .sh_offset    = 0          , /* (bytes) */
                .sh_size      = 0          , /* (bytes) */
                .sh_link      = 0          ,
                .sh_info      = 0          ,
                .sh_addralign = 0          ,
                .sh_entsize   = 0         
            },
            // .text
            {
                .sh_name      = 0           ,
                .sh_type      = SHT_PROGBITS,
                .sh_flags     = 6           ,
                .sh_addr      = 0x400000    ,
                .sh_offset    = 0           , /* (bytes) */
                .sh_size      = 0           , /* (bytes) */
                .sh_link      = 0           ,
                .sh_info      = 0           ,
                .sh_addralign = 16          ,
                .sh_entsize   = 0         
            },
            // .rodata
            {
                .sh_name      = 0           ,
                .sh_type      = SHT_PROGBITS,
                .sh_flags     = 2           ,
                .sh_addr      = 0x400000    ,
                .sh_offset    = 0           , /* (bytes) */
                .sh_size      = 0           , /* (bytes) */
                .sh_link      = 0           ,
                .sh_info      = 0           ,
                .sh_addralign = 8           ,
                .sh_entsize   = 0         
            },
            // .data
            {
                .sh_name      = 0           ,
                .sh_type      = SHT_PROGBITS,
                .sh_flags     = 3           ,
                .sh_addr      = 0x400000    ,
                .sh_offset    = 0           , /* (bytes) */
                .sh_size      = 0           , /* (bytes) */
                .sh_link      = 0           ,
                .sh_info      = 0           ,
                .sh_addralign = 32          ,
                .sh_entsize   = 0         
            },
            // .bss
            {
                .sh_name      = 0          ,
                .sh_type      = SHT_NOBITS ,
                .sh_flags     = 3          ,
                .sh_addr      = 0x400000   ,
                .sh_offset    = 0          , /* (bytes) */
                .sh_size      = 128        , /* (bytes) */
                .sh_link      = 0          ,
                .sh_info      = 0          ,
                .sh_addralign = 32         ,
                .sh_entsize   = 0         
            },
            // .debug_info
            {
                .sh_name      = 0           ,
                .sh_type      = SHT_PROGBITS,
                .sh_flags     = 0           ,
                .sh_addr      = 0x000000    ,
                .sh_offset    = 0           , /* (bytes) */
                .sh_size      = 0           , /* (bytes) */
                .sh_link      = 0           ,
                .sh_info      = 0           ,
                .sh_addralign = 16          ,
                .sh_entsize   = 0         
            },
            // .debug_abbrev
            {
                .sh_name      = 0           ,
                .sh_type      = SHT_PROGBITS,
                .sh_flags     = 0           ,
                .sh_addr      = 0x000000    ,
                .sh_offset    = 0           , /* (bytes) */
                .sh_size      = 0           , /* (bytes) */
                .sh_link      = 0           ,
                .sh_info      = 0           ,
                .sh_addralign = 16          ,
                .sh_entsize   = 0         
            },
            // .debug_line
            {
                .sh_name      = 0           ,
                .sh_type      = SHT_PROGBITS,
                .sh_flags     = 0           ,
                .sh_addr      = 0x000000    ,
                .sh_offset    = 0           , /* (bytes) */
                .sh_size      = 0           , /* (bytes) */
                .sh_link      = 0           ,
                .sh_info      = 0           ,
                .sh_addralign = 16          ,
                .sh_entsize   = 0         
            },
            // .symtab
            {
                .sh_name      = 0          ,
                .sh_type      = SHT_SYMTAB ,
                .sh_flags     = 0          ,
                .sh_addr      = 0x0        ,
                .sh_offset    = 0          , /* (bytes) */
                .sh_size      = 0          , /* (bytes) */
                .sh_link      = 9          ,
                .sh_info      = 0          ,
                .sh_addralign = 8          ,
                .sh_entsize   = sizeof(Elf64_Sym)         
            },
            // .strtab
            {
                .sh_name      = 0          ,
                .sh_type      = SHT_STRTAB ,
                .sh_flags     = 0          ,
                .sh_addr      = 0x0        ,
                .sh_offset    = 0          , /* (bytes) */
                .sh_size      = 0          , /* (bytes) */
                .sh_link      = 0          ,
                .sh_info      = 0          ,
                .sh_addralign = 1          ,
                .sh_entsize   = 0         
            },
            // .shstrtab
            {
                .sh_name      = 0          ,
                .sh_type      = SHT_STRTAB ,
                .sh_flags     = 0          ,
                .sh_addr      = 0x0        ,
                .sh_offset    = 0          , /* (bytes) */
                .sh_size      = 0          , /* (bytes) */
                .sh_link      = 0          ,
                .sh_info      = 0          ,
                .sh_addralign = 1          ,
                .sh_entsize   = 0         
            },
        }
    };

    size_t phdr_offset = offsetof(struct OpenasmElf, phdrs);

    openasm_section(buf, "text");
    size_t text_offset = openasm_align_up(offsetof(struct OpenasmElf, shdrs), 16);
    size_t text_size = buf->sections[buf->section].len;
    void *text_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "data");
    size_t data_offset = openasm_align_up(text_offset + text_size, 16);
    size_t data_size = buf->sections[buf->section].len;
    void *data_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "rodata");
    size_t rodata_offset = openasm_align_up(data_offset + data_size, 16);
    size_t rodata_size = buf->sections[buf->section].len;
    void *rodata_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "bss");
    size_t bss_offset = openasm_align_up(rodata_offset + rodata_size, 16);
    size_t bss_size = buf->sections[buf->section].len;
    size_t debug_info_offset = bss_offset;
    size_t debug_info_size = 0;
    void *debug_info_ptr = NULL;
    if (openasm_section_exists(buf, "debug_info")) {
        openasm_section(buf, "debug_info");
        debug_info_offset = openasm_align_up(bss_offset + bss_size, 16);
        debug_info_size = buf->sections[buf->section].len;
        debug_info_ptr = buf->sections[buf->section].buffer;
    }
    size_t debug_abbrev_offset = bss_offset;
    size_t debug_abbrev_size = 0;
    void *debug_abbrev_ptr = NULL;
    if (openasm_section_exists(buf, "debug_abbrev")) {
        openasm_section(buf, "debug_abbrev");
        debug_abbrev_offset = openasm_align_up(debug_info_offset + debug_info_size, 16);
        debug_abbrev_size = buf->sections[buf->section].len;
        debug_abbrev_ptr = buf->sections[buf->section].buffer;
    }
    size_t debug_line_offset = bss_offset;
    size_t debug_line_size = 0;
    void *debug_line_ptr = NULL;
    if (openasm_section_exists(buf, "debug_line")) {
        openasm_section(buf, "debug_line");
        debug_line_offset = openasm_align_up(debug_abbrev_offset + debug_abbrev_size, 16);
        debug_line_size = buf->sections[buf->section].len;
        debug_line_ptr = buf->sections[buf->section].buffer;
    }

    size_t strtab_size = 1;
    for (size_t i = 0; i < buf->export.len; i++) {
        if (!buf->export.table[i].defined || buf->export.table[i].binding == OPENASM_BIND_PRIVATE) {
            continue;
        }
        strtab_size += strlen(buf->export.table[i].sym) + 1;
    }

    char *strtab = malloc(strtab_size);
    strtab[0] = 0;
    size_t strtab_idx = 1;

    uint64_t text_start = elf.phdrs[1].p_vaddr + text_offset;

    Elf64_Sym *symtab = malloc((1 + buf->export.len) * sizeof(Elf64_Sym));
    memset(symtab, 0, sizeof(Elf64_Sym));
    size_t symtab_offset = openasm_align_up(debug_line_offset + debug_line_size, 16);
    size_t symtab_size = sizeof(Elf64_Sym);

    // first the local symbols
    size_t symtab_idx = 1;
    for (size_t i = 0; i < buf->export.len; i++) {
        if (!buf->export.table[i].defined || buf->export.table[i].binding != OPENASM_BIND_LOCAL) {
            continue;
        }
        symtab[symtab_idx].st_name = strtab_idx;
        strcpy(strtab + strtab_idx, buf->export.table[i].sym);
        strtab_idx += strlen(buf->export.table[i].sym) + 1;
        symtab[symtab_idx].st_value = text_start + buf->export.table[i].addr;
        symtab[symtab_idx].st_size = buf->export.table[i].size;
        symtab[symtab_idx].st_info = ELF64_ST_INFO(STB_LOCAL, STT_FUNC); // TODO: other symbol types
        symtab[symtab_idx].st_other = 0;
        symtab[symtab_idx].st_shndx = 1; // TODO: section numbers
        ++symtab_idx;
        symtab_size += sizeof(Elf64_Sym);
    }
    
    uint32_t symtab_info = symtab_idx;

    // then weak and global
    for (size_t i = 0; i < buf->export.len; i++) {
        if (!buf->export.table[i].defined
            || buf->export.table[i].binding == OPENASM_BIND_PRIVATE
            || buf->export.table[i].binding == OPENASM_BIND_LOCAL) {
            continue;
        }
        symtab[symtab_idx].st_name = strtab_idx;
        strcpy(strtab + strtab_idx, buf->export.table[i].sym);
        strtab_idx += strlen(buf->export.table[i].sym) + 1;
        symtab[symtab_idx].st_value = text_start + buf->export.table[i].addr;
        symtab[symtab_idx].st_size = buf->export.table[i].size;
        unsigned char binding = 1;
        switch (buf->export.table[i].binding) {
        case OPENASM_BIND_GLOBAL:
            binding = STB_GLOBAL;
            break;
        case OPENASM_BIND_WEAK:
            binding = STB_WEAK;
            break;
        }
        symtab[symtab_idx].st_info = ELF64_ST_INFO(binding, STT_FUNC); // TODO: other symbol types
        symtab[symtab_idx].st_other = 0;
        symtab[symtab_idx].st_shndx = 1; // TODO: section numbers
        ++symtab_idx;
        symtab_size += sizeof(Elf64_Sym);
    }

    size_t strtab_offset = openasm_align_up(symtab_offset + symtab_size, 16);

    char *shstrtab = malloc(128);
    size_t shstrtab_size = 0;
#define def_sname(s) \
    size_t s##_name = shstrtab_size; \
    const char *s##_name_str = "." openasm_stringify(s); \
    strcpy(shstrtab + shstrtab_size, s##_name_str); \
    shstrtab_size += strlen(s##_name_str) + 1;

    size_t nul_name = 0;
    shstrtab[0] = 0;
    shstrtab_size += 1;
    
    def_sname(text);
    def_sname(rodata);
    def_sname(data);
    def_sname(bss);
    def_sname(debug_info);
    def_sname(debug_abbrev);
    def_sname(debug_line);
    def_sname(strtab);
    def_sname(symtab);
    def_sname(shstrtab);
    
    const void *shstrtab_ptr = shstrtab;
    size_t shstrtab_offset = openasm_align_up(strtab_offset + strtab_size, 16);
    
    size_t shdr_offset = openasm_align_up(shstrtab_offset + shstrtab_size, 16);
    size_t shdr_size = sizeof(struct OpenasmElf) - offsetof(struct OpenasmElf, shdrs);
    size_t size_dt_shdr = offsetof(struct OpenasmElf, shdrs);

    elf.ehdr.e_phoff = phdr_offset;
    elf.ehdr.e_shoff = shdr_offset;

    elf.shdrs[0].sh_name = nul_name;

    elf.ehdr.e_entry += text_offset;
    elf.phdrs[1].p_offset = text_offset;
    elf.phdrs[1].p_vaddr += text_offset;
    elf.phdrs[1].p_paddr += text_offset;
    elf.phdrs[1].p_filesz = text_size;
    elf.phdrs[1].p_memsz = text_size;
    elf.shdrs[1].sh_name = text_name;
    elf.shdrs[1].sh_offset = text_offset;
    elf.shdrs[1].sh_addr += text_offset;
    elf.shdrs[1].sh_size = text_size;
    
    elf.phdrs[2].p_offset = rodata_offset;
    elf.phdrs[2].p_vaddr += rodata_offset;
    elf.phdrs[2].p_paddr += rodata_offset;
    elf.phdrs[2].p_filesz = rodata_size;
    elf.phdrs[2].p_memsz = rodata_size;
    elf.shdrs[2].sh_name = rodata_name;
    elf.shdrs[2].sh_offset = rodata_offset;
    elf.shdrs[2].sh_addr += rodata_offset;
    elf.shdrs[2].sh_size = rodata_size;
    
    elf.phdrs[3].p_offset = data_offset;
    elf.phdrs[3].p_vaddr += data_offset;
    elf.phdrs[3].p_paddr += data_offset;
    elf.phdrs[3].p_filesz = data_size;
    elf.phdrs[3].p_memsz = data_size;
    elf.shdrs[3].sh_name = data_name;
    elf.shdrs[3].sh_offset = data_offset;
    elf.shdrs[3].sh_addr += data_offset;
    elf.shdrs[3].sh_size = data_size;
    
    elf.phdrs[4].p_offset = bss_offset;
    elf.phdrs[4].p_vaddr += bss_offset;
    elf.phdrs[4].p_paddr += bss_offset;
    elf.phdrs[4].p_filesz = 0;
    elf.phdrs[4].p_memsz = bss_size;
    elf.shdrs[4].sh_name = bss_name;
    elf.shdrs[4].sh_offset = bss_offset;
    elf.shdrs[4].sh_addr += bss_offset;
    elf.shdrs[4].sh_size = bss_size;

    elf.shdrs[5].sh_name = debug_info_name;
    elf.shdrs[5].sh_offset = debug_info_offset;
    elf.shdrs[5].sh_size = debug_info_size;

    elf.shdrs[6].sh_name = debug_abbrev_name;
    elf.shdrs[6].sh_offset = debug_abbrev_offset;
    elf.shdrs[6].sh_size = debug_abbrev_size;
    
    elf.shdrs[7].sh_name = debug_line_name;
    elf.shdrs[7].sh_offset = debug_line_offset;
    elf.shdrs[7].sh_size = debug_line_size;

    elf.shdrs[8].sh_name = symtab_name;
    elf.shdrs[8].sh_offset = symtab_offset;
    elf.shdrs[8].sh_addr += symtab_offset;
    elf.shdrs[8].sh_size = symtab_size;
    elf.shdrs[8].sh_info = symtab_info;

    elf.shdrs[9].sh_name = strtab_name;
    elf.shdrs[9].sh_offset = strtab_offset;
    elf.shdrs[9].sh_addr += strtab_offset;
    elf.shdrs[9].sh_size = strtab_size;
    
    elf.shdrs[10].sh_name = shstrtab_name;
    elf.shdrs[10].sh_offset = shstrtab_offset;
    elf.shdrs[10].sh_addr += shstrtab_offset;
    elf.shdrs[10].sh_size = shstrtab_size;

    uint8_t padding[16] = {0};

    size_t count = 0;
    size_t pad = 0;

    count += fwrite(&elf, 1, size_dt_shdr, fileout);

    pad = text_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(text_ptr, 1, text_size, fileout);
    
    pad = rodata_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(rodata_ptr, 1, rodata_size, fileout);
    
    pad = data_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(data_ptr, 1, data_size, fileout);

    pad = debug_info_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(debug_info_ptr, 1, debug_info_size, fileout);

    pad = debug_abbrev_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(debug_abbrev_ptr, 1, debug_abbrev_size, fileout);

    pad = debug_line_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(debug_line_ptr, 1, debug_line_size, fileout);

    pad = symtab_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(symtab, 1, symtab_size, fileout);

    pad = strtab_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(strtab, 1, strtab_size, fileout);

    pad = shstrtab_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(shstrtab_ptr, 1, shstrtab_size, fileout);
    
    pad = shdr_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(&elf.shdrs, 1, shdr_size, fileout);

    fchmod(fileno(fileout), 0755);

    return 0;
}
