#include <sys/stat.h>
#define OPENASM_ARCH_AARCH64 1
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

    size_t cap = DEFAULT_BUFFER_CAP / sizeof(uint32_t);
    buf->sections[buf->len].name = section;
    buf->sections[buf->len].cap = cap;
    buf->sections[buf->len].len = 0;
    buf->sections[buf->len].buffer = malloc(cap * sizeof(uint32_t));
    buf->section = buf->len++;
}

uint64_t openasm_addr_of(OpenasmBuffer *buf, uint32_t *inst) {
    return (uint64_t) inst - (uint64_t) buf->sections[buf->section].buffer;
}

uint64_t openasm_current_addr(OpenasmBuffer *buf) {
    return buf->sections[buf->section].len * sizeof(uint32_t);
}

bool openasm_symbol(OpenasmBuffer *buf, const char *section, const char *sym, uint64_t addr) {
    bool used = 0;
    for (size_t i = 0; i < buf->symtable.len; i++) {
        if (strcmp(buf->symtable.table[i].addr_section, section) == 0
            && strcmp(buf->symtable.table[i].sym, sym) == 0) {
            used = 1;
	    // TODO: set the shift and mask shits
            buf->symtable.table[i].addr = addr;
            buf->symtable.table[i].defined = 1;
        }
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
        uint64_t offset = buf->symtable.table[i].offset;
        uint64_t addr = buf->symtable.table[i].addr >> 2; /* has to be 4-byte aligned */
        int func = buf->symtable.table[i].func;
        uint32_t mask1 = buf->symtable.table[i].mask1;
        uint32_t shift1 = buf->symtable.table[i].shift1;
        uint32_t mask2 = buf->symtable.table[i].mask2;
        uint32_t shift2 = buf->symtable.table[i].shift2;
        if (rel) {
            addr = addr - offset;
        }
        uint32_t *ptr = buf->sections[buf->section].buffer + offset / sizeof(uint32_t);
        switch (func) {
        case OPENASM_SYM_FUNC_DEFAULT:
            *ptr |= addr;
            break;
        case OPENASM_SYM_FUNC_SHIFT_MASK:
            addr = (addr & mask1) << shift1;
            *ptr |= addr;
            break;
        case OPENASM_SYM_FUNC_SPLIT_SHIFT_MASK:
            *ptr |= (addr & mask2) << shift2;
            *ptr |= (addr & mask1) << shift1;
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
    
    fwrite(text_ptr, sizeof(uint32_t), text_size, fileout);
    fwrite(rodata_ptr, sizeof(uint32_t), rodata_size, fileout);
    fwrite(data_ptr, sizeof(uint32_t), data_size, fileout);
    fwrite(bss_ptr, sizeof(uint32_t), bss_size, fileout);

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
    Elf64_Half machine = EM_AARCH64;
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
            .e_shnum     = 6          , /* (section headers) */
            .e_shstrndx  = 5        
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
            }
        }
    };

    size_t phdr_offset = offsetof(struct OpenasmElf, phdrs);

    openasm_section(buf, "text");
    size_t text_offset = openasm_align_up(offsetof(struct OpenasmElf, shdrs), 16);
    size_t text_size = buf->sections[buf->section].len * sizeof(uint32_t);
    void *text_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "data");
    size_t data_offset = openasm_align_up(text_offset + text_size, 16);
    size_t data_size = buf->sections[buf->section].len * sizeof(uint32_t);
    void *data_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "rodata");
    size_t rodata_offset = openasm_align_up(data_offset + data_size, 16);
    size_t rodata_size = buf->sections[buf->section].len * sizeof(uint32_t);
    void *rodata_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "bss");
    size_t bss_offset = openasm_align_up(rodata_offset + rodata_size, 16);
    size_t bss_size = buf->sections[buf->section].len * sizeof(uint32_t);

    const char *shstrtab =
        "\0" // 0
        ".text\0" // 1
        ".rodata\0" // 7
        ".data\0" // 15
        ".bss\0" // 21
        ".shstrtab\0"; // 26
    size_t shstrtab_offset = openasm_align_up(bss_offset + bss_size, 16);
    size_t shstrtab_size = 36;
    const void *shstrtab_ptr = shstrtab;
    
    size_t shdr_offset = openasm_align_up(shstrtab_offset + shstrtab_size, 16);
    size_t shdr_size = sizeof(struct OpenasmElf) - offsetof(struct OpenasmElf, shdrs);
    size_t size_dt_shdr = offsetof(struct OpenasmElf, shdrs);

    elf.ehdr.e_phoff = phdr_offset;
    elf.ehdr.e_shoff = shdr_offset;

    elf.shdrs[0].sh_name = 0;

    elf.ehdr.e_entry += text_offset;
    elf.phdrs[1].p_offset = text_offset;
    elf.phdrs[1].p_vaddr += text_offset;
    elf.phdrs[1].p_paddr += text_offset;
    elf.phdrs[1].p_filesz = text_size;
    elf.phdrs[1].p_memsz = text_size;
    elf.shdrs[1].sh_name = 1;
    elf.shdrs[1].sh_offset = text_offset;
    elf.shdrs[1].sh_addr += text_offset;
    elf.shdrs[1].sh_size = text_size;
    
    elf.phdrs[2].p_offset = rodata_offset;
    elf.phdrs[2].p_vaddr += rodata_offset;
    elf.phdrs[2].p_paddr += rodata_offset;
    elf.phdrs[2].p_filesz = rodata_size;
    elf.phdrs[2].p_memsz = rodata_size;
    elf.shdrs[2].sh_name = 7;
    elf.shdrs[2].sh_offset = rodata_offset;
    elf.shdrs[2].sh_addr += rodata_offset;
    elf.shdrs[2].sh_size = rodata_size;
    
    elf.phdrs[3].p_offset = data_offset;
    elf.phdrs[3].p_vaddr += data_offset;
    elf.phdrs[3].p_paddr += data_offset;
    elf.phdrs[3].p_filesz = data_size;
    elf.phdrs[3].p_memsz = data_size;
    elf.shdrs[3].sh_name = 15;
    elf.shdrs[3].sh_offset = data_offset;
    elf.shdrs[3].sh_addr += data_offset;
    elf.shdrs[3].sh_size = data_size;
    
    elf.phdrs[4].p_offset = bss_offset;
    elf.phdrs[4].p_vaddr += bss_offset;
    elf.phdrs[4].p_paddr += bss_offset;
    elf.phdrs[4].p_filesz = 0;
    elf.phdrs[4].p_memsz = bss_size;
    elf.shdrs[4].sh_name = 21;
    elf.shdrs[4].sh_offset = bss_offset;
    elf.shdrs[4].sh_addr += bss_offset;
    elf.shdrs[4].sh_size = bss_size;
    
    elf.shdrs[5].sh_name = 26;
    elf.shdrs[5].sh_offset = shstrtab_offset;
    elf.shdrs[5].sh_addr += shstrtab_offset;
    elf.shdrs[5].sh_size = shstrtab_size;

    uint8_t padding[16];

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

    pad = shstrtab_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(shstrtab_ptr, 1, shstrtab_size, fileout);
    
    pad = shdr_offset - count;
    count += fwrite(padding, 1, pad, fileout);
    count += fwrite(&elf.shdrs, 1, shdr_size, fileout);

    fchmod(fileno(fileout), 0755);

    return 0;
}
