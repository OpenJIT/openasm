#include <sys/stat.h>
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

bool openasm_symbol(OpenasmBuffer *buf, const char *section, const char *sym, uint64_t addr) {
    bool used = 0;
    for (size_t i = 0; i < buf->symtable.len; i++) {
        if (strcmp(buf->symtable.table[i].addr_section, section) == 0
            && strcmp(buf->symtable.table[i].sym, sym) == 0) {
            used = 1;
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
        uint64_t offset = buf->symtable.table[i].offset;
        uint64_t addr = buf->symtable.table[i].addr;
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

// this function was written with the help of `dumpelf` from `pax-utils`
int openasm_elfdump(FILE *fileout, int flags, OpenasmBuffer *buf) {
    unsigned char class = ELFCLASS64;
    unsigned char data = ELFDATA2LSB;
    unsigned char version = EV_CURRENT;
    unsigned char osabi = ELFOSABI_SYSV;
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
            .e_entry     = 0x4000     , /* (start address at runtime) */
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
            // (nul)
            {
                .p_type   = PT_LOAD    ,
                .p_offset = 0          , /* (bytes into file) */
                .p_vaddr  = 0x0        , /* (virtual addr at runtime) */
                .p_paddr  = 0x0        , /* (physical addr at runtime) */
                .p_filesz = 0          , /* (bytes in file) */
                .p_memsz  = 0          , /* (bytes in mem at runtime) */
                .p_flags  = PF_R       ,
                .p_align  = 4096       , /* (min mem alignment in bytes) */
            },
            // .text
            {
                .p_type   = PT_LOAD    ,
                .p_offset = 0          , /* (bytes into file) */
                .p_vaddr  = 0x4000     , /* (virtual addr at runtime) */
                .p_paddr  = 0x4000     , /* (physical addr at runtime) */
                .p_filesz = 0          , /* (bytes in file) */
                .p_memsz  = 0          , /* (bytes in mem at runtime) */
                .p_flags  = PF_R | PF_X,
                .p_align  = 4096       , /* (min mem alignment in bytes) */
            },
            // .rodata
            {
                .p_type   = PT_LOAD    ,
                .p_offset = 0          , /* (bytes into file) */
                .p_vaddr  = 0xB000     , /* (virtual addr at runtime) */
                .p_paddr  = 0xB000     , /* (physical addr at runtime) */
                .p_filesz = 0          , /* (bytes in file) */
                .p_memsz  = 0          , /* (bytes in mem at runtime) */
                .p_flags  = PF_R       ,
                .p_align  = 4096       , /* (min mem alignment in bytes) */
            },
            // .bss
            {
                .p_type   = PT_DYNAMIC ,
                .p_offset = 0          , /* (bytes into file) */
                .p_vaddr  = 0xDDE8     , /* (virtual addr at runtime) */
                .p_paddr  = 0xDDE8     , /* (physical addr at runtime) */
                .p_filesz = 0          , /* (bytes in file) */
                .p_memsz  = 0          , /* (bytes in mem at runtime) */
                .p_flags  = PF_R | PF_W,
                .p_align  = 8          , /* (min mem alignment in bytes) */
            },
            // .stack
            {
                .p_type   = PT_GNU_STACK,
                .p_offset = 0           , /* (bytes into file) */
                .p_vaddr  = 0x0         , /* (virtual addr at runtime) */
                .p_paddr  = 0x0         , /* (physical addr at runtime) */
                .p_filesz = 0           , /* (bytes in file) */
                .p_memsz  = 0           , /* (bytes in mem at runtime) */
                .p_flags  = PF_R | PF_W ,
                .p_align  = 16          , /* (min mem alignment in bytes) */
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
                .sh_name      = 1           ,
                .sh_type      = SHT_PROGBITS,
                .sh_flags     = 6           ,
                .sh_addr      = 0x4520      ,
                .sh_offset    = 0           , /* (bytes) */
                .sh_size      = 0           , /* (bytes) */
                .sh_link      = 0           ,
                .sh_info      = 0           ,
                .sh_addralign = 16          ,
                .sh_entsize   = 0         
            },
            // .rodata
            {
                .sh_name      = 2           ,
                .sh_type      = SHT_PROGBITS,
                .sh_flags     = 2           ,
                .sh_addr      = 0xB000      ,
                .sh_offset    = 0           , /* (bytes) */
                .sh_size      = 0           , /* (bytes) */
                .sh_link      = 0           ,
                .sh_info      = 0           ,
                .sh_addralign = 8           ,
                .sh_entsize   = 0         
            },
            // .data
            {
                .sh_name      = 3           ,
                .sh_type      = SHT_PROGBITS,
                .sh_flags     = 3           ,
                .sh_addr      = 0xE160      ,
                .sh_offset    = 0           , /* (bytes) */
                .sh_size      = 0           , /* (bytes) */
                .sh_link      = 0           ,
                .sh_info      = 0           ,
                .sh_addralign = 32          ,
                .sh_entsize   = 0         
            },
            // .bss
            {
                .sh_name      = 4          ,
                .sh_type      = SHT_NOBITS ,
                .sh_flags     = 3          ,
                .sh_addr      = 0xF7A0     ,
                .sh_offset    = 0          , /* (bytes) */
                .sh_size      = 128        , /* (bytes) */
                .sh_link      = 0          ,
                .sh_info      = 0          ,
                .sh_addralign = 32         ,
                .sh_entsize   = 0         
            },
            // .shstrtab
            {
                .sh_name      = 5          ,
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
    size_t shdr_offset = offsetof(struct OpenasmElf, shdrs);
    
    size_t nul_offset = sizeof(struct OpenasmElf);
    size_t nul_size = 0;
    void *nul_ptr = NULL;
    openasm_section(buf, "text");
    size_t text_offset = nul_offset + nul_size;
    size_t text_size = buf->sections[buf->section].len;
    void *text_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "data");
    size_t data_offset = text_offset + text_size;
    size_t data_size = buf->sections[buf->section].len;
    void *data_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "rodata");
    size_t rodata_offset = data_offset + data_size;
    size_t rodata_size = buf->sections[buf->section].len;
    void *rodata_ptr = buf->sections[buf->section].buffer;
    openasm_section(buf, "bss");
    size_t bss_offset = rodata_offset + rodata_size;
    size_t bss_size = buf->sections[buf->section].len;
    void *bss_ptr = buf->sections[buf->section].buffer;
    
    const char *shstrtab =
        "\0" // 0
        ".text\0" // 1
        ".rodata\0" // 7
        ".data\0" // 15
        ".bss\0" // 21
        ".shstrtab\0"; // 26
    size_t shstrtab_offset = bss_offset + bss_size;
    size_t shstrtab_size = 36;
    const void *shstrtab_ptr = shstrtab;

    elf.ehdr.e_phoff = phdr_offset;
    elf.ehdr.e_shoff = shdr_offset;

    elf.shdrs[0].sh_name = 0;
    
    elf.phdrs[1].p_offset = text_offset;
    elf.phdrs[1].p_filesz = text_size;
    elf.phdrs[1].p_memsz = text_size;
    elf.shdrs[1].sh_name = 1;
    elf.shdrs[1].sh_offset = text_offset;
    elf.shdrs[1].sh_size = text_size;
    
    elf.phdrs[2].p_offset = rodata_offset;
    elf.phdrs[2].p_filesz = rodata_size;
    elf.phdrs[2].p_memsz = rodata_size;
    elf.shdrs[2].sh_name = 7;
    elf.shdrs[2].sh_offset = rodata_offset;
    elf.shdrs[2].sh_size = rodata_size;
    
    elf.phdrs[3].p_offset = data_offset;
    elf.phdrs[3].p_filesz = data_size;
    elf.phdrs[3].p_memsz = data_size;
    elf.shdrs[3].sh_name = 15;
    elf.shdrs[3].sh_offset = data_offset;
    elf.shdrs[3].sh_size = data_size;
    
    elf.phdrs[4].p_offset = bss_offset;
    elf.phdrs[4].p_filesz = bss_size;
    elf.phdrs[4].p_memsz = bss_size;
    elf.shdrs[4].sh_name = 21;
    elf.shdrs[4].sh_offset = bss_offset;
    elf.shdrs[4].sh_size = bss_size;
    
    elf.shdrs[5].sh_name = 26;
    elf.shdrs[5].sh_offset = shstrtab_offset;
    elf.shdrs[5].sh_size = shstrtab_size;

    fwrite(&elf, 1, sizeof(struct OpenasmElf), fileout);
    fwrite(nul_ptr, 1, nul_size, fileout);
    fwrite(text_ptr, 1, text_size, fileout);
    fwrite(rodata_ptr, 1, rodata_size, fileout);
    fwrite(data_ptr, 1, data_size, fileout);
    fwrite(bss_ptr, 1, bss_size, fileout);
    fwrite(shstrtab_ptr, 1, shstrtab_size, fileout);

    /* fchmod(fileno(fileout), 0755); */

    return 0;
}
