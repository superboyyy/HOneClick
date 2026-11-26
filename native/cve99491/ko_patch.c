/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 woshigenm <woshigenm@gmail.com>
 */

/*
 * ko_patch.c —— 在手机上为当前 boot 打 KernelSU 模块。
 *
 * 从 CVE-2026-98260 的 app/native/ko_patch.c 移植（MIT License,
 * Copyright (c) 2026 woshigenm）；本仓库按 GPL-2.0 分发，详见
 * THIRD_PARTY_NOTICES.md。
 *
 *   ko_patch <in.ko> <out.ko> <syms.txt> <slide_hex> <kernel_release>
 *
 * syms.txt 每行: <name> 0x<link_addr>；运行时地址 = link_addr + slide。
 * 所有 SHN_UNDEF 且能在 syms.txt 找到的符号 -> SHN_ABS + 绝对地址。
 * vermagic = <kernel_release> + " SMP preempt mod_unload modversions aarch64"。
 *
 * 输入在触碰任何 section/relocation 之前先按 ELF64 little-endian 校验；
 * 畸形输入只打印 ERR=...（退出 1），不会产生输出文件。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SHN_ABS 0xFFF1
#define SHN_XINDEX 0xFFFF
#define SHT_NOBITS 8
#define SHT_RELA 4

#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define ELF_EHDR_SIZE 64u
#define ELF_SHDR_SIZE 64u
#define ELF_SYM_SIZE 24u
#define ELF_RELA_SIZE 24u

#define R_ADR_PREL_PG_HI21 275
#define R_LDST64_ABS_LO12_NC 286
#define R_ADD_ABS_LO12_NC 277
#define R_AARCH64_CALL26 283
#define AARCH64_NOP 0xd503201fu

struct sec {
    uint32_t name_off, type, link, info;
    uint64_t flags, addr, off, size, align, entsize;
};

struct elf_file {
    uint8_t *data;
    size_t len;
    uint64_t shoff;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
    struct sec *secs;
    const uint8_t *shstr;
    size_t shstr_size;
};

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void wr64(uint8_t *p, uint64_t v)
{
    wr32(p, (uint32_t)v);
    wr32(p + 4, (uint32_t)(v >> 32));
}

static int range_ok64(uint64_t len, uint64_t off, uint64_t size)
{
    return off <= len && size <= len - off;
}

static void set_err(char *err, size_t errlen, const char *msg)
{
    snprintf(err, errlen, "%s", msg);
}

static uint8_t *read_all(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)n);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_len = (size_t)n;
    return buf;
}

/* NUL-terminated string inside [blob, blob+len), or NULL if out of bounds. */
static const char *safe_str(const uint8_t *blob, size_t len, uint64_t off)
{
    if (!blob || off >= (uint64_t)len)
        return NULL;
    if (!memchr(blob + (size_t)off, 0, len - (size_t)off))
        return NULL;
    return (const char *)(blob + (size_t)off);
}

static int section_name_is(const struct elf_file *ef, const struct sec *s,
                           const char *want)
{
    const char *n = safe_str(ef->shstr, ef->shstr_size, s->name_off);

    return n && strcmp(n, want) == 0;
}

/*
 * Parse and validate an ELF64 little-endian object.  All section offsets are
 * checked here so later stages never dereference out-of-range data.
 */
static int elf_parse(uint8_t *data, size_t len, struct elf_file *ef,
                     char *err, size_t errlen)
{
    uint64_t shoff;
    uint16_t shentsize, shnum, shstrndx;
    struct sec *secs;
    unsigned i;

    memset(ef, 0, sizeof *ef);
    if (len < ELF_EHDR_SIZE) {
        set_err(err, errlen, "elf_too_small");
        return -1;
    }
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        set_err(err, errlen, "elf_magic");
        return -1;
    }
    if (data[4] != ELFCLASS64) {
        set_err(err, errlen, "elf_not_64bit");
        return -1;
    }
    if (data[5] != ELFDATA2LSB) {
        set_err(err, errlen, "elf_not_little_endian");
        return -1;
    }

    shoff = rd64(data + 0x28);
    shentsize = rd16(data + 0x3a);
    shnum = rd16(data + 0x3c);
    shstrndx = rd16(data + 0x3e);

    if (shentsize != ELF_SHDR_SIZE) {
        set_err(err, errlen, "elf_shentsize");
        return -1;
    }
    if (shnum == 0) {
        set_err(err, errlen, "elf_no_sections");
        return -1;
    }
    if (shoff > (uint64_t)len ||
        (uint64_t)shnum * shentsize > (uint64_t)len - shoff) {
        set_err(err, errlen, "elf_section_table_bounds");
        return -1;
    }
    if (shstrndx >= shnum) {
        set_err(err, errlen, "elf_shstrndx");
        return -1;
    }

    secs = calloc(shnum, sizeof *secs);
    if (!secs) {
        set_err(err, errlen, "elf_oom");
        return -1;
    }
    for (i = 0; i < shnum; i++) {
        const uint8_t *p = data + shoff + (uint64_t)i * shentsize;

        secs[i].name_off = rd32(p + 0);
        secs[i].type = rd32(p + 4);
        secs[i].flags = rd64(p + 8);
        secs[i].addr = rd64(p + 16);
        secs[i].off = rd64(p + 24);
        secs[i].size = rd64(p + 32);
        secs[i].link = rd32(p + 40);
        secs[i].info = rd32(p + 44);
        secs[i].align = rd64(p + 48);
        secs[i].entsize = rd64(p + 56);
    }

    /* Every backed section must lie inside the file. */
    for (i = 0; i < shnum; i++) {
        if (secs[i].type == SHT_NOBITS)
            continue;
        if (!range_ok64((uint64_t)len, secs[i].off, secs[i].size)) {
            free(secs);
            set_err(err, errlen, "elf_section_bounds");
            return -1;
        }
    }
    if (secs[shstrndx].type == SHT_NOBITS ||
        !range_ok64((uint64_t)len, secs[shstrndx].off,
                    secs[shstrndx].size)) {
        free(secs);
        set_err(err, errlen, "elf_shstr_bounds");
        return -1;
    }

    ef->data = data;
    ef->len = len;
    ef->shoff = shoff;
    ef->shentsize = shentsize;
    ef->shnum = shnum;
    ef->shstrndx = shstrndx;
    ef->secs = secs;
    ef->shstr = data + secs[shstrndx].off;
    ef->shstr_size = (size_t)secs[shstrndx].size;
    return 0;
}

/* Locate .symtab plus the string table it links to, and validate both. */
static int find_symtab(struct elf_file *ef, int *sym_idx, int *str_idx,
                       char *err, size_t errlen)
{
    int si = -1, ti;

    for (int i = 0; i < (int)ef->shnum; i++) {
        if (section_name_is(ef, &ef->secs[i], ".symtab")) {
            si = i;
            break;
        }
    }
    if (si < 0) {
        set_err(err, errlen, "no_symtab");
        return -1;
    }
    if (ef->secs[si].type == SHT_NOBITS) {
        set_err(err, errlen, "symtab_bounds");
        return -1;
    }
    if (ef->secs[si].entsize != ELF_SYM_SIZE) {
        set_err(err, errlen, "symtab_entsize");
        return -1;
    }
    if (ef->secs[si].link >= ef->shnum) {
        set_err(err, errlen, "symtab_link");
        return -1;
    }
    ti = (int)ef->secs[si].link;
    if (ef->secs[ti].type == SHT_NOBITS ||
        !range_ok64((uint64_t)ef->len, ef->secs[ti].off,
                    ef->secs[ti].size)) {
        set_err(err, errlen, "strtab_bounds");
        return -1;
    }
    *sym_idx = si;
    *str_idx = ti;
    return 0;
}

/* 返回 0 成功 */
static int patch_symbols(uint8_t *data, size_t len, const char *syms_path,
                         uint64_t slide, int *patched_out, int *missing_out,
                         char *err, size_t errlen)
{
    struct elf_file ef;
    int sym_idx, str_idx, rc = -1;
    int patched = 0, missing = 0;
    FILE *sf = NULL;
    char line[512];
    const struct sec *symtab;
    const struct sec *strtab;
    const uint8_t *str_data;
    size_t count;

    if (elf_parse(data, len, &ef, err, errlen) != 0)
        return -1;
    if (find_symtab(&ef, &sym_idx, &str_idx, err, errlen) != 0)
        goto out;

    int modinfo_idx = -1;
    for (int i = 0; i < (int)ef.shnum; i++) {
        if (section_name_is(&ef, &ef.secs[i], ".modinfo")) {
            modinfo_idx = i;
            break;
        }
    }
    symtab = &ef.secs[sym_idx];
    strtab = &ef.secs[str_idx];
    str_data = data + strtab->off;
    count = (size_t)(symtab->size / ELF_SYM_SIZE);

    int repaired = 0;
    for (size_t i = 1; i < count; i++) {
        uint8_t *e = data + symtab->off + (uint64_t)i * ELF_SYM_SIZE;
        if (rd16(e + 6) == SHN_XINDEX) {
            wr16(e + 6, modinfo_idx >= 0 ? (uint16_t)modinfo_idx : 0);
            repaired++;
        }
    }
    printf("XINDEX_REPAIRED=%d\n", repaired);

    sf = fopen(syms_path, "r");
    if (!sf) {
        set_err(err, errlen, "syms_read");
        goto out;
    }
    while (fgets(line, sizeof line, sf)) {
        char name[256];
        unsigned long long link;

        if (sscanf(line, "%255s %llx", name, &link) != 2)
            continue;
        uint64_t addr = (uint64_t)link + slide;

        for (size_t i = 1; i < count; i++) {
            uint8_t *e = data + symtab->off + (uint64_t)i * ELF_SYM_SIZE;
            const char *sn;

            if (rd16(e + 6) != 0)
                continue;
            sn = safe_str(str_data, (size_t)strtab->size, rd32(e + 0));
            if (!sn || strcmp(sn, name) != 0)
                continue;
            wr16(e + 6, SHN_ABS);
            wr64(e + 8, addr);
            patched++;
            break;
        }
    }

    /* 统计仍未定义的符号 */
    for (size_t i = 1; i < count; i++) {
        const uint8_t *e = data + symtab->off + (uint64_t)i * ELF_SYM_SIZE;

        if (rd16(e + 6) == 0 && rd32(e + 0) != 0)
            missing++;
    }

    *patched_out = patched;
    *missing_out = missing;
    rc = 0;

out:
    if (sf)
        fclose(sf);
    free(ef.secs);
    return rc;
}

/*
 * HOneClick 的 track_throne 补丁的等价实现：
 * 在 track_throne 内把引用 ksu_cred 的 "adrp x8, ksu_cred; ldr xN,[x8]"
 * 改成 "adrp x8, init_cred; add xN,x8,#0"，并把 LDR 的 LO12 重定位类型改成
 * ADD_ABS_LO12_NC；然后追加 init_cred 未定义符号给后面的 syms.txt 解析。
 * 这样 manager 的 track_throne 用 init_cred（uid 0/满能力）读包列表，
 * 不会因为 manager 签名/ksu_cred 识别失败而显示“未安装”。
 *
 * realloc 可能搬移整个 buffer：所有指针都在每次 realloc 之后按偏移重新
 * 计算，成功后才把新指针交还给调用者。
 */
static int patch_track_throne(uint8_t **pdata, size_t *plen,
                              char *err, size_t errlen)
{
    uint8_t *data = *pdata;
    size_t len = *plen;
    struct elf_file ef;
    int sym_i = -1, str_i = -1, text_i = -1, rela_i = -1;
    int track_idx = -1, ksu_idx = -1, already = 0;
    uint64_t track_val = 0, track_size = 0;
    uint64_t track_end;
    uint64_t adrp_off = UINT64_MAX, ldr_off = UINT64_MAX;
    uint32_t adrp_type = 0;
    size_t relcount, relentsize, old_str_size, old_sym_size, new_sym_index;
    int patched = 0;

    if (elf_parse(data, len, &ef, err, errlen) != 0)
        return -1;

    for (int i = 0; i < (int)ef.shnum; i++) {
        const char *n = safe_str(ef.shstr, ef.shstr_size,
                                 ef.secs[i].name_off);

        if (!n)
            continue;
        if (!strcmp(n, ".symtab"))
            sym_i = i;
        else if (!strcmp(n, ".strtab"))
            str_i = i;
        else if (!strcmp(n, ".text"))
            text_i = i;
        else if (!strcmp(n, ".rela.text"))
            rela_i = i;
    }
    if (sym_i < 0 || str_i < 0 || text_i < 0) {
        printf("TRACK_THRONE=absent\n");
        free(ef.secs);
        return 0;
    }
    if (rela_i < 0) {
        /* 5.15/CFI modules can put the track_throne relocations in
         * .rela.text.__cfi_check_fail (sh_info points at .text). */
        for (int i = 0; i < (int)ef.shnum; i++) {
            if (ef.secs[i].type == SHT_RELA &&
                ef.secs[i].info == (uint32_t)text_i) {
                rela_i = i;
                break;
            }
        }
    }
    if (rela_i < 0) {
        printf("TRACK_THRONE=absent\n");
        free(ef.secs);
        return 0;
    }

    if (ef.secs[sym_i].type == SHT_NOBITS ||
        !range_ok64((uint64_t)len, ef.secs[sym_i].off,
                    ef.secs[sym_i].size)) {
        set_err(err, errlen, "symtab_bounds");
        free(ef.secs);
        return -1;
    }
    if (ef.secs[sym_i].entsize != ELF_SYM_SIZE) {
        set_err(err, errlen, "symtab_entsize");
        free(ef.secs);
        return -1;
    }
    if (ef.secs[sym_i].link >= ef.shnum) {
        set_err(err, errlen, "symtab_link");
        free(ef.secs);
        return -1;
    }
    /* symtab->link 才是符号名的真实字符串表。 */
    str_i = (int)ef.secs[sym_i].link;
    if (ef.secs[str_i].type == SHT_NOBITS ||
        !range_ok64((uint64_t)len, ef.secs[str_i].off,
                    ef.secs[str_i].size)) {
        set_err(err, errlen, "strtab_bounds");
        free(ef.secs);
        return -1;
    }
    if (ef.secs[text_i].type == SHT_NOBITS ||
        !range_ok64((uint64_t)len, ef.secs[text_i].off,
                    ef.secs[text_i].size)) {
        set_err(err, errlen, "text_bounds");
        free(ef.secs);
        return -1;
    }
    if (ef.secs[rela_i].type == SHT_NOBITS ||
        !range_ok64((uint64_t)len, ef.secs[rela_i].off,
                    ef.secs[rela_i].size) ||
        ef.secs[rela_i].entsize != ELF_RELA_SIZE) {
        set_err(err, errlen, "rela_text_bounds");
        free(ef.secs);
        return -1;
    }

    old_str_size = (size_t)ef.secs[str_i].size;
    old_sym_size = (size_t)ef.secs[sym_i].size;

    for (size_t i = 1; i < old_sym_size / ELF_SYM_SIZE; i++) {
        const uint8_t *e = data + ef.secs[sym_i].off +
                           (uint64_t)i * ELF_SYM_SIZE;
        const char *sn = safe_str(data + ef.secs[str_i].off,
                                  old_str_size, rd32(e + 0));

        if (!sn)
            continue;
        if (!strcmp(sn, "track_throne")) {
            track_idx = (int)i;
            track_val = rd64(e + 8);
            track_size = rd64(e + 16);
        } else if (!strcmp(sn, "ksu_cred")) {
            ksu_idx = (int)i;
        } else if (!strcmp(sn, "init_cred")) {
            already = 1;
        }
    }
    if (already) {
        free(ef.secs);
        printf("TRACK_THRONE=already\n");
        return 0;
    }
    if (track_idx < 0 || ksu_idx < 0) {
        free(ef.secs);
        printf("TRACK_THRONE=absent\n");
        return 0;
    }

    {
        uint64_t span = track_size ? track_size : 0x1000;

        if (track_val > UINT64_MAX - span) {
            set_err(err, errlen, "track_range");
            free(ef.secs);
            return -1;
        }
        track_end = track_val + span;
    }

    relentsize = (size_t)ef.secs[rela_i].entsize;
    relcount = (size_t)(ef.secs[rela_i].size / relentsize);
    for (size_t i = 0; i < relcount; i++) {
        const uint8_t *r = data + ef.secs[rela_i].off + i * relentsize;
        uint64_t off = rd64(r + 0);
        uint64_t info = rd64(r + 8);
        uint32_t sym = (uint32_t)(info >> 32);
        uint32_t type = (uint32_t)(info & 0xffffffffu);

        if (sym != (uint32_t)ksu_idx || off < track_val || off >= track_end)
            continue;
        if (type == R_ADR_PREL_PG_HI21 && adrp_off == UINT64_MAX) {
            adrp_off = off;
            adrp_type = type;
        } else if ((type == R_LDST64_ABS_LO12_NC ||
                    type == R_ADD_ABS_LO12_NC) &&
                   ldr_off == UINT64_MAX) {
            ldr_off = off;
        }
    }
    if (adrp_off == UINT64_MAX || ldr_off == UINT64_MAX) {
        free(ef.secs);
        printf("TRACK_THRONE=no_reloc\n");
        return 0;
    }

    /* ldr xN,[x8]（imm12 必须为 0，后面才等价于 add xN,x8,#0）。 */
    if (ldr_off > ef.secs[text_i].size ||
        ef.secs[text_i].size - ldr_off < 4) {
        set_err(err, errlen, "ldr_out_of_bounds");
        free(ef.secs);
        return -1;
    }
    {
        uint32_t insn = rd32(data + ef.secs[text_i].off + ldr_off);
        uint32_t adrp_insn;
        uint32_t rd, rn;

        if ((insn & 0xFFC00000u) != 0xF9400000u ||
            (insn & 0x003FFC00u) != 0) {
            free(ef.secs);
            printf("TRACK_THRONE=bad_instr:%#x\n", insn);
            return 0;
        }
        rd = insn & 0x1F;
        rn = (insn >> 5) & 0x1F;
        if (adrp_off > ef.secs[text_i].size ||
            ef.secs[text_i].size - adrp_off < 4) {
            free(ef.secs);
            printf("TRACK_THRONE=bad_adrp\n");
            return 0;
        }
        adrp_insn = rd32(data + ef.secs[text_i].off + adrp_off);
        /* The LDR base must be the register ADRP loaded, otherwise the
         * ADD rewrite would read an unrelated register. */
        if ((adrp_insn & 0x9F000000u) != 0x90000000u ||
            (adrp_insn & 0x1Fu) != rn) {
            free(ef.secs);
            printf("TRACK_THRONE=bad_adrp:%#x\n", adrp_insn);
            return 0;
        }

        /* 追加 init_cred 名字到 .strtab 的副本，并更新 section header。 */
        {
            size_t new_str_off = *plen;
            size_t add = old_str_size + 10;
            uint8_t *grown;
            uint8_t *sh;

            if (add < old_str_size || new_str_off > SIZE_MAX - add) {
                set_err(err, errlen, "oom");
                free(ef.secs);
                return -1;
            }
            grown = realloc(data, new_str_off + add);
            if (!grown) {
                set_err(err, errlen, "oom");
                free(ef.secs);
                return -1;
            }
            data = grown;
            *pdata = data;
            *plen = new_str_off + add;
            memcpy(data + new_str_off, data + ef.secs[str_i].off,
                   old_str_size);
            memcpy(data + new_str_off + old_str_size, "init_cred", 9);
            data[new_str_off + old_str_size + 9] = 0;
            sh = data + ef.shoff + (uint64_t)str_i * ef.shentsize;
            wr64(sh + 24, new_str_off);
            wr64(sh + 32, old_str_size + 10);
        }

        /* 追加 init_cred (GLOBAL/UNDEF) 到 .symtab 的副本。 */
        {
            size_t new_sym_off = *plen;
            size_t add = old_sym_size + ELF_SYM_SIZE;
            uint8_t *grown;
            uint8_t *ne;
            uint8_t *sh;

            new_sym_index = old_sym_size / ELF_SYM_SIZE;
            if (add < old_sym_size || new_sym_off > SIZE_MAX - add) {
                set_err(err, errlen, "oom");
                free(ef.secs);
                return -1;
            }
            grown = realloc(data, new_sym_off + add);
            if (!grown) {
                set_err(err, errlen, "oom");
                free(ef.secs);
                return -1;
            }
            data = grown;
            *pdata = data;
            *plen = new_sym_off + add;
            memcpy(data + new_sym_off, data + ef.secs[sym_i].off,
                   old_sym_size);
            ne = data + new_sym_off + old_sym_size;
            memset(ne, 0, ELF_SYM_SIZE);
            wr32(ne + 0, (uint32_t)old_str_size); /* init_cred name offset */
            ne[4] = 1 << 4;                       /* GLOBAL / NOTYPE */
            wr16(ne + 6, 0);                      /* SHN_UNDEF */
            sh = data + ef.shoff + (uint64_t)sym_i * ef.shentsize;
            wr64(sh + 24, new_sym_off);
            wr64(sh + 32, old_sym_size + ELF_SYM_SIZE);
        }

        /* 改两条重定位指向新 init_cred，并把 LDR 改成 ADD。 */
        {
            uint32_t add_insn = 0x91000000u | (rn << 5) | rd;

            for (size_t i = 0; i < relcount; i++) {
                uint8_t *r = data + ef.secs[rela_i].off + i * relentsize;
                uint64_t off = rd64(r + 0);
                uint64_t info;

                if (off != adrp_off && off != ldr_off)
                    continue;
                info = rd64(r + 8);
                if (off == adrp_off) {
                    info = ((uint64_t)new_sym_index << 32) | adrp_type;
                } else {
                    info = ((uint64_t)new_sym_index << 32) |
                           R_ADD_ABS_LO12_NC;
                    wr32(data + ef.secs[text_i].off + ldr_off, add_insn);
                }
                wr64(r + 8, info);
                patched++;
            }
        }
        free(ef.secs);
        if (patched != 2) {
            printf("TRACK_THRONE=partial:%d\n", patched);
            return 0;
        }
        printf("TRACK_THRONE=patched track=%#llx adrp=%#llx ldr=%#llx rd=x%u\n",
               (unsigned long long)track_val, (unsigned long long)adrp_off,
               (unsigned long long)ldr_off, rd);
        return 0;
    }
}

static int patch_noenforce(uint8_t *data, size_t len, char *err,
                           size_t errlen)
{
    struct elf_file ef;
    int sym_i = -1, str_i = -1;
    int patched = 0, bad = 0;

    if (elf_parse(data, len, &ef, err, errlen) != 0)
        return -1;
    if (find_symtab(&ef, &sym_i, &str_i, err, errlen) != 0) {
        free(ef.secs);
        printf("NOENFORCE=absent\n");
        return 0;
    }
    if (ef.secs[sym_i].size % ELF_SYM_SIZE != 0 ||
        ef.secs[sym_i].size / ELF_SYM_SIZE > UINT32_MAX) {
        free(ef.secs);
        set_err(err, errlen, "noenforce_symtab");
        return -1;
    }
    for (int si = 0; si < (int)ef.shnum; si++) {
        const struct sec *rela = &ef.secs[si];
        uint32_t target_i;
        const struct sec *target;
        size_t relcount;

        if (rela->type != SHT_RELA || rela->entsize != ELF_RELA_SIZE ||
            rela->size == 0)
            continue;
        if (rela->off > len || rela->size > len - rela->off)
            continue;
        target_i = rela->info;
        if (target_i >= ef.shnum)
            continue;
        target = &ef.secs[target_i];
        if (target->type == SHT_NOBITS || target->off > len ||
            target->size > len - target->off)
            continue;
        relcount = (size_t)(rela->size / ELF_RELA_SIZE);
        for (size_t ri = 0; ri < relcount; ri++) {
            uint8_t *r = data + rela->off + ri * ELF_RELA_SIZE;
            uint64_t off = rd64(r);
            uint64_t info = rd64(r + 8);
            uint32_t sym = (uint32_t)(info >> 32);
            uint32_t type = (uint32_t)(info & 0xffffffffu);
            const uint8_t *se;
            const char *name;
            uint32_t insn;

            if (type != R_AARCH64_CALL26 || sym == 0 ||
                sym >= ef.secs[sym_i].size / ELF_SYM_SIZE)
                continue;
            se = data + ef.secs[sym_i].off + (uint64_t)sym * ELF_SYM_SIZE;
            name = safe_str(data + ef.secs[str_i].off,
                            (size_t)ef.secs[str_i].size, rd32(se));
            if (!name || strcmp(name, "setenforce") != 0)
                continue;
            if (off > target->size || target->size - off < 4) {
                bad++;
                continue;
            }
            insn = rd32(data + target->off + off);
            if ((insn & 0xFC000000u) != 0x94000000u) {
                bad++;
                continue;
            }
            wr32(data + target->off + off, AARCH64_NOP);
            /* R_AARCH64_NONE: the loader must not apply the call again. */
            wr64(r + 8, 0);
            wr64(r + 16, 0);
            patched++;
        }
    }
    free(ef.secs);
    if (patched)
        printf("NOENFORCE=patched count=%d\n", patched);
    else
        printf("NOENFORCE=absent%s\n", bad ? " bad_reloc" : "");
    return 0;
}

static int patch_vermagic(uint8_t **pdata, size_t *plen, const char *magic,
                          char *err, size_t errlen)
{
    uint8_t *data = *pdata;
    size_t len = *plen;
    struct elf_file ef;
    int idx = -1;
    size_t old_off, old_size, magic_len, new_size, new_off, i;
    uint8_t *blob, *grown;

    if (elf_parse(data, len, &ef, err, errlen) != 0)
        return -1;
    for (int s = 0; s < (int)ef.shnum; s++) {
        if (section_name_is(&ef, &ef.secs[s], ".modinfo")) {
            idx = s;
            break;
        }
    }
    if (idx < 0) {
        set_err(err, errlen, "no_modinfo");
        free(ef.secs);
        return -1;
    }
    if (ef.secs[idx].type == SHT_NOBITS ||
        !range_ok64((uint64_t)len, ef.secs[idx].off, ef.secs[idx].size)) {
        set_err(err, errlen, "modinfo_bounds");
        free(ef.secs);
        return -1;
    }

    old_off = (size_t)ef.secs[idx].off;
    old_size = (size_t)ef.secs[idx].size;
    magic_len = strlen(magic);
    if (magic_len > SIZE_MAX - 10 || old_size > SIZE_MAX - 10 - magic_len) {
        set_err(err, errlen, "oom");
        free(ef.secs);
        return -1;
    }
    new_size = old_size + 10 + magic_len; /* "vermagic=" + magic + NUL */
    blob = malloc(new_size);
    if (!blob) {
        set_err(err, errlen, "oom");
        free(ef.secs);
        return -1;
    }
    memcpy(blob, data + old_off, old_size);
    /* 旧 vermagic= -> zermagic= */
    for (i = 0; i + 9 <= old_size; i++) {
        if (memcmp(blob + i, "vermagic=", 9) == 0)
            memcpy(blob + i, "zermagic=", 9);
    }
    memcpy(blob + old_size, "vermagic=", 9);
    memcpy(blob + old_size + 9, magic, magic_len);
    blob[old_size + 9 + magic_len] = 0;

    new_off = len;
    if (new_off > SIZE_MAX - new_size) {
        free(blob);
        set_err(err, errlen, "oom");
        free(ef.secs);
        return -1;
    }
    grown = realloc(data, new_off + new_size);
    if (!grown) {
        free(blob);
        set_err(err, errlen, "oom");
        free(ef.secs);
        return -1;
    }
    data = grown;
    *pdata = data;
    memcpy(data + new_off, blob, new_size);
    *plen = new_off + new_size;
    {
        uint8_t *hdr = data + ef.shoff + (uint64_t)idx * ef.shentsize;

        wr64(hdr + 24, new_off);
        wr64(hdr + 32, new_size);
    }
    free(blob);
    free(ef.secs);
    return 0;
}

int ko_patch_cli(int argc, char **argv)
{
    char err[64];
    char vermagic[512];
    size_t len = 0;
    uint8_t *data;
    uint64_t slide;
    int patched = 0, missing = 0;
    char *tmp;
    size_t tmp_len;
    FILE *out;
    size_t put;
    int werr = 0;

    if (argc != 6) {
        fprintf(stderr, "usage: %s <in.ko> <out.ko> <syms.txt> <slide_hex> <vermagic>\n", argv[0]);
        return 2;
    }
    data = read_all(argv[1], &len);
    if (!data) { printf("ERR=read:%d\n", errno); return 1; }
    slide = strtoull(argv[4], NULL, 0);

    /* 117 ksu-template already has the right vermagic.  Only patch the
     * undefined symbols; avoid moving/rewriting section headers. */
    if (patch_symbols(data, len, argv[3], slide, &patched, &missing,
                      err, sizeof err) != 0) {
        printf("ERR=symbols:%s\n", err);
        free(data);
        return 1;
    }

    (void)vermagic;
    /* 先写临时文件，全部成功后才 rename，失败时不发布半成品。 */
    tmp_len = strlen(argv[2]) + 32;
    tmp = malloc(tmp_len);
    if (!tmp) {
        printf("ERR=write:%d\n", ENOMEM);
        free(data);
        return 1;
    }
    snprintf(tmp, tmp_len, "%s.tmp.%ld", argv[2], (long)getpid());
    out = fopen(tmp, "wb");
    if (!out) {
        int e = errno;

        printf("ERR=write:%d\n", e);
        free(tmp);
        free(data);
        return 1;
    }
    put = fwrite(data, 1, len, out);
    if (put != len)
        werr = EIO;
    if (fclose(out) != 0 && werr == 0)
        werr = errno;
    if (werr != 0) {
        unlink(tmp);
        printf("ERR=write:%d\n", werr);
        free(tmp);
        free(data);
        return 1;
    }
    if (rename(tmp, argv[2]) != 0) {
        int e = errno;

        unlink(tmp);
        printf("ERR=write:%d\n", e);
        free(tmp);
        free(data);
        return 1;
    }
    free(tmp);
    free(data);
    printf("PATCHED=%d MISSING=%d VERMAGIC=%s\n", patched, missing, vermagic);
    return 0;
}
