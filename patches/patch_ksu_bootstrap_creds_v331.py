#!/usr/bin/env python3
"""Fix HOneClick's exact v3.3.1 template: cache prepare_kernel_cred(&init_task).

The corresponding module source is not distributed by HOneClick. This guarded
ELF patch replaces the optional allow_shell printk immediately before the
initial credential allocation with the argument setup for prepare_kernel_cred.
It does not change exploit helpers, root profiles, or su authorization.
Requires pyelftools. Unknown inputs are rejected before any output is written.
"""

import argparse
import hashlib
import io
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile

INPUT_SHA256 = "e33b7c5dbbef2206571c99b13eadf1bc99a11d3182f6e5f3e2540c6ca9568003"
NOP = 0xD503201F
ADRP = 275
ADD_LO12 = 277
CALL26 = 283
EXPECTED_WORDS = {
    0x44: 0x54000081,  # b.ne 0x54: optional allow_shell log
    0x48: 0x90000000,  # adrp x0, log string
    0x4C: 0x91000000,  # add x0, x0, :lo12:log string
    0x50: 0x94000000,  # bl _printk
    0x54: 0x94000000,  # bl prepare_creds
}


def elf_view(raw):
    return ELFFile(io.BytesIO(raw))


def replace_section(raw, name, blob):
    elf = elf_view(raw)
    index, section = next((i, s) for i, s in enumerate(elf.iter_sections()) if s.name == name)
    alignment = max(1, int(section["sh_addralign"]))
    result = bytearray(raw)
    result.extend(b"\0" * (-len(result) % alignment))
    offset = len(result)
    result.extend(blob)
    header = elf["e_shoff"] + index * elf["e_shentsize"]
    struct.pack_into("<QQ", result, header + 0x18, offset, len(blob))
    return bytes(result)


def patch(raw):
    actual = hashlib.sha256(raw).hexdigest()
    if actual != INPUT_SHA256:
        raise ValueError(f"unsupported module SHA-256: {actual}; expected {INPUT_SHA256}")
    elf = elf_view(raw)
    if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_AARCH64" or elf["e_type"] != "ET_REL":
        raise ValueError("expected little-endian ELF64 AArch64 relocatable module")
    init = elf.get_section_by_name(".init.text")
    symtab = elf.get_section_by_name(".symtab")
    strings = elf.get_section_by_name(".strtab")
    relocations = elf.get_section_by_name(".rela.init.text")
    if any(s is None for s in (init, symtab, strings, relocations)):
        raise ValueError("required ELF sections are absent")
    for offset, expected in EXPECTED_WORDS.items():
        actual_word = struct.unpack_from("<I", raw, init["sh_offset"] + offset)[0]
        if actual_word != expected:
            raise ValueError(f"unexpected instruction at .init.text+{offset:#x}")

    symbols = list(symtab.iter_symbols())
    init_task = next(i for i, s in enumerate(symbols) if s.name == "init_task")
    if any(s.name == "prepare_kernel_cred" for s in symbols):
        raise ValueError("unexpected pre-existing prepare_kernel_cred symbol")
    expected_relocs = {
        0x48: (ADRP, ".rodata", 0x50BF),
        0x4C: (ADD_LO12, ".rodata", 0x50BF),
        0x50: (CALL26, "_printk", 0),
        0x54: (CALL26, "prepare_creds", 0),
    }
    found = {}
    relocation_rows = []
    for relocation in relocations.iter_relocations():
        offset = relocation["r_offset"]
        info = relocation["r_info"]
        addend = relocation["r_addend"]
        symbol = symbols[relocation["r_info_sym"]]
        symbol_name = symbol.name
        if not symbol_name and isinstance(symbol["st_shndx"], int):
            symbol_name = elf.get_section(symbol["st_shndx"]).name
        if offset in expected_relocs:
            observed = (relocation["r_info_type"], symbol_name, addend)
            if observed != expected_relocs[offset] or offset in found:
                raise ValueError(f"unexpected relocation at .init.text+{offset:#x}: {observed}")
            found[offset] = observed
        relocation_rows.append((offset, info, addend))
    if set(found) != set(expected_relocs):
        raise ValueError("missing bootstrap relocations")

    result = bytearray(raw)
    for offset in (0x44, 0x50):
        struct.pack_into("<I", result, init["sh_offset"] + offset, NOP)
    # The ADRP/ADD instructions already target x0. Retarget their relocations
    # to &init_task; only the bootstrap allocation call gets the new callee.
    string_blob = strings.data() + b"prepare_kernel_cred\0"
    symbol_blob = symtab.data() + struct.pack("<IBBHQQ", len(strings.data()), 0x12, 0, 0, 0, 0)
    new_symbol = len(symbols)
    new_relocations = bytearray()
    for offset, info, addend in relocation_rows:
        if offset == 0x48:
            info, addend = (init_task << 32) | ADRP, 0
        elif offset == 0x4C:
            info, addend = (init_task << 32) | ADD_LO12, 0
        elif offset == 0x50:
            continue  # The old printk call is now NOP, with no relocation.
        elif offset == 0x54:
            info, addend = (new_symbol << 32) | CALL26, 0
        new_relocations.extend(struct.pack("<QQq", offset, info, addend))
    result = replace_section(bytes(result), ".strtab", string_blob)
    result = replace_section(result, ".symtab", symbol_blob)
    result = replace_section(result, ".rela.init.text", bytes(new_relocations))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error("use a separate output path so the original input is retained")
    if args.destination.exists():
        parser.error("destination already exists")
    result = patch(args.source.read_bytes())
    args.destination.write_bytes(result)
    print("patched bootstrap ksu_cred allocation to prepare_kernel_cred(&init_task)")
    print("sha256=" + hashlib.sha256(result).hexdigest())


if __name__ == "__main__":
    main()
