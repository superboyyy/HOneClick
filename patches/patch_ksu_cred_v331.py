#!/usr/bin/env python3
"""Patch KernelSU v3.3.1 track_throne() from ksu_cred to &init_cred."""

import io
import struct
import sys

from elftools.elf.elffile import ELFFile

OFF_ADRP = 0x5E48
OFF_LDR = 0x5E54
ADD_X8_X8_0 = 0x91000108
R_ADR_PREL_PG_HI21 = 275
R_ADD_ABS_LO12_NC = 277
R_LDST64_ABS_LO12_NC = 286


def append_blob(elf, raw, name, blob):
    index = next(
        index
        for index, section in enumerate(elf.iter_sections())
        if section.name == name
    )
    data = bytearray(raw)
    offset = len(data)
    data += blob
    header = elf["e_shoff"] + index * elf["e_shentsize"]
    struct.pack_into("<Q", data, header + 0x18, offset)
    struct.pack_into("<Q", data, header + 0x20, len(blob))
    return bytes(data)


def main(source, destination):
    raw = open(source, "rb").read()
    elf = ELFFile(open(source, "rb"))
    text = elf.get_section_by_name(".text")
    text_offset = text["sh_offset"]

    def instruction(offset):
        return struct.unpack_from("<I", raw, text_offset + offset)[0]

    if instruction(OFF_ADRP) & 0x9F000000 != 0x90000000:
        raise SystemExit(
            f"{OFF_ADRP:#x} is not ADRP ({instruction(OFF_ADRP):#010x})"
        )
    if instruction(OFF_LDR) != 0xF9400108:
        raise SystemExit(
            f"{OFF_LDR:#x} is not ldr x8,[x8] "
            f"({instruction(OFF_LDR):#010x})"
        )

    data = bytearray(raw)
    struct.pack_into("<I", data, text_offset + OFF_LDR, ADD_X8_X8_0)

    strtab = elf.get_section_by_name(".strtab")
    symtab = elf.get_section_by_name(".symtab")
    if strtab is None or symtab is None:
        raise SystemExit("missing .strtab/.symtab")

    string_blob = bytearray(strtab.data())
    name_offset = len(string_blob)
    string_blob += b"init_cred\0"

    entry_size = symtab["sh_entsize"]
    symbol_count = symtab["sh_size"] // entry_size
    symbol_blob = bytearray(symtab.data())
    symbol_blob += struct.pack(
        "<IBBHQQ", name_offset, (1 << 4) | 0, 0, 0, 0, 0
    )
    new_symbol = symbol_count

    data = bytearray(
        append_blob(elf, bytes(data), ".strtab", bytes(string_blob))
    )
    elf = ELFFile(io.BytesIO(bytes(data)))
    data = bytearray(
        append_blob(elf, bytes(data), ".symtab", bytes(symbol_blob))
    )

    elf = ELFFile(io.BytesIO(bytes(data)))
    relocations = elf.get_section_by_name(".rela.text")
    base = relocations["sh_offset"]
    count = relocations["sh_size"] // relocations["sh_entsize"]
    patched = 0
    for index in range(count):
        position = base + index * relocations["sh_entsize"]
        offset, info, addend = struct.unpack_from("<QQq", data, position)
        relocation_type = info & 0xFFFFFFFF
        if offset == OFF_ADRP:
            new_info = (new_symbol << 32) | R_ADR_PREL_PG_HI21
        elif offset == OFF_LDR:
            if relocation_type not in (
                R_LDST64_ABS_LO12_NC,
                R_ADD_ABS_LO12_NC,
            ):
                raise SystemExit(
                    f"unexpected relocation type {relocation_type} "
                    f"at {offset:#x}"
                )
            new_info = (new_symbol << 32) | R_ADD_ABS_LO12_NC
        else:
            continue
        struct.pack_into("<QQq", data, position, offset, new_info, addend)
        patched += 1

    if patched != 2:
        raise SystemExit(f"expected 2 relocations, patched {patched}")

    open(destination, "wb").write(bytes(data))
    print(
        f"patched ksu_cred -> init_cred: symbol={new_symbol}, "
        f"relocations={patched}"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} <in.ko> <out.ko>")
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
