#!/usr/bin/env python3
"""Patch a KernelSU module's vermagic for the Honor WKL-AN20 kernel."""

import struct
import sys

from elftools.elf.elffile import ELFFile

VERMAGIC = (
    b"6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k "
    b"SMP preempt mod_unload modversions aarch64"
)


def patch(source: str, destination: str) -> int:
    raw = open(source, "rb").read()
    elf = ELFFile(open(source, "rb"))
    section = elf.get_section_by_name(".modinfo")
    if section is None:
        raise SystemExit("no .modinfo section")

    offset = section["sh_offset"]
    size = section["sh_size"]
    index = next(
        index
        for index, candidate in enumerate(elf.iter_sections())
        if candidate.name == ".modinfo"
    )
    blob = raw[offset : offset + size]
    blob = blob.replace(b"vermagic=", b"zermagic=")
    new_blob = blob + b"vermagic=" + VERMAGIC + b"\0"

    data = bytearray(raw)
    new_offset = len(data)
    data += new_blob
    section_header = elf["e_shoff"] + index * elf["e_shentsize"]
    struct.pack_into("<Q", data, section_header + 0x18, new_offset)
    struct.pack_into("<Q", data, section_header + 0x20, len(new_blob))
    open(destination, "wb").write(data)
    print(
        f"patched vermagic: {VERMAGIC.decode()} "
        f"(.modinfo @ {new_offset:#x})"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} <in.ko> <out.ko>")
    raise SystemExit(patch(sys.argv[1], sys.argv[2]))
