#!/usr/bin/env python3
"""Patch an aarch64 kernel module for a runtime KernelSU/SukiSU load."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

SHT_SYMTAB = 2
SHN_UNDEF = 0
SHN_XINDEX = 0xFFFF
SHN_ABS = 0xFFF1
ELF64_HEADER_SIZE = 64
EM_AARCH64 = 183
MASK64 = (1 << 64) - 1


class PatchError(RuntimeError):
    pass


class ElfModule:
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        if len(data) < ELF64_HEADER_SIZE or data[:4] != b"\x7fELF":
            raise PatchError("input is not an ELF file")
        if data[4] != 2 or data[5] != 1:
            raise PatchError("only little-endian ELF64 is supported")
        machine = self.u16(0x12)
        if machine != EM_AARCH64:
            raise PatchError(f"expected AArch64 ELF, machine={machine}")
        self.shoff = self.u64(0x28)
        self.shentsize = self.u16(0x3A)
        self.shnum = self.u16(0x3C)
        self.shstrndx = self.u16(0x3E)
        if self.shentsize != 64 or self.shnum == 0:
            raise PatchError("unsupported or truncated section table")
        if self.shoff + self.shentsize * self.shnum > len(data):
            raise PatchError("section table is out of bounds")
        self.sections = [self._section(i) for i in range(self.shnum)]
        if self.shstrndx >= self.shnum:
            raise PatchError("invalid section-name string table")
        self.shstr = self.sections[self.shstrndx]
        for section in self.sections:
            section["name"] = self.string_at(self.shstr, section["name_off"])

    def _section(self, index: int) -> dict[str, int | str]:
        off = self.shoff + index * self.shentsize
        return {
            "index": index,
            "name_off": self.u32(off),
            "type": self.u32(off + 4),
            "offset": self.u64(off + 0x18),
            "size": self.u64(off + 0x20),
            "link": self.u32(off + 0x28),
            "entsize": self.u64(off + 0x38),
            "name": "",
        }

    def section(self, name: str) -> dict[str, int | str]:
        for section in self.sections:
            if section["name"] == name:
                return section
        raise PatchError(f"section not found: {name}")

    def string_at(self, section: dict[str, int | str], offset: int) -> str:
        start = int(section["offset"]) + offset
        end = int(section["offset"]) + int(section["size"])
        if offset < 0 or start >= end or end > len(self.data):
            return ""
        stop = self.data.find(b"\0", start, end)
        if stop < 0:
            stop = end
        return bytes(self.data[start:stop]).decode("utf-8", "replace")

    def u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def u64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.data, offset)[0]

    def put16(self, offset: int, value: int) -> None:
        struct.pack_into("<H", self.data, offset, value)

    def put64(self, offset: int, value: int) -> None:
        struct.pack_into("<Q", self.data, offset, value & MASK64)

    def patch_vermagic(self, kernel_release: str) -> None:
        modinfo = self.section(".modinfo")
        index = int(modinfo["index"])
        old_offset = int(modinfo["offset"])
        old_size = int(modinfo["size"])
        if old_offset + old_size > len(self.data):
            raise PatchError(".modinfo is out of bounds")
        old = bytes(self.data[old_offset:old_offset + old_size])
        old = old.replace(b"vermagic=", b"zermagic=")
        vermagic = (
            b"vermagic="
            + kernel_release.encode("ascii")
            + b" SMP preempt mod_unload modversions aarch64\0"
        )
        new_offset = len(self.data)
        self.data.extend(old)
        self.data.extend(vermagic)
        header = self.shoff + index * self.shentsize
        self.put64(header + 0x18, new_offset)
        self.put64(header + 0x20, len(old) + len(vermagic))

    def patch_symbols(self, symbols: dict[str, int], slide: int) -> tuple[int, int, int]:
        symtab = next((s for s in self.sections if s["type"] == SHT_SYMTAB), None)
        if symtab is None:
            raise PatchError("module has no symbol table")
        if int(symtab["link"]) >= self.shnum:
            raise PatchError("symbol string table link is invalid")
        strtab = self.sections[int(symtab["link"])]
        modinfo_index = int(self.section(".modinfo")["index"])
        sym_offset = int(symtab["offset"])
        sym_size = int(symtab["size"])
        entry_size = int(symtab["entsize"]) or 24
        if entry_size != 24 or sym_offset + sym_size > len(self.data):
            raise PatchError("unsupported symbol table")
        patched = repaired = undefined = 0
        for offset in range(sym_offset, sym_offset + sym_size, entry_size):
            name_off = self.u32(offset)
            shndx = self.u16(offset + 6)
            if shndx == SHN_XINDEX:
                self.put16(offset + 6, modinfo_index)
                repaired += 1
                continue
            if shndx != SHN_UNDEF or name_off == 0:
                continue
            name = self.string_at(strtab, name_off)
            undefined += 1
            address = symbols.get(name)
            if address is None:
                continue
            self.put16(offset + 6, SHN_ABS)
            self.put64(offset + 8, address + slide)
            patched += 1
        if patched == 0:
            raise PatchError(f"no module symbols were patched (undefined={undefined})")
        return patched, repaired, undefined

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.data)


def read_symbols(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        try:
            address = int(parts[0], 16)
        except ValueError:
            continue
        name = parts[2] if len(parts) == 3 and len(parts[1]) == 1 else line.split(None, 1)[1]
        symbols.setdefault(name, address)
    return symbols


def parse_slide(value: str) -> int:
    slide = int(value, 0)
    if slide <= 0 or slide & 0xFFF:
        raise PatchError("slide must be a positive 4 KiB-aligned value")
    return slide


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--kernel-release", required=True)
    parser.add_argument("--symbols", type=Path)
    parser.add_argument("--slide")
    args = parser.parse_args()
    if (args.symbols is None) != (args.slide is None):
        parser.error("--symbols and --slide must be supplied together")

    module = ElfModule(args.input.read_bytes())
    module.patch_vermagic(args.kernel_release)
    if args.symbols is not None:
        patched, repaired, undefined = module.patch_symbols(
            read_symbols(args.symbols), parse_slide(args.slide)
        )
        print(
            f"patched={patched} repaired={repaired} undefined={undefined} "
            f"output={args.output}",
            file=sys.stderr,
        )
    else:
        print(f"vermagic-only output={args.output}", file=sys.stderr)
    module.write(args.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PatchError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
