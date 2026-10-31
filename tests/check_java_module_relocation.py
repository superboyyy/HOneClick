"""Run the application's actual patchModule method on the fixed ELF, offline."""

import argparse
import io
import os
from pathlib import Path
import subprocess

from elftools.elf.elffile import ELFFile

parser = argparse.ArgumentParser()
parser.add_argument("--java-home", type=Path, required=True)
args = parser.parse_args()
executable_suffix = ".exe" if os.name == "nt" else ""
root = Path(__file__).resolve().parents[1]
build = root / "build/credential-relocation-check"
build.mkdir(parents=True, exist_ok=True)
source = (root / "src/main/java/com/aiden/honoroneclick/MainActivity.java").read_text(encoding="utf-8")
start = source.index("    private static byte[] patchModule(")
end = source.index("    private String shell(", start)
method = source[start:end]
harness = """import java.nio.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
public final class ModulePatchHarness {
    public static void main(String[] args) throws Exception {
        Map<String, Long> symbols = new HashMap<>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] fields = line.trim().split("\\\\s+");
            if (fields.length >= 2)
                symbols.put(fields[fields.length - 1], Long.parseUnsignedLong(fields[0], 16));
        }
        byte[] result = patchModule(Files.readAllBytes(Path.of(args[0])), symbols, 0x20000000L);
        Files.write(Path.of(args[2]), result);
    }
    // The Android mapper only uses Log for diagnostics. Keep its actual
    // method body below; the standalone harness needs no Android runtime.
    private static final class Log {
        static int i(String tag, String message) { return 0; }
    }
""" + method + "}\n"
java_source = build / "ModulePatchHarness.java"
java_source.write_text(harness, encoding="utf-8")
subprocess.run([str(args.java_home / "bin" / ("javac" + executable_suffix)), "-encoding", "UTF-8", str(java_source)], check=True)
output = build / "relocated.ko"
subprocess.run([str(args.java_home / "bin" / ("java" + executable_suffix)), "-cp", str(build), "ModulePatchHarness", str(root / "assets/ksu-template.ko"), str(root / "assets/syms.txt"), str(output)], check=True)
symbols = {}
for line in (root / "assets/syms.txt").read_text().splitlines():
    fields = line.split()
    if len(fields) >= 2:
        symbols[fields[-1]] = int(fields[0], 16)
elf = ELFFile(io.BytesIO(output.read_bytes()))
table = elf.get_section_by_name(".symtab")
for name in ("init_task", "prepare_kernel_cred"):
    entry = table.get_symbol_by_name(name)[0]
    assert entry["st_shndx"] == "SHN_ABS", name
    assert entry["st_value"] == symbols[name] + 0x20000000, name
print("Application patchModule resolved init_task and prepare_kernel_cred correctly")
