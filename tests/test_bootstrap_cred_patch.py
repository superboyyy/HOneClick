import hashlib
import importlib.util
import io
import os
from pathlib import Path
import struct
import subprocess
import unittest

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "87dfc2e6dc9c82b4fbeb79090c91f0c66c4596c9"
spec = importlib.util.spec_from_file_location("bootstrap_patch", ROOT / "patches/patch_ksu_bootstrap_creds_v331.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BootstrapCredentialPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = os.environ.get("KSU_ORIGINAL_MODULE")
        cls.original = Path(fixture).read_bytes() if fixture else subprocess.check_output(
            ["git", "-C", str(ROOT), "show", UPSTREAM + ":assets/ksu-template.ko"]
        )
        cls.fixed = module.patch(cls.original)

    def test_reproducible_output_matches_bundled_module(self):
        self.assertEqual(self.fixed, module.patch(self.original))
        self.assertEqual(self.fixed, (ROOT / "assets/ksu-template.ko").read_bytes())
        self.assertEqual(hashlib.sha256(self.fixed).hexdigest(), "86ed32a0946490736850d0c5d7a703c6e5bfde541e82864ed892b31e2b590563")

    def test_other_sections_and_runtime_code_are_unchanged(self):
        before = ELFFile(io.BytesIO(self.original))
        after = ELFFile(io.BytesIO(self.fixed))
        self.assertEqual(before.num_sections(), after.num_sections())
        for section in before.iter_sections():
            if section.name in {".init.text", ".strtab", ".symtab", ".rela.init.text"}:
                continue
            self.assertEqual(section.data(), after.get_section_by_name(section.name).data(), section.name)
        old_init = before.get_section_by_name(".init.text").data()
        new_init = after.get_section_by_name(".init.text").data()
        changed_words = {i for i in range(0, len(old_init), 4) if old_init[i:i+4] != new_init[i:i+4]}
        self.assertEqual(changed_words, {0x44, 0x50})
        self.assertEqual(struct.unpack_from("<I", new_init, 0x44)[0], module.NOP)
        self.assertEqual(struct.unpack_from("<I", new_init, 0x50)[0], module.NOP)

    def test_bootstrap_argument_and_callee_are_relocated_correctly(self):
        elf = ELFFile(io.BytesIO(self.fixed))
        symbols = elf.get_section_by_name(".symtab")
        rows = {
            r["r_offset"]: (r["r_info_type"], symbols.get_symbol(r["r_info_sym"]).name, r["r_addend"])
            for r in elf.get_section_by_name(".rela.init.text").iter_relocations()
        }
        self.assertEqual(rows[0x48], (module.ADRP, "init_task", 0))
        self.assertEqual(rows[0x4C], (module.ADD_LO12, "init_task", 0))
        self.assertNotIn(0x50, rows)
        self.assertEqual(rows[0x54], (module.CALL26, "prepare_kernel_cred", 0))
        symbol_names = {s.name for s in symbols.iter_symbols()}
        self.assertIn("prepare_creds", symbol_names)
        firmware_names = {line.split()[-1] for line in (ROOT / "assets/syms.txt").read_text().splitlines() if line.split()}
        self.assertTrue({"prepare_kernel_cred", "init_task"} <= firmware_names)

    def test_unknown_and_already_patched_modules_are_rejected(self):
        damaged = bytearray(self.original)
        damaged[-1] ^= 1
        for raw in (bytes(damaged), self.original[:-1], self.fixed):
            with self.subTest(size=len(raw)):
                with self.assertRaisesRegex(ValueError, "unsupported module SHA-256"):
                    module.patch(raw)


if __name__ == "__main__":
    unittest.main()
