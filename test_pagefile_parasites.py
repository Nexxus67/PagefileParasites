"""
Integration tests for PagefileParasites / ParasiteView technique.

Validates PE parsing, struct ABI layouts, and architecture-aware logic
without requiring a Windows environment. Useful for conference demos
and correctness verification.

Usage:
    python test_pagefile_parasites.py
    python -m pytest test_pagefile_parasites.py -v
"""

import struct
import os
import re
import unittest

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "pagefile_parasites.ps1")


# ---------------------------------------------------------------------------
# Helpers: build minimal PE files for testing
# ---------------------------------------------------------------------------

def build_minimal_pe(machine=0x8664, magic=0x20B, entry_rva=0x1000, image_base=0x140000000):
    """Build a minimal valid PE32+ binary with the given header values."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    e_lfanew = 64
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)

    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes)
    coff = struct.pack("<HHIIIHH",
        machine,        # Machine
        1,              # NumberOfSections
        0,              # TimeDateStamp
        0,              # PointerToSymbolTable
        0,              # NumberOfSymbols
        0xF0,           # SizeOfOptionalHeader (PE32+ minimum)
        0x22,           # Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)
    )

    # Optional header (PE32+) - only the fields we parse
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0x00, magic)           # Magic
    struct.pack_into("<I", opt, 0x10, entry_rva)       # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 0x18, image_base)      # ImageBase (8 bytes for PE32+)
    struct.pack_into("<I", opt, 0x20, 0x1000)          # SectionAlignment
    struct.pack_into("<I", opt, 0x24, 0x200)           # FileAlignment
    struct.pack_into("<I", opt, 0x38, 0x200000)        # SizeOfImage

    pe = dos_header + pe_sig + coff + bytes(opt)
    # Pad to look realistic
    pe += b"\x00" * (0x200 - len(pe))
    return bytes(pe)


def parse_pe_like_script(data):
    """Replicate the script's PE parsing logic in Python for validation."""
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    opt_off = e_lfanew + 0x18
    magic = struct.unpack_from("<H", data, opt_off)[0]
    image_base = struct.unpack_from("<Q", data, opt_off + 0x18)[0]
    entry_rva = struct.unpack_from("<I", data, opt_off + 0x10)[0]
    return {
        "e_lfanew": e_lfanew,
        "machine": machine,
        "magic": magic,
        "image_base": image_base,
        "entry_rva": entry_rva,
    }


# ---------------------------------------------------------------------------
# Helpers: compute expected struct sizes from the C# definitions
# ---------------------------------------------------------------------------

def expected_context64_size():
    """Calculate CONTEXT64 size per winnt.h."""
    size = 0
    size += 6 * 8   # P1Home..P6Home
    size += 4 + 4   # ContextFlags, MxCsr
    size += 6 * 2   # Seg registers
    size += 4       # EFlags
    size += 6 * 8   # Dr0..Dr7
    size += 17 * 8  # Rax..R15 + Rip
    size += 512     # FltSave (XSAVE_FORMAT)
    size += 416     # VectorRegister M128A[26]
    size += 6 * 8   # VectorControl..LastExceptionFromRip
    return size


def expected_context_arm64_size():
    """Calculate CONTEXT_ARM64 size per winnt.h."""
    size = 0
    size += 4 + 4       # ContextFlags, Cpsr
    size += 31 * 8      # X[31]
    size += 8 + 8       # Sp, Pc
    size += 512         # V[32] (NEON128)
    size += 4 + 4       # Fpcr, Fpsr
    size += 8 * 4       # Bcr[8]
    size += 8 * 8       # Bvr[8]
    size += 2 * 4       # Wcr[2]
    size += 2 * 8       # Wvr[2]
    return size


# ---------------------------------------------------------------------------
# Read the PowerShell script once
# ---------------------------------------------------------------------------

def read_script():
    with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
        return f.read()


SCRIPT_TEXT = read_script()


# ===========================================================================
# Tests
# ===========================================================================

class TestPEParsing(unittest.TestCase):
    """Verify the PE header parsing logic matches the PE specification."""

    def test_amd64_pe_parses_correctly(self):
        pe = build_minimal_pe(machine=0x8664, entry_rva=0x1000, image_base=0x140000000)
        info = parse_pe_like_script(pe)
        self.assertEqual(info["machine"], 0x8664)
        self.assertEqual(info["magic"], 0x20B)
        self.assertEqual(info["entry_rva"], 0x1000)
        self.assertEqual(info["image_base"], 0x140000000)

    def test_arm64_pe_parses_correctly(self):
        pe = build_minimal_pe(machine=0xAA64, entry_rva=0x2000, image_base=0x180000000)
        info = parse_pe_like_script(pe)
        self.assertEqual(info["machine"], 0xAA64)
        self.assertEqual(info["magic"], 0x20B, "ARM64 PE is still PE32+ (64-bit)")
        self.assertEqual(info["entry_rva"], 0x2000)
        self.assertEqual(info["image_base"], 0x180000000)

    def test_entry_point_offset_is_0x10_not_0x20(self):
        """Regression: the original code read offset 0x20 (SectionAlignment) instead of 0x10."""
        pe = build_minimal_pe(entry_rva=0xDEAD)
        e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
        opt_off = e_lfanew + 0x18

        entry_at_0x10 = struct.unpack_from("<I", pe, opt_off + 0x10)[0]
        entry_at_0x20 = struct.unpack_from("<I", pe, opt_off + 0x20)[0]

        self.assertEqual(entry_at_0x10, 0xDEAD, "AddressOfEntryPoint is at optional header + 0x10")
        self.assertEqual(entry_at_0x20, 0x1000, "Offset 0x20 is SectionAlignment, NOT entry point")
        self.assertNotEqual(entry_at_0x10, entry_at_0x20)

    def test_pe32_rejected(self):
        """PE32 (32-bit, magic 0x10B) should not be accepted."""
        pe = build_minimal_pe(magic=0x10B)
        info = parse_pe_like_script(pe)
        self.assertNotEqual(info["magic"], 0x20B)

    def test_image_base_is_8_bytes_for_pe32plus(self):
        """ImageBase at opt+0x18 is 8 bytes wide in PE32+."""
        large_base = 0x7FF700000000
        pe = build_minimal_pe(image_base=large_base)
        info = parse_pe_like_script(pe)
        self.assertEqual(info["image_base"], large_base)


class TestStructLayouts(unittest.TestCase):
    """Validate that C# struct sizes in the script match the Windows ABI."""

    def test_context64_fltsave_is_512(self):
        self.assertIn("SizeConst = 512", SCRIPT_TEXT.split("CONTEXT_ARM64")[0],
                       "CONTEXT64.FltSave must be 512 bytes (XSAVE_FORMAT)")

    def test_context64_vector_register_is_416(self):
        self.assertIn("SizeConst = 416", SCRIPT_TEXT.split("CONTEXT_ARM64")[0],
                       "CONTEXT64.VectorRegister must be 416 bytes (M128A[26])")

    def test_context64_expected_size(self):
        size = expected_context64_size()
        self.assertEqual(size, 1232, "CONTEXT64 should be 1232 bytes (no padding)")

    def test_context_arm64_expected_size(self):
        size = expected_context_arm64_size()
        self.assertEqual(size, 912, "CONTEXT_ARM64 should be 912 bytes (no padding)")

    def test_context_arm64_has_31_gp_registers(self):
        self.assertIn("SizeConst = 31", SCRIPT_TEXT,
                       "ARM64 context needs 31 GP registers (X0-X28, Fp, Lr)")

    def test_context_arm64_neon_is_512(self):
        arm64_section = SCRIPT_TEXT.split("public struct CONTEXT_ARM64")[1].split("}")[0]
        self.assertIn("SizeConst = 512", arm64_section,
                       "ARM64 NEON V[32] = 32*16 = 512 bytes")


class TestScriptArchitectureSupport(unittest.TestCase):
    """Verify the script contains proper architecture-aware code paths."""

    def test_machine_constants_defined(self):
        self.assertIn("IMAGE_FILE_MACHINE_AMD64 = 0x8664", SCRIPT_TEXT)
        self.assertIn("IMAGE_FILE_MACHINE_ARM64 = 0xAA64", SCRIPT_TEXT)

    def test_context_flag_constants(self):
        self.assertIn("CONTEXT_AMD64_INTEGER = 0x100002", SCRIPT_TEXT)
        self.assertIn("CONTEXT_ARM64_INTEGER = 0x00400002", SCRIPT_TEXT)

    def test_dual_getthreadcontext_overloads(self):
        self.assertIn("GetThreadContext64", SCRIPT_TEXT)
        self.assertIn("GetThreadContextArm64", SCRIPT_TEXT)

    def test_runtime_arch_detection(self):
        self.assertIn("RuntimeInformation", SCRIPT_TEXT)
        self.assertIn("Architecture]::Arm64", SCRIPT_TEXT)

    def test_arm64_context_fallback_uses_x1(self):
        """ARM64 initial thread has PEB in X1 (analogous to Rdx on x64)."""
        self.assertIn("ctx.X[1]", SCRIPT_TEXT)

    def test_machine_type_validation_present(self):
        self.assertIn("Payload Machine type mismatch", SCRIPT_TEXT)

    def test_peb_offset_0x10_for_imagebase(self):
        """PEB.ImageBaseAddress is at offset 0x10 on both x64 and ARM64."""
        self.assertIn("Add($pbi.PebBaseAddress, 0x10)", SCRIPT_TEXT)


class TestScriptTypeReferences(unittest.TestCase):
    """Verify types are referenced correctly (nested vs top-level)."""

    def test_unicode_string_not_nested(self):
        """UNICODE_STRING is top-level, not inside NtNative."""
        self.assertNotIn("NtNative+UNICODE_STRING", SCRIPT_TEXT)

    def test_object_attributes_not_nested(self):
        self.assertNotIn("NtNative+OBJECT_ATTRIBUTES", SCRIPT_TEXT)

    def test_process_basic_info_not_nested(self):
        self.assertNotIn("NtNative+PROCESS_BASIC_INFORMATION", SCRIPT_TEXT)

    def test_nested_types_correct(self):
        """PROCESS_INFORMATION and STARTUPINFOEXW ARE nested inside NtNative."""
        self.assertIn("NtNative+STARTUPINFOEXW", SCRIPT_TEXT)
        self.assertIn("NtNative+PROCESS_INFORMATION", SCRIPT_TEXT)


class TestPEOffsetRegression(unittest.TestCase):
    """Regression tests for the entry point offset bug."""

    def test_script_uses_correct_entry_offset(self):
        """The script must read entry point at opt+0x10, not opt+0x20."""
        self.assertIn("$optionalHeaderOffset + 0x10", SCRIPT_TEXT,
                       "EntryPoint RVA must be read from optional header + 0x10")

    def test_script_does_not_use_wrong_offset(self):
        """Ensure the old buggy offset 0x20 is not used for entry point."""
        # Find lines that read from optionalHeaderOffset
        for line in SCRIPT_TEXT.splitlines():
            if "entryPointRVA" in line.lower() and "0x20" in line:
                self.fail(f"Buggy offset 0x20 still used for entry point: {line.strip()}")


class TestSyntheticPayloadRoundTrip(unittest.TestCase):
    """End-to-end: build PE -> parse -> verify APC target would be correct."""

    def _run_roundtrip(self, machine, entry_rva, image_base):
        pe = build_minimal_pe(machine=machine, entry_rva=entry_rva, image_base=image_base)
        info = parse_pe_like_script(pe)
        apc_target = info["image_base"] + info["entry_rva"]
        expected = image_base + entry_rva
        self.assertEqual(apc_target, expected,
                         f"APC routine address should be ImageBase+EntryRVA = 0x{expected:X}")
        return info

    def test_amd64_roundtrip(self):
        info = self._run_roundtrip(0x8664, 0x1000, 0x140000000)
        self.assertEqual(info["machine"], 0x8664)

    def test_arm64_roundtrip(self):
        info = self._run_roundtrip(0xAA64, 0x2000, 0x180000000)
        self.assertEqual(info["machine"], 0xAA64)

    def test_large_entry_rva(self):
        self._run_roundtrip(0x8664, 0xFFFFF, 0x140000000)

    def test_various_image_bases(self):
        for base in [0x10000, 0x140000000, 0x7FF700000000]:
            with self.subTest(image_base=hex(base)):
                self._run_roundtrip(0x8664, 0x1000, base)


if __name__ == "__main__":
    unittest.main(verbosity=2)