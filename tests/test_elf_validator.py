"""Tests for elf_validator.validate()."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from soxtract.elf_validator import validate


# ── Helpers ───────────────────────────────────────────────────────────────

def make_elf_ident(bitness: int = 64, endian: str = "little") -> bytes:
    ei_class = 2 if bitness == 64 else 1
    ei_data = 1 if endian == "little" else 2
    ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    assert len(ident) == 16
    return ident


def make_elf64_header(
    e_type: int = 3,
    e_machine: int = 183,
    e_phoff: int = 64,
    e_phnum: int = 2,
    e_phentsize: int = 56,
    e_shoff: int = 0,
    e_shnum: int = 0,
    e_shstrndx: int = 0,
) -> bytes:
    ident = make_elf_ident(64, "little")
    rest = struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, e_machine,
        1,        # e_version
        0,        # e_entry
        e_phoff,  # e_phoff
        e_shoff,  # e_shoff
        0,        # e_flags
        64,       # e_ehsize
        e_phentsize,
        e_phnum,
        64,       # e_shentsize
        e_shnum,
        e_shstrndx,
    )
    header = ident + rest
    # Pad to at least 64 bytes
    return header + b"\x00" * max(0, 64 - len(header))


def make_elf32_header(
    e_type: int = 3,
    e_machine: int = 40,
    e_phoff: int = 52,
    e_phnum: int = 2,
    e_phentsize: int = 32,
    e_shoff: int = 0,
) -> bytes:
    ident = make_elf_ident(32, "little")
    rest = struct.pack(
        "<HHIIIIIHHHHHH",
        e_type, e_machine,
        1,        # e_version
        0,        # e_entry
        e_phoff,
        e_shoff,
        0,        # e_flags
        52,       # e_ehsize
        e_phentsize,
        e_phnum,
        40,       # e_shentsize
        0,        # e_shnum
        0,        # e_shstrndx
    )
    header = ident + rest
    return header + b"\x00" * max(0, 64 - len(header))


# ── Tests ─────────────────────────────────────────────────────────────────

def test_valid_elf64_aarch64():
    data = make_elf64_header() + b"\x00" * 200
    r = validate(data)
    assert r.is_valid
    assert r.magic_ok
    assert r.bitness == 64
    assert r.endian == "little"
    assert r.abi == "aarch64"
    assert r.e_type == 3
    assert r.errors == []


def test_valid_elf32_arm():
    data = make_elf32_header() + b"\x00" * 200
    r = validate(data)
    assert r.is_valid
    assert r.bitness == 32
    assert r.abi == "arm"
    assert r.errors == []


def test_invalid_magic():
    r = validate(b"JUNK" + b"\x00" * 60)
    assert not r.is_valid
    assert not r.magic_ok
    assert not r.is_repairable


def test_too_small():
    r = validate(b"\x7fELF" + b"\x00" * 20)
    assert not r.is_valid
    assert not r.magic_ok


def test_wrong_e_type():
    data = make_elf64_header(e_type=2) + b"\x00" * 200   # ET_EXEC
    r = validate(data)
    assert not r.is_valid
    assert r.magic_ok
    assert r.is_repairable
    assert any("e_type" in e for e in r.errors)


def test_unknown_machine():
    data = make_elf64_header(e_machine=9999) + b"\x00" * 200
    r = validate(data)
    assert not r.is_valid
    assert r.is_repairable
    assert any("e_machine" in e for e in r.errors)


def test_phoff_out_of_bounds():
    data = make_elf64_header(e_phoff=9999) + b"\x00" * 100
    r = validate(data)
    assert not r.is_valid
    assert any("e_phoff" in e for e in r.errors)


def test_zero_phnum():
    data = make_elf64_header(e_phnum=0) + b"\x00" * 200
    r = validate(data)
    assert not r.is_valid
    assert any("e_phnum" in e for e in r.errors)


def test_wrong_phentsize():
    data = make_elf64_header(e_phentsize=32) + b"\x00" * 200  # 32 is wrong for 64-bit
    r = validate(data)
    assert not r.is_valid
    assert any("e_phentsize" in e for e in r.errors)


def test_x86_64():
    data = make_elf64_header(e_machine=62) + b"\x00" * 200
    r = validate(data)
    assert r.is_valid
    assert r.abi == "x86_64"


def test_x86_32():
    data = make_elf32_header(e_machine=3) + b"\x00" * 200
    r = validate(data)
    assert r.is_valid
    assert r.abi == "x86"
