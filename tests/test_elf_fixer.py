"""Tests for elf_fixer.fix()."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from soxtract.elf_fixer import fix
from soxtract.elf_validator import validate


# ── Helpers ───────────────────────────────────────────────────────────────

def make_elf64_with_phdrs(segments: list[dict]) -> bytes:
    """
    Build a minimal ELF64 binary with given PT_LOAD segments.
    segments: list of dicts with keys p_vaddr, p_filesz (p_offset intentionally wrong).
    """
    e_phnum = len(segments)
    e_phoff = 64
    e_phentsize = 56
    total_hdr_size = e_phoff + e_phnum * e_phentsize

    # ELF ident
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8

    # ELF header
    ehdr = struct.pack(
        "<HHIQQQIHHHHHH",
        3,          # e_type = ET_DYN
        183,        # e_machine = EM_AARCH64
        1,          # e_version
        0,          # e_entry
        e_phoff,
        0,          # e_shoff (absent)
        0,          # e_flags
        64,         # e_ehsize
        e_phentsize,
        e_phnum,
        64,         # e_shentsize
        0,          # e_shnum
        0,          # e_shstrndx
    )

    # Program headers — p_offset intentionally set to 0 (broken)
    phdrs = b""
    for seg in segments:
        phdr = struct.pack(
            "<IIQQQQQQ",
            1,                   # p_type = PT_LOAD
            7,                   # p_flags = RWX
            0,                   # p_offset (WRONG — should equal p_vaddr)
            seg["p_vaddr"],
            seg["p_vaddr"],      # p_paddr
            seg["p_filesz"],
            seg["p_filesz"],     # p_memsz
            0x1000,              # p_align
        )
        phdrs += phdr

    # Pad to total header size then add dummy segment data
    header = ident + ehdr + phdrs
    assert len(header) == total_hdr_size, f"{len(header)} != {total_hdr_size}"

    # Fill segment bodies with distinct bytes so we can verify content is untouched
    body = b""
    for i, seg in enumerate(segments):
        filler = bytes([i + 1]) * seg["p_filesz"]
        body += filler

    return header + body


def read_phdr_offset(data: bytes, phdr_index: int, is64: bool = True) -> int:
    e_phoff = 64
    phentsize = 56 if is64 else 32
    ph_base = e_phoff + phdr_index * phentsize
    if is64:
        return struct.unpack_from("<Q", data, ph_base + 8)[0]
    else:
        return struct.unpack_from("<I", data, ph_base + 4)[0]


# ── Tests ─────────────────────────────────────────────────────────────────

def test_fix_single_pt_load_zero_vaddr():
    """PT_LOAD with p_vaddr=0: p_offset must become 0 (already correct)."""
    raw = make_elf64_with_phdrs([{"p_vaddr": 0, "p_filesz": 0x1000}])
    result = fix(raw)
    assert result.success
    assert result.patched_bytes is not None
    assert read_phdr_offset(result.patched_bytes, 0) == 0


def test_fix_two_pt_load_segments():
    """Two PT_LOAD segments: p_offset must equal p_vaddr after fix."""
    segments = [
        {"p_vaddr": 0x0000, "p_filesz": 0x5000},
        {"p_vaddr": 0x6000, "p_filesz": 0x1000},
    ]
    raw = make_elf64_with_phdrs(segments)
    result = fix(raw)
    assert result.success
    assert result.patched_bytes is not None
    assert read_phdr_offset(result.patched_bytes, 0) == 0x0000
    assert read_phdr_offset(result.patched_bytes, 1) == 0x6000
    assert len(result.changes_made) >= 1  # at least the second segment was patched


def test_fix_non_zero_min_vaddr():
    """When min p_vaddr is non-zero, offsets are shifted accordingly."""
    segments = [
        {"p_vaddr": 0x1000, "p_filesz": 0x5000},
        {"p_vaddr": 0x7000, "p_filesz": 0x1000},
    ]
    raw = make_elf64_with_phdrs(segments)
    result = fix(raw)
    assert result.success
    assert result.patched_bytes is not None
    # new_p_offset = p_vaddr - min_vaddr
    assert read_phdr_offset(result.patched_bytes, 0) == 0x0000   # 0x1000 - 0x1000
    assert read_phdr_offset(result.patched_bytes, 1) == 0x6000   # 0x7000 - 0x1000


def test_segment_content_unchanged():
    """Fixing headers must not alter the segment body bytes."""
    segments = [
        {"p_vaddr": 0, "p_filesz": 0x100},
        {"p_vaddr": 0x200, "p_filesz": 0x100},
    ]
    raw = make_elf64_with_phdrs(segments)
    result = fix(raw)
    assert result.success
    assert result.patched_bytes is not None
    # Bodies follow the header; content must be identical
    header_size = 64 + 2 * 56
    assert result.patched_bytes[header_size:] == raw[header_size:]


def test_fix_zeros_absent_shnum():
    """When e_shoff=0, e_shnum and e_shstrndx should be zeroed out."""
    # Build header with garbage shnum/shstrndx but shoff=0
    segments = [{"p_vaddr": 0, "p_filesz": 0x1000}]
    raw = bytearray(make_elf64_with_phdrs(segments))
    # Manually set e_shnum=5 and e_shstrndx=3 while e_shoff remains 0
    struct.pack_into("<H", raw, 60, 5)   # e_shnum
    struct.pack_into("<H", raw, 62, 3)   # e_shstrndx
    result = fix(bytes(raw))
    assert result.success
    assert result.patched_bytes is not None
    e_shnum = struct.unpack_from("<H", result.patched_bytes, 60)[0]
    e_shstrndx = struct.unpack_from("<H", result.patched_bytes, 62)[0]
    assert e_shnum == 0
    assert e_shstrndx == 0
    assert any("zeroed" in c for c in result.changes_made)


def test_fix_not_elf():
    result = fix(b"NOTELF" + b"\x00" * 100)
    assert not result.success
    assert "not an ELF" in (result.error or "")


def test_fix_too_small():
    result = fix(b"\x7fELF\x00" * 5)
    assert not result.success


def test_fixed_output_is_valid_elf():
    """After fixing, the output should pass elf_validator.validate()."""
    segments = [
        {"p_vaddr": 0x0000, "p_filesz": 0x5000},
        {"p_vaddr": 0x6000, "p_filesz": 0x1000},
    ]
    raw = make_elf64_with_phdrs(segments)
    result = fix(raw)
    assert result.success
    vresult = validate(result.patched_bytes)  # type: ignore[arg-type]
    assert vresult.is_valid, vresult.errors
