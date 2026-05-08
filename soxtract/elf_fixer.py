"""
Repairs program-header file offsets in a memory-dumped ELF .so.

When Frida reads memory starting at mod.base, the dump at byte offset D
corresponds to virtual address (mod.base + D).  For a PIC .so the link-time
virtual addresses start at the minimum p_vaddr of the PT_LOAD segments
(almost always 0 for Android libs).  So for every segment:

    correct p_offset in dump = p_vaddr - min_pt_load_vaddr

Section headers are stripped by the Android linker and should be zeroed out.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field

ELF_MAGIC = b"\x7fELF"
PT_LOAD = 1
PT_NULL = 0


@dataclass
class ElfFixResult:
    success: bool
    patched_bytes: bytes | None
    changes_made: list[str] = field(default_factory=list)
    error: str | None = None


def fix(raw: bytes) -> ElfFixResult:
    """
    Return a copy of *raw* with corrected program-header p_offset values.
    The segment content is never modified — only the metadata fields.
    """
    if len(raw) < 64:
        return ElfFixResult(
            success=False, patched_bytes=None,
            error=f"file too small: {len(raw)} bytes"
        )
    if raw[:4] != ELF_MAGIC:
        return ElfFixResult(
            success=False, patched_bytes=None,
            error=f"not an ELF file (magic={raw[:4].hex()})"
        )

    ei_class = raw[4]
    ei_data = raw[5]
    if ei_class not in (1, 2):
        return ElfFixResult(
            success=False, patched_bytes=None,
            error=f"unsupported EI_CLASS={ei_class}"
        )
    if ei_data not in (1, 2):
        return ElfFixResult(
            success=False, patched_bytes=None,
            error=f"unsupported EI_DATA={ei_data}"
        )

    is64 = ei_class == 2
    pfx = "<" if ei_data == 1 else ">"
    buf = bytearray(raw)
    changes: list[str] = []

    # ── Parse ELF header ──────────────────────────────────────────────────
    # ELF64 Ehdr offsets (absolute from file start):
    #   16  e_type(2)  18  e_machine(2)  20  e_version(4)
    #   24  e_entry(8) 32  e_phoff(8)   40  e_shoff(8)
    #   48  e_flags(4) 52  e_ehsize(2)  54  e_phentsize(2)  56  e_phnum(2)
    #   58  e_shentsize(2) 60  e_shnum(2) 62  e_shstrndx(2)
    #
    # ELF32 Ehdr offsets (absolute from file start):
    #   16  e_type(2)  18  e_machine(2)  20  e_version(4)
    #   24  e_entry(4) 28  e_phoff(4)   32  e_shoff(4)
    #   36  e_flags(4) 40  e_ehsize(2)  42  e_phentsize(2)  44  e_phnum(2)
    #   46  e_shentsize(2) 48  e_shnum(2) 50  e_shstrndx(2)

    if is64:
        fmt = f"{pfx}HHIQQQIHHHHHH"
        SHOFF_OFF = 40   # absolute byte offset of e_shoff in file
        SHNUM_OFF = 60
        SHSTRNDX_OFF = 62
        PHENTSIZE = 56
        PH_TYPE_FMT = f"{pfx}I"
        PH_TYPE_OFF = 0
        PH_OFFSET_OFF = 8    # Elf64_Phdr: p_offset at byte 8
        PH_VADDR_OFF = 16
        OFFSET_FMT = f"{pfx}Q"
        VADDR_FMT = f"{pfx}Q"
    else:
        fmt = f"{pfx}HHIIIIIHHHHHH"
        SHOFF_OFF = 32
        SHNUM_OFF = 48
        SHSTRNDX_OFF = 50
        PHENTSIZE = 32
        PH_TYPE_FMT = f"{pfx}I"
        PH_TYPE_OFF = 0
        PH_OFFSET_OFF = 4    # Elf32_Phdr: p_offset at byte 4
        PH_VADDR_OFF = 8
        OFFSET_FMT = f"{pfx}I"
        VADDR_FMT = f"{pfx}I"

    fields = struct.unpack_from(fmt, buf, 16)
    (
        _e_type, _e_machine, _e_version, _e_entry,
        e_phoff, e_shoff, _e_flags,
        _e_ehsize, _e_phentsize, e_phnum,
        _e_shentsize, e_shnum, e_shstrndx,
    ) = fields

    if e_phoff == 0 or e_phoff >= len(buf):
        return ElfFixResult(
            success=False, patched_bytes=None,
            error=f"e_phoff={e_phoff:#x} is invalid (file size={len(buf)})"
        )
    if e_phnum == 0:
        return ElfFixResult(
            success=False, patched_bytes=None, error="e_phnum=0"
        )

    # ── Find min p_vaddr of PT_LOAD segments ─────────────────────────────
    pt_load_vaddrs: list[int] = []
    for i in range(e_phnum):
        ph_base = e_phoff + i * PHENTSIZE
        if ph_base + PHENTSIZE > len(buf):
            break
        p_type = struct.unpack_from(PH_TYPE_FMT, buf, ph_base + PH_TYPE_OFF)[0]
        if p_type == PT_LOAD:
            p_vaddr = struct.unpack_from(VADDR_FMT, buf, ph_base + PH_VADDR_OFF)[0]
            pt_load_vaddrs.append(p_vaddr)

    if not pt_load_vaddrs:
        return ElfFixResult(
            success=False, patched_bytes=None, error="no PT_LOAD segments found"
        )

    min_vaddr = min(pt_load_vaddrs)

    # ── Patch p_offset for every non-NULL segment ─────────────────────────
    for i in range(e_phnum):
        ph_base = e_phoff + i * PHENTSIZE
        if ph_base + PHENTSIZE > len(buf):
            break
        p_type = struct.unpack_from(PH_TYPE_FMT, buf, ph_base + PH_TYPE_OFF)[0]
        if p_type == PT_NULL:
            continue

        p_offset = struct.unpack_from(OFFSET_FMT, buf, ph_base + PH_OFFSET_OFF)[0]
        p_vaddr = struct.unpack_from(VADDR_FMT, buf, ph_base + PH_VADDR_OFF)[0]
        new_offset = p_vaddr - min_vaddr

        if new_offset < 0:
            changes.append(
                f"ph[{i}]: skipped — p_vaddr={p_vaddr:#x} < min_vaddr={min_vaddr:#x}"
            )
            continue

        if p_offset != new_offset:
            struct.pack_into(OFFSET_FMT, buf, ph_base + PH_OFFSET_OFF, new_offset)
            changes.append(f"ph[{i}]: p_offset {p_offset:#x} → {new_offset:#x}")

    # ── Zero out absent section-header table ──────────────────────────────
    if e_shoff == 0 or e_shoff >= len(buf):
        if e_shnum != 0 or e_shstrndx != 0:
            if is64:
                struct.pack_into(f"{pfx}H", buf, SHNUM_OFF, 0)
                struct.pack_into(f"{pfx}H", buf, SHSTRNDX_OFF, 0)
            else:
                struct.pack_into(f"{pfx}H", buf, SHNUM_OFF, 0)
                struct.pack_into(f"{pfx}H", buf, SHSTRNDX_OFF, 0)
            changes.append("zeroed e_shnum/e_shstrndx (section table absent)")

    return ElfFixResult(
        success=True,
        patched_bytes=bytes(buf),
        changes_made=changes,
    )
