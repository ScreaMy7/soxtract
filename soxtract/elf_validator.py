from __future__ import annotations
import struct
from dataclasses import dataclass, field

ELF_MAGIC = b"\x7fELF"

_MACHINE_ABI: dict[int, str] = {
    3: "x86",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
}

# ELF e_type values
ET_DYN = 3


@dataclass
class ElfValidationResult:
    is_valid: bool
    is_repairable: bool
    magic_ok: bool
    bitness: int | None
    endian: str | None
    abi: str | None
    e_type: int | None
    errors: list[str] = field(default_factory=list)


def validate(data: bytes) -> ElfValidationResult:
    """Inspect ELF header fields and return a structured validation result."""

    def _fail(msg: str, repairable: bool = False) -> ElfValidationResult:
        return ElfValidationResult(
            is_valid=False,
            is_repairable=repairable,
            magic_ok=False,
            bitness=None,
            endian=None,
            abi=None,
            e_type=None,
            errors=[msg],
        )

    if len(data) < 64:
        return _fail(f"file too small: {len(data)} bytes (minimum 64)")

    if data[:4] != ELF_MAGIC:
        return _fail(f"bad magic: {data[:4].hex()}")

    ei_class = data[4]
    ei_data = data[5]
    errors: list[str] = []

    if ei_class not in (1, 2):
        errors.append(f"invalid EI_CLASS={ei_class}")
    if ei_data not in (1, 2):
        errors.append(f"invalid EI_DATA={ei_data}")

    if errors:
        return ElfValidationResult(
            is_valid=False,
            is_repairable=True,
            magic_ok=True,
            bitness=None,
            endian=None,
            abi=None,
            e_type=None,
            errors=errors,
        )

    is64 = ei_class == 2
    bitness = 64 if is64 else 32
    endian = "little" if ei_data == 1 else "big"
    pfx = "<" if endian == "little" else ">"

    # Unpack from offset 16 (after e_ident[16]).
    # ELF64: HHIQQQIHHHHHH  (e_type HH I Q QQ I HHHHHH)
    # ELF32: HHIIIIIHHHHHH (same logical fields, different sizes)
    if is64:
        fmt = f"{pfx}HHIQQQIHHHHHH"
    else:
        fmt = f"{pfx}HHIIIIIHHHHHH"

    fields = struct.unpack_from(fmt, data, 16)
    (
        e_type, e_machine, e_version, _e_entry,
        e_phoff, _e_shoff, _e_flags,
        _e_ehsize, e_phentsize, e_phnum,
        _e_shentsize, _e_shnum, _e_shstrndx,
    ) = fields

    abi = _MACHINE_ABI.get(e_machine)
    expected_phentsize = 56 if is64 else 32

    if e_type != ET_DYN:
        errors.append(f"e_type={e_type} (expected {ET_DYN}/ET_DYN)")
    if e_machine not in _MACHINE_ABI:
        errors.append(f"unknown e_machine={e_machine}")
    if e_version != 1:
        errors.append(f"e_version={e_version} (expected 1)")
    if e_phoff == 0:
        errors.append("e_phoff=0 (no program headers)")
    elif e_phoff >= len(data):
        errors.append(f"e_phoff={e_phoff:#x} beyond file size {len(data)}")
    if e_phnum == 0:
        errors.append("e_phnum=0")
    if e_phentsize != expected_phentsize:
        errors.append(
            f"e_phentsize={e_phentsize} (expected {expected_phentsize})"
        )

    is_valid = len(errors) == 0
    is_repairable = len(errors) <= 4

    return ElfValidationResult(
        is_valid=is_valid,
        is_repairable=is_repairable,
        magic_ok=True,
        bitness=bitness,
        endian=endian,
        abi=abi,
        e_type=e_type,
        errors=errors,
    )
