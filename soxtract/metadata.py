from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class LibraryMetadata:
    schema_version: int = 1
    library_name: str = ""
    base_address: str = ""
    size_bytes: int = 0
    extraction_method: str = ""
    timestamp_utc: str = ""
    pid: int = 0
    package: str = ""
    elf_valid: bool = False
    elf_bitness: int | None = None
    elf_abi: str | None = None
    elf_repaired: bool = False
    repair_changes: list[str] = field(default_factory=list)
    retry_count: int = 0
    read_errors: list[str] = field(default_factory=list)
    notes: str = ""


def write_sidecar(path: Path, meta: LibraryMetadata) -> None:
    path.write_text(json.dumps(asdict(meta), indent=2))
