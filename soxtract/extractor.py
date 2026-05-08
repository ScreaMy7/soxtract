"""
Receives Frida agent messages, reassembles chunked memory transfers,
validates the ELF data, optionally repairs it, and writes output files.
"""
from __future__ import annotations

import datetime
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import Any

from .config import Config
from .dedup import DedupRegistry
from .elf_fixer import fix as elf_fix
from .elf_validator import validate as elf_validate
from .metadata import LibraryMetadata, write_sidecar

logger = logging.getLogger(__name__)


@dataclass
class TransferState:
    lib_id: str
    transfer_id: str
    name: str
    base_addr: int
    total_size: int
    total_chunks: int
    method: str
    path: str
    chunks: dict[int, bytes] = field(default_factory=dict)
    received: int = 0
    done_signalled: bool = False
    started_at: float = field(default_factory=monotonic)
    retry_count: int = 0
    read_errors: list[str] = field(default_factory=list)


def _safe_name(name: str) -> str:
    base = name.removesuffix(".so")
    sanitized = re.sub(r"[^\w\-.]", "_", base)[:60]
    return sanitized or "unknown"


def _output_stem(name: str, base_addr: int) -> str:
    suffix = f"{base_addr & 0xFFFFFFFF:08x}"
    return f"{_safe_name(name)}_{suffix}"


class Extractor:
    def __init__(self, config: Config, output_dir: Path) -> None:
        self._config = config
        self._output_dir = output_dir
        self._libs_dir = output_dir / "libs"
        self._raw_dir = output_dir / "raw"
        self._libs_dir.mkdir(parents=True, exist_ok=True)
        self._raw_dir.mkdir(parents=True, exist_ok=True)
        self._dedup = DedupRegistry()
        self._transfers: dict[str, TransferState] = {}
        self._lock = threading.Lock()
        self._saved = 0
        self._skipped = 0

    # ── Public message entry point ────────────────────────────────────────

    def on_message(self, message: dict[str, Any], data: bytes | None) -> None:
        if message.get("type") == "error":
            logger.error("Agent error: %s", message.get("description", message))
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        event = payload.get("event")
        try:
            match event:
                case "lib_found":
                    self._on_lib_found(payload)
                case "chunk":
                    self._on_chunk(payload, data)
                case "lib_done":
                    self._on_lib_done(payload)
                case "lib_error":
                    self._on_lib_error(payload)
                case "lib_skipped":
                    self._on_lib_skipped(payload)
                case "scan_status":
                    logger.debug(
                        "Scan: %d new, %d cached",
                        payload.get("new_found", 0),
                        payload.get("cached_skipped", 0),
                    )
        except Exception:
            logger.exception("Error handling event=%s", event)

    # ── Event handlers ────────────────────────────────────────────────────

    def _on_lib_found(self, p: dict[str, Any]) -> None:
        tid = p["transfer_id"]
        base_addr = int(p["base"], 16)
        size = int(p["size"])
        chunk_size = self._config.chunk_size
        total_chunks = max(1, -(-size // chunk_size))  # ceiling division

        state = TransferState(
            lib_id=p["lib_id"],
            transfer_id=tid,
            name=p["name"],
            base_addr=base_addr,
            total_size=size,
            total_chunks=total_chunks,
            method=p["method"],
            path=p.get("path", ""),
        )
        with self._lock:
            self._transfers[tid] = state
        logger.info("Found  %-40s  base=%s  size=%d", p["name"], p["base"], size)

    def _on_chunk(self, p: dict[str, Any], data: bytes | None) -> None:
        tid = p["transfer_id"]
        with self._lock:
            state = self._transfers.get(tid)
            if state is None or data is None:
                return
            seq = int(p["seq"])
            state.chunks[seq] = data
            state.received += 1
            # Update total_chunks from the agent's value (more accurate)
            state.total_chunks = int(p["total"])
            should_finalize = (
                state.done_signalled and state.received >= state.total_chunks
            )

        if should_finalize:
            self._finalize(tid)

    def _on_lib_done(self, p: dict[str, Any]) -> None:
        tid = p["transfer_id"]
        with self._lock:
            state = self._transfers.get(tid)
            if state is None:
                return
            state.done_signalled = True
            ready = state.received >= state.total_chunks

        if ready:
            self._finalize(tid)

    def _on_lib_error(self, p: dict[str, Any]) -> None:
        tid = p["transfer_id"]
        with self._lock:
            state = self._transfers.pop(tid, None)
        if state:
            state.read_errors.append(p.get("error", "unknown"))
            logger.warning(
                "Read error %-36s (retry %d): %s",
                state.name, p.get("retry_count", 0), p.get("error", ""),
            )

    def _on_lib_skipped(self, p: dict[str, Any]) -> None:
        logger.info("Skipped %s (%s)", p.get("lib_id", "?"), p.get("reason", "?"))
        with self._lock:
            self._skipped += 1

    # ── Finalization pipeline ─────────────────────────────────────────────

    def _finalize(self, tid: str) -> None:
        with self._lock:
            state = self._transfers.pop(tid, None)
        if state is None:
            return

        if not self._dedup.is_new(state.name, state.base_addr):
            logger.debug("Duplicate skipped: %s @ %#x", state.name, state.base_addr)
            return

        # Reassemble chunks in seq order
        raw = b"".join(
            state.chunks[i]
            for i in sorted(state.chunks)
        )

        stem = _output_stem(state.name, state.base_addr)
        raw_path = self._raw_dir / f"{stem}.so.raw"
        raw_path.write_bytes(raw)

        # ELF validation
        vresult = elf_validate(raw)
        logger.debug(
            "Validate %s: valid=%s repairable=%s errors=%s",
            state.name, vresult.is_valid, vresult.is_repairable, vresult.errors,
        )

        # ELF repair
        final_bytes = raw
        repaired = False
        repair_changes: list[str] = []

        if self._config.fix_elf and vresult.is_repairable and not vresult.is_valid:
            fresult = elf_fix(raw)
            if fresult.success and fresult.patched_bytes:
                reverify = elf_validate(fresult.patched_bytes)
                if reverify.is_valid:
                    final_bytes = fresult.patched_bytes
                    repaired = True
                    repair_changes = fresult.changes_made
                    logger.debug("Repaired %s: %s", state.name, repair_changes)
                else:
                    logger.warning(
                        "Repair of %s produced invalid ELF: %s",
                        state.name, reverify.errors,
                    )

        so_path = self._libs_dir / f"{stem}.so"
        so_path.write_bytes(final_bytes)

        final_valid = vresult.is_valid or repaired
        meta = LibraryMetadata(
            library_name=state.name,
            base_address=f"{state.base_addr:#x}",
            size_bytes=len(raw),
            extraction_method=state.method,
            timestamp_utc=datetime.datetime.utcnow().isoformat() + "Z",
            pid=0,
            package=self._config.package_name or "",
            elf_valid=final_valid,
            elf_bitness=vresult.bitness,
            elf_abi=vresult.abi,
            elf_repaired=repaired,
            repair_changes=repair_changes,
            retry_count=state.retry_count,
            read_errors=state.read_errors,
            notes="anonymous mapping — possible packed lib" if not state.path else "",
        )
        write_sidecar(self._libs_dir / f"{stem}.meta.json", meta)

        status = "repaired" if repaired else ("valid" if vresult.is_valid else "raw")
        logger.info(
            "Saved  %-40s  %s  (%d bytes) → libs/%s",
            state.name, status, len(final_bytes), so_path.name,
        )
        with self._lock:
            self._saved += 1

    # ── Summary ───────────────────────────────────────────────────────────

    def print_summary(self) -> None:
        print(f"\n{'─' * 50}")
        print(f"  Saved:   {self._saved}")
        print(f"  Skipped: {self._skipped}")
        print(f"  libs/    {self._libs_dir}")
        print(f"  raw/     {self._raw_dir}")
        print(f"{'─' * 50}\n")
