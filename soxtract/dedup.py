from __future__ import annotations
import threading


class DedupRegistry:
    """Thread-safe deduplication registry keyed on (library_name, base_addr)."""

    def __init__(self) -> None:
        self._seen: set[tuple[str, int]] = set()
        self._lock = threading.Lock()

    def is_new(self, name: str, base_addr: int) -> bool:
        key = (name, base_addr)
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)
