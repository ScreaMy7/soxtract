from __future__ import annotations
import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[no-redef]
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            tomllib = None  # type: ignore[assignment]


@dataclass
class Config:
    package_name: str | None = None
    pid: int | None = None
    output_dir: Path = Path("soxtract_out")
    chunk_size: int = 256 * 1024   # bytes (256 KB)
    scan_interval: int = 5000       # ms
    loader_delay: int = 250         # ms
    retries: int = 3
    retry_backoff_ms: int = 500
    fix_elf: bool = True
    spawn: bool = False
    timeout: int = 0               # seconds; 0 = unlimited
    log_level: str = "INFO"


def from_args(args: object) -> Config:
    cfg = Config()

    if hasattr(args, "config") and args.config:  # type: ignore[union-attr]
        cfg = _load_toml(Path(args.config), cfg)  # type: ignore[union-attr]

    target = getattr(args, "package_or_pid", None)
    if target:
        try:
            cfg.pid = int(target)
        except ValueError:
            cfg.package_name = target

    if getattr(args, "output_dir", None):
        cfg.output_dir = Path(args.output_dir)  # type: ignore[union-attr]
    if getattr(args, "chunk_size", None) is not None:
        cfg.chunk_size = args.chunk_size * 1024  # type: ignore[union-attr]
    if getattr(args, "scan_interval", None) is not None:
        cfg.scan_interval = args.scan_interval  # type: ignore[union-attr]
    if getattr(args, "loader_delay", None) is not None:
        cfg.loader_delay = args.loader_delay  # type: ignore[union-attr]
    if getattr(args, "retries", None) is not None:
        cfg.retries = args.retries  # type: ignore[union-attr]
    if getattr(args, "no_fix", False):
        cfg.fix_elf = False
    if getattr(args, "spawn", False):
        cfg.spawn = True
    if getattr(args, "timeout", None) is not None:
        cfg.timeout = args.timeout  # type: ignore[union-attr]
    if getattr(args, "log_level", None):
        cfg.log_level = args.log_level.upper()  # type: ignore[union-attr]

    return cfg


def _load_toml(path: Path, base: Config) -> Config:
    if tomllib is None:
        raise RuntimeError(
            "TOML config requires Python 3.11+ or: pip install tomli"
        )
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    section = data.get("soxtract", {})
    for key, value in section.items():
        if hasattr(base, key):
            if key == "output_dir":
                setattr(base, key, Path(value) if value else Path("sosaver_out"))
            else:
                setattr(base, key, value)
    return base
