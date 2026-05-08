from __future__ import annotations

import argparse
import datetime
import logging
import signal
import sys
import threading

from .config import from_args
from .extractor import Extractor
from .session import ExtractionSession


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="soxtract",
        description="Dynamically extract native .so libraries from Android apps via Frida",
    )
    p.add_argument(
        "package_or_pid",
        metavar="PACKAGE|PID",
        help="Target Android package name (com.example.app) or process PID",
    )
    p.add_argument("--output-dir", metavar="DIR", help="Directory to save extracted libs")
    p.add_argument("--config", metavar="FILE", help="Optional TOML config file")
    p.add_argument(
        "--no-fix",
        action="store_true",
        default=False,
        help="Skip ELF repair; save raw memory dump as .so",
    )
    p.add_argument(
        "--chunk-size",
        type=int,
        metavar="KB",
        help="Memory read chunk size in KB (default: 256)",
    )
    p.add_argument(
        "--scan-interval",
        type=int,
        metavar="MS",
        help="Memory scan interval in ms (default: 5000)",
    )
    p.add_argument(
        "--loader-delay",
        type=int,
        metavar="MS",
        help="Delay after dlopen before dumping in ms (default: 250)",
    )
    p.add_argument("--retries", type=int, metavar="N", help="Memory read retries (default: 3)")
    p.add_argument(
        "--spawn",
        action="store_true",
        default=False,
        help="Spawn the target app instead of attaching to a running process",
    )
    p.add_argument(
        "--timeout",
        type=int,
        metavar="S",
        help="Stop after N seconds (default: 0 = run until Ctrl-C)",
    )
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        metavar="LEVEL",
        help="Logging level (default: INFO)",
    )
    return p


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    cfg = from_args(args)

    logging.basicConfig(
        level=getattr(logging, cfg.log_level, logging.INFO),
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )

    # Build a timestamped output dir under the user-specified root
    target = cfg.package_name or str(cfg.pid)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = cfg.output_dir / target / ts

    extractor = Extractor(cfg, output_dir)
    session = ExtractionSession(cfg, extractor)

    stop_event = threading.Event()

    def _sigint(*_: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    try:
        session.start()
        print(f"\n[soxtract] Extracting from '{target}'  →  {output_dir}")
        print("[soxtract] Press Ctrl-C to stop.\n")

        if cfg.timeout > 0:
            stop_event.wait(timeout=cfg.timeout)
        else:
            stop_event.wait()

    except Exception as exc:
        print(f"\n[soxtract] Fatal: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        session.stop()
        extractor.print_summary()
