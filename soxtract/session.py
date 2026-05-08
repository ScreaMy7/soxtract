from __future__ import annotations

import importlib.resources
import logging
from pathlib import Path
from typing import Any

import frida

from .config import Config
from .extractor import Extractor

logger = logging.getLogger(__name__)

# Prefer the in-package agent.js (used when installed via pip).
# Fall back to the build tree location for local development.
def _find_agent_js() -> Path:
    pkg_agent = Path(__file__).parent / "agent.js"
    if pkg_agent.exists():
        return pkg_agent
    dev_agent = Path(__file__).parent.parent / "agent" / "dist" / "agent.js"
    return dev_agent


class ExtractionSession:
    def __init__(self, config: Config, extractor: Extractor) -> None:
        self._config = config
        self._extractor = extractor
        self._device: frida.core.Device | None = None
        self._session: frida.core.Session | None = None
        self._script: frida.core.Script | None = None
        self._spawned_pid: int | None = None

    def start(self) -> None:
        agent_js = _find_agent_js()
        if not agent_js.exists():
            raise FileNotFoundError(
                f"Compiled agent not found at {agent_js}\n"
                "Run: cd agent && npm install && npm run build"
            )

        self._device = frida.get_usb_device(timeout=10)
        cfg = self._config

        if cfg.spawn:
            if not cfg.package_name:
                raise ValueError("--spawn requires a package name, not a PID")
            self._spawned_pid = self._device.spawn([cfg.package_name])
            self._session = self._device.attach(self._spawned_pid)
            logger.info("Spawned and attached to %s (pid %d)", cfg.package_name, self._spawned_pid)
        elif cfg.pid is not None:
            self._session = self._device.attach(cfg.pid)
            logger.info("Attached to pid %d", cfg.pid)
        else:
            self._session = self._device.attach(cfg.package_name)
            logger.info("Attached to %s", cfg.package_name)

        source = agent_js.read_text(encoding="utf-8")
        self._script = self._session.create_script(source)
        self._script.on("message", self._on_message)
        self._script.load()

        agent_cfg = {
            "chunkSize": cfg.chunk_size,
            "scanInterval": cfg.scan_interval,
            "loaderDelay": cfg.loader_delay,
            "retries": cfg.retries,
            "retryBackoffMs": cfg.retry_backoff_ms,
        }
        self._script.exports_sync.configure(agent_cfg)

        if cfg.spawn and self._spawned_pid is not None:
            self._device.resume(self._spawned_pid)
            logger.info("Resumed pid %d", self._spawned_pid)

    def _on_message(self, message: dict[str, Any], data: bytes | None) -> None:
        self._extractor.on_message(message, data)

    def stop(self) -> None:
        if self._script:
            try:
                self._script.exports_sync.stop()
            except Exception:
                pass
            try:
                self._script.unload()
            except Exception:
                pass
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass
        logger.info("Session stopped.")
