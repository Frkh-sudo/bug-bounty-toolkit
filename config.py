"""
BugKit v4 — Global Configuration
All settings can be overridden via environment variables (BUGKIT_*) or
~/.bugkit/config.json.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

VERSION   = "4.0.0"
TOOL_NAME = "BugKit"
UA        = f"Mozilla/5.0 (compatible; {TOOL_NAME}/{VERSION}; security-research)"

# ── Paths ──────────────────────────────────────────────────────────────
HOME_DIR    = Path.home() / ".bugkit"
DB_PATH     = HOME_DIR / "bugkit.db"
OUTPUT_DIR  = Path("output")
CONFIG_FILE = HOME_DIR / "config.json"
KEY_FILE    = HOME_DIR / ".identity_key"   # Fernet key for credential encryption

# ── Defaults ───────────────────────────────────────────────────────────
DEFAULT_TIMEOUT  = 15
DEFAULT_DELAY    = 0.3
DEFAULT_WORKERS  = 4
DEFAULT_RETRIES  = 2
DEFAULT_BURST    = 30


class Settings:
    """
    Singleton-style settings object loaded once at startup.
    Priority: environment variable > config.json > coded default.
    """
    def __init__(self) -> None:
        raw: dict = {}
        if CONFIG_FILE.exists():
            try:
                raw = json.loads(CONFIG_FILE.read_text())
            except Exception:
                pass

        def _get(key: str, default):
            env_key = f"BUGKIT_{key.upper()}"
            return os.environ.get(env_key, raw.get(key, default))

        def _get_bool(key: str, default: bool) -> bool:
            # os.environ.get() always returns a str, and bool("false") is
            # True in Python since any non-empty string is truthy. That
            # silently broke BUGKIT_SAFE_MODE=false / BUGKIT_DEBUG=0, etc.
            # — the value would come back True regardless of what was set.
            v = _get(key, default)
            if isinstance(v, bool):
                return v
            if isinstance(v, str):
                return v.strip().lower() in ("1", "true", "yes", "on")
            return bool(v)

        self.timeout:    int   = int(_get("timeout",    DEFAULT_TIMEOUT))
        self.delay:      float = float(_get("delay",    DEFAULT_DELAY))
        self.workers:    int   = int(_get("workers",    DEFAULT_WORKERS))
        self.retries:    int   = int(_get("retries",    DEFAULT_RETRIES))
        self.proxy:      Optional[str] = _get("proxy",  None)
        self.safe_mode:  bool  = _get_bool("safe_mode", True)
        self.dry_run:    bool  = _get_bool("dry_run",   False)
        self.db_path:    Path  = Path(_get("db_path",   str(DB_PATH)))
        self.output_dir: Path  = Path(_get("output_dir",str(OUTPUT_DIR)))
        self.debug:      bool  = _get_bool("debug",     False)

    def save(self) -> None:
        HOME_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps({
            "timeout":    self.timeout,
            "delay":      self.delay,
            "workers":    self.workers,
            "retries":    self.retries,
            "proxy":      self.proxy,
            "safe_mode":  self.safe_mode,
            "dry_run":    self.dry_run,
            "db_path":    str(self.db_path),
            "output_dir": str(self.output_dir),
        }, indent=2))


# Eagerly loaded singleton
settings = Settings()
