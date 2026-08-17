"""Utility helpers for SecureVPN configuration."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable


def load_env(path: str | os.PathLike[str] = ".env") -> None:
    """Load key=value pairs from a simple .env file into the environment."""
    env_path = Path(path)
    if not env_path.exists():
        return

    try:
        lines: Iterable[str] = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)
