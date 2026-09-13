"""Environment variable loader for OpenMontage.

Loads .env file and provides typed access to environment configuration.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from dotenv import dotenv_values

from lib.env_allowlist import is_allowed_env_key, warn_rejected_keys


def load_env(project_root: Optional[Path] = None) -> None:
    """Load .env file from project root.

    Entries outside the shared allow-list are skipped rather than exported: a
    .env file is untrusted input, and an unfiltered export would let it set
    LD_PRELOAD / BASH_ENV / PATH for every child process the pipeline spawns.
    See ``lib.env_allowlist`` for the rationale and the allowed key set.
    """
    if project_root is None:
        project_root = Path(__file__).resolve().parent.parent
    env_path = project_root / ".env"
    if not env_path.exists():
        return
    rejected: List[str] = []
    for key, value in dotenv_values(env_path).items():
        if not is_allowed_env_key(key):
            rejected.append(key)
            continue
        if value is None:
            continue
        # Historical behaviour: never clobber an environment variable the
        # operator already exported.
        os.environ.setdefault(key, value)
    warn_rejected_keys(rejected)


def get_env(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get an environment variable with optional default."""
    return os.environ.get(key, default)


def require_env(key: str) -> str:
    """Get a required environment variable. Raises if missing."""
    value = os.environ.get(key)
    if value is None:
        raise EnvironmentError(f"Required environment variable {key!r} is not set")
    return value
