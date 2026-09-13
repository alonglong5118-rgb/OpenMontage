"""Environment variable loader for OpenMontage.

Loads .env file and provides typed access to environment configuration.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from lib.env_allowlist import apply_env_entries, parse_dotenv


def load_env(project_root: Optional[Path] = None) -> None:
    """Load .env file from project root.

    Entries outside the shared allow-list are skipped rather than exported: a
    .env file is untrusted input, and an unfiltered export would let it set
    LD_PRELOAD / BASH_ENV / PATH for every child process the pipeline spawns.
    See ``lib.env_allowlist`` for the rationale and the allowed key set.

    The project's own ``parse_dotenv`` is used instead of python-dotenv's
    ``dotenv_values`` on purpose: ``dotenv_values`` performs ``${VAR}``
    interpolation *before* the allow-list is consulted, so a line such as
    ``FAL_KEY=${AWS_SECRET_ACCESS_KEY}`` would be resolved against the
    operator's live environment and copied in verbatim -- the key name passes
    the allow-list, but the value is a credential that does not belong in
    FAL_KEY. ``parse_dotenv`` keeps values literal and lets ``apply_env_entries``
    do the gating, matching ``tools.base_tool._load_dotenv``.
    """
    if project_root is None:
        project_root = Path(__file__).resolve().parent.parent
    env_path = project_root / ".env"
    if not env_path.exists():
        return
    apply_env_entries(
        parse_dotenv(env_path.read_text(encoding="utf-8", errors="ignore"))
    )


def get_env(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get an environment variable with optional default."""
    return os.environ.get(key, default)


def require_env(key: str) -> str:
    """Get a required environment variable. Raises if missing."""
    value = os.environ.get(key)
    if value is None:
        raise EnvironmentError(f"Required environment variable {key!r} is not set")
    return value
