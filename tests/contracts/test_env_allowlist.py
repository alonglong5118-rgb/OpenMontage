"""Contract tests for the project .env allow-list.

A regression here means a .env file that arrives with a cloned repository or an
imported project bundle can set LD_PRELOAD / BASH_ENV / PATH / PYTHONPATH and
execute attacker code in every child process the pipeline spawns.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from lib.env_allowlist import (
    ALLOWED_ENV_KEYS,
    apply_env_entries,
    is_allowed_env_key,
    parse_dotenv,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

# Matches live and commented-out .env.example entries alike, e.g. "FAL_KEY="
# and "# GEMINI_API_KEY=   # alias for GOOGLE_API_KEY".
_DECLARED_KEY = re.compile(r"^#?\s*([A-Z][A-Z0-9_]*)\s*=", re.MULTILINE)


def _documented_keys() -> set[str]:
    text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    return set(_DECLARED_KEY.findall(text))


def test_env_example_still_declares_keys() -> None:
    """Guard the guard: the extractor has to actually find the documented keys."""
    assert len(_documented_keys()) > 40


def test_every_documented_key_is_allow_listed() -> None:
    missing = sorted(_documented_keys() - ALLOWED_ENV_KEYS)
    assert missing == [], (
        ".env.example documents keys that lib/env_allowlist.py refuses to load: "
        f"{missing}. Add them to ALLOWED_ENV_KEYS, otherwise the pipeline "
        "silently loses that configuration."
    )


@pytest.mark.parametrize(
    "hostile_key",
    [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "BASH_ENV",
        "PATH",
        "IFS",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "HOME",
        "TMPDIR",
        "SSH_AUTH_SOCK",
        "GIT_SSH_COMMAND",
        "REQUESTS_CA_BUNDLE",
        "BASH_FUNC_anything%%",
    ],
)
def test_process_integrity_keys_are_rejected(hostile_key: str) -> None:
    assert is_allowed_env_key(hostile_key) is False


def test_hostile_dotenv_never_reaches_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    text = "\n".join(
        [
            "# a hostile .env shipped with a repository",
            "LD_PRELOAD=/tmp/evil.so",
            "BASH_ENV=/tmp/evil.sh",
            "PATH=/tmp/evil-bin",
            "PYTHONPATH=/tmp/evil",
            'FAL_KEY="legit-key"',
        ]
    )
    tracked = ("LD_PRELOAD", "BASH_ENV", "PATH", "PYTHONPATH", "FAL_KEY")
    for key in tracked:
        monkeypatch.delenv(key, raising=False)

    applied, rejected = apply_env_entries(parse_dotenv(text), warn=False)

    assert applied == ["FAL_KEY"]
    assert set(rejected) == {"LD_PRELOAD", "BASH_ENV", "PATH", "PYTHONPATH"}
    assert os.environ["FAL_KEY"] == "legit-key"
    for key in ("LD_PRELOAD", "BASH_ENV", "PATH", "PYTHONPATH"):
        assert key not in os.environ


def test_existing_environment_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "from-shell")

    applied, _ = apply_env_entries([("OPENAI_API_KEY", "from-dotenv")], warn=False)

    assert applied == []
    assert os.environ["OPENAI_API_KEY"] == "from-shell"


def test_registry_delegates_to_the_shared_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both entry points must share one parser rather than keep two copies."""
    import tools.base_tool as base_tool
    from tools.tool_registry import ToolRegistry

    calls: list[int] = []
    monkeypatch.setattr(base_tool, "load_project_dotenv", lambda: calls.append(1))

    ToolRegistry._load_dotenv()

    assert calls == [1], "ToolRegistry must not carry its own .env parser"
