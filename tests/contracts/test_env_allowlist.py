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
    DENIED_ENV_KEYS,
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


# ---------------------------------------------------------------------------
# Allow-list completeness against the code, not just against .env.example.
#
# ALLOWED_ENV_KEYS claims to be "every key .env.example documents *plus* the
# additional keys read directly from the environment elsewhere in the tree".
# The tests above only enforce the first half. The second half matters because
# a key the code reads but the allow-list omits is dropped from .env silently:
# the rejected-key warning only fires for names *outside* the allow-list, so it
# cannot report this case. The operator loses a configured provider (Atlas
# Cloud tools report UNAVAILABLE; a split-GPU ComfyUI topology collapses onto
# the shared endpoint) with no diagnostic at all.
# ---------------------------------------------------------------------------

# Every way this tree resolves an environment name.
_ENV_READ_PATTERNS = (
    # os.environ["X"] / os.environ.get("X")
    re.compile(r"""os\.environ(?:\.get)?\s*[\(\[]\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"""os\.getenv\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    # lib/env_loader.get_env / require_env
    re.compile(r"""(?:get_env|require_env)\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    # Tool dependency declarations, e.g. dependencies = ["env:FAL_KEY"]
    re.compile(r"""["']env:([A-Za-z_][A-Za-z0-9_]*)["']"""),
    # JS / TS surface.
    re.compile(r"""process\.env(?:\.|\[\s*["'])([A-Za-z_][A-Za-z0-9_]*)"""),
    re.compile(r"""import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)"""),
)

# Alias lists a literal scan cannot see into, e.g. tools/atlas_client.py's
# ENV_KEYS = ("ATLASCLOUD_API_KEY", "ATLAS_CLOUD_API_KEY", "ATLAS_API_KEY").
_ENV_TUPLE = re.compile(r"^_?ENV_KEYS\s*=\s*\(([^)]*)\)", re.MULTILINE)
_ENV_TUPLE_ITEM = re.compile(r"""["']([A-Za-z_][A-Za-z0-9_]*)["']""")

# Names assembled at runtime, e.g.
# f"COMFYUI_{capability.upper()}_SERVER_URL" in tools/_comfyui/client.py. The
# concrete names cannot be recovered from the f-string (the interpolated value
# is a variable, not a literal), so this pattern is used only to notice that a
# dynamic family exists; the names themselves are read from the declaration in
# tools/_comfyui/metadata.py.
_ENV_FSTRING = re.compile(r"""f["']([A-Za-z_]*)\{([a-z_]+)\.upper\(\)\}([A-Za-z_]*)["']""")

# The only places allowed to build an environment name at runtime. Adding an
# entry means a new dynamic family whose concrete names a literal scan cannot
# see, so _env_names_read_by_code() has to be told where to read them from.
_DYNAMIC_ENV_NAME_SITES = {"tools/_comfyui/client.py"}

_SCANNED_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".mjs", ".cjs"}

# "tests" is shipped as part of the repository but is not the shipped surface:
# contract tests deliberately spell out placeholder names in docstrings and
# comments, which are not environment reads.
_SKIPPED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "tests"}

# Names the tree reads that are deliberately *not* part of the .env
# configuration surface. Every entry needs a reason, and
# test_exemptions_are_not_stale() fails if one stops being read — so this list
# cannot quietly become a hole.
_EXEMPT_ENV_KEYS = {
    # Standalone skill CLIs under .agents/ are invoked as
    # `NAME=basemap STYLE=satellite node bake-basemap.mjs`: per-invocation
    # arguments, not operator configuration, so they never belong in .env.
    "BEARING",
    "CENTER",
    "CHROME",
    "COUNTRIES",
    "DUR",
    "FPS",
    "HOLD",
    "KEEPMARGIN",
    "NAME",
    "OUT",
    "PITCH",
    "STYLE",
    "ZEND",
    "ZSTART",
    # Host / OS environment the process inherits — Windows install paths and the
    # X11 display used by the capture tools. There is nothing to load from .env.
    "APPDATA",
    "DISPLAY",
    "LOCALAPPDATA",
    "PROGRAMFILES",
    # Placeholder in the "add env:<NAME>" guidance comment in
    # tools/base_tool.py, not a real variable.
    "ENVVAR_NAME",
}


def _iter_source_files():
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in _SCANNED_SUFFIXES:
            continue
        if _SKIPPED_DIRS.intersection(path.relative_to(REPO_ROOT).parts):
            continue
        yield path


def _line_of(text: str, offset: int) -> str:
    return str(text.count("\n", 0, offset) + 1)


def _env_names_read_by_code() -> dict[str, str]:
    """Map each resolved environment name to one example ``path:line``."""
    found: dict[str, str] = {}

    for path in _iter_source_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        location = str(path.relative_to(REPO_ROOT))
        for pattern in _ENV_READ_PATTERNS:
            for match in pattern.finditer(text):
                found.setdefault(
                    match.group(1), f"{location}:{_line_of(text, match.start())}"
                )
        if path.suffix == ".py":
            for tuple_match in _ENV_TUPLE.finditer(text):
                for name in _ENV_TUPLE_ITEM.findall(tuple_match.group(1)):
                    found.setdefault(
                        name, f"{location}:{_line_of(text, tuple_match.start())}"
                    )

    # Per-capability ComfyUI endpoints are declared as data rather than as
    # string literals, so the patterns above cannot find them. Dynamic sites are
    # checked separately by _dynamic_env_name_sites().
    from tools._comfyui.metadata import COMFYUI_SETUP_OFFER

    for name in COMFYUI_SETUP_OFFER["per_capability_env_var_overrides"].values():
        found.setdefault(name, "tools/_comfyui/metadata.py (per_capability_env_var_overrides)")

    return found


def _dynamic_env_name_sites() -> dict[str, str]:
    """Files that build an environment name at runtime, with an example line."""
    sites: dict[str, str] = {}
    for path in _iter_source_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        match = _ENV_FSTRING.search(text)
        if match:
            location = str(path.relative_to(REPO_ROOT))
            sites[location] = f"{location}:{_line_of(text, match.start())}"
    return sites


def test_scanner_sees_the_tree() -> None:
    """Guard the guard: a silent scanner would make the test below vacuous."""
    read = _env_names_read_by_code()

    assert len(read) > 40, f"scanner found only {len(read)} names; it is broken"
    assert "FAL_KEY" in read, "scanner missed a key read from tool dependencies"
    assert "ATLASCLOUD_API_KEY" in read, "scanner missed an alias tuple"
    assert "COMFYUI_IMAGE_SERVER_URL" in read, "scanner missed the dynamic family"


def test_dynamic_env_name_sites_are_known() -> None:
    """A new dynamic family would hide its names from a literal scan."""
    sites = set(_dynamic_env_name_sites())

    assert sites == _DYNAMIC_ENV_NAME_SITES, (
        "the set of files that build environment names at runtime changed: "
        f"unexpected={sorted(sites - _DYNAMIC_ENV_NAME_SITES)}, "
        f"missing={sorted(_DYNAMIC_ENV_NAME_SITES - sites)}. Read the concrete "
        "names from wherever the new family is declared and add them to "
        "ALLOWED_ENV_KEYS."
    )


def test_every_key_the_code_reads_is_allow_listed() -> None:
    # DENIED_ENV_KEYS is a second gate: those names are process integrity, not
    # configuration, so no code reading them can ever justify allow-listing.
    missing = sorted(
        name
        for name in _env_names_read_by_code()
        if name not in ALLOWED_ENV_KEYS
        and name not in _EXEMPT_ENV_KEYS
        and name not in DENIED_ENV_KEYS
    )

    assert missing == [], (
        "the tree reads environment names that lib/env_allowlist.py refuses to "
        f"load: {missing}. A .env entry for these is dropped without any "
        "warning (the rejected-key warning only covers names *outside* the "
        "allow-list), so the configuration silently disappears. Add them to "
        "ALLOWED_ENV_KEYS, or to _EXEMPT_ENV_KEYS with a reason if they are "
        "not part of the .env surface."
    )


def test_exemptions_are_not_stale() -> None:
    """An exemption for a name nothing reads any more is a hole, not a waiver."""
    read = set(_env_names_read_by_code())
    stale = sorted(_EXEMPT_ENV_KEYS - read)

    assert stale == [], (
        f"_EXEMPT_ENV_KEYS waives names nothing reads any more: {stale}. Drop "
        "them so the list keeps proving it is intentional."
    )


def test_documented_keys_and_code_reads_are_consistent() -> None:
    """The documented surface must also be a surface something actually reads."""
    documented = _documented_keys()

    assert documented <= (ALLOWED_ENV_KEYS | _EXEMPT_ENV_KEYS), (
        ".env.example documents keys the allow-list refuses: "
        f"{sorted(documented - ALLOWED_ENV_KEYS - _EXEMPT_ENV_KEYS)}"
    )

