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
    SHELL_ONLY_ENV_KEYS,
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
    """Guard the guard: the extractor has to actually find the documented keys.

    Round 6 收口把一批端点/路径键从 `KEY=` 改为纯注释说明（它们属 DENIED，
    本就不该以 KEY= 形式出现在 .env.example 诱导填写），故文档键降到 38。
    下限 30 仍能在 .env.example 被大规模清空时抓住回归。
    """
    assert len(_documented_keys()) > 30


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
    # Record each name before the body writes it. delenv() only registers a name
    # for restoration when it is currently present, so an already-unset name is
    # not recorded and the direct os.environ write below would survive teardown
    # (the next test would then read a value no file supplied). setenv() first
    # makes the name present so it is recorded; the delenv() leaves it absent.
    for key in tracked:
        monkeypatch.setenv(key, "")
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


def test_env_loader_does_not_interpolate(monkeypatch: pytest.MonkeyPatch) -> None:
    """load_env must keep .env values literal, never resolve ${VAR}.

    python-dotenv's ``dotenv_values`` interpolates ``${AWS_SECRET_ACCESS_KEY}``
    against the live environment *before* the allow-list is consulted, so
    ``FAL_KEY=${AWS_SECRET_ACCESS_KEY}`` would copy the operator's real AWS
    secret into FAL_KEY even though the key name passes the allow-list.
    load_env must use parse_dotenv (literal) so the value stays the literal
    ``${AWS_SECRET_ACCESS_KEY}`` and never reaches a credential.
    """
    import tempfile
    from pathlib import Path as _Path

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "OPERATOR-REAL-SECRET")
    # FAL_KEY is written by load_env -> apply_env_entries below, outside the
    # monkeypatch record if we only delenv a name that is already absent. Record
    # it first (setenv("") then delenv) so fixture teardown restores it and no
    # value leaks into later tests (vuln-0005).
    monkeypatch.setenv("FAL_KEY", "")
    monkeypatch.delenv("FAL_KEY", raising=False)

    d = _Path(tempfile.mkdtemp())
    (d / ".env").write_text("FAL_KEY=${AWS_SECRET_ACCESS_KEY}\n")

    from lib.env_loader import load_env

    load_env(d)

    assert os.environ.get("FAL_KEY") == "${AWS_SECRET_ACCESS_KEY}", (
        "load_env resolved ${AWS_SECRET_ACCESS_KEY} against the live env: "
        f"{os.environ.get('FAL_KEY')!r}"
    )
    assert os.environ.get("FAL_KEY") != "OPERATOR-REAL-SECRET"


def test_nul_value_is_rejected_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """An embedded NUL in an allow-listed value must be dropped, not raised.

    ``os.environ[key] = value`` raises ``ValueError`` on a NUL byte, and the
    loader runs at module scope in ``tools/base_tool``, so an uncaught raise
    would abort ``import tools.base_tool``. The value is untrusted input like
    the key, so it is validated too: a NUL-bearing pair is reported as rejected
    and skipped, never written.
    """
    monkeypatch.delenv("FAL_KEY", raising=False)

    applied, rejected = apply_env_entries([("FAL_KEY", "sk-live\x00")], warn=False)

    assert applied == []
    assert rejected == ["FAL_KEY"]
    assert os.environ.get("FAL_KEY") is None


def test_executable_selection_keys_are_denied() -> None:
    """Names whose value is the program a tool spawns must never be honoured.

    ``BLENDER_PATH`` / ``SADTALKER_PATH`` / ``WAV2LIP_PATH`` are consumed as
    ``argv[0]`` by the graphics/avatar tools, so a ``.env`` carrying one is
    remote code execution. They live in ``DENIED_ENV_KEYS`` and are also caught
    by the ``*_PATH`` / ``*_EXEC`` / ``*_BIN`` / ``*_CMD`` / ``*_SHELL`` /
    ``*_RUNNER`` fail-closed shape, so a future allow-list addition cannot
    reintroduce the redirect.
    """
    for name in ("BLENDER_PATH", "SADTALKER_PATH", "WAV2LIP_PATH"):
        assert is_allowed_env_key(name) is False
    # Fail-closed: any future executable-selection shape is denied.
    assert is_allowed_env_key("MYTOOL_PATH") is False
    assert is_allowed_env_key("FOO_EXECUTABLE") is False
    assert is_allowed_env_key("FOO_BIN") is False
    assert is_allowed_env_key("FOO_COMMAND") is False
    assert is_allowed_env_key("FOO_SHELL") is False
    assert is_allowed_env_key("FOO_RUNNER") is False
    # Legit config keys must still pass.
    assert is_allowed_env_key("FAL_KEY") is True
    assert is_allowed_env_key("OPENMONTAGE_CACHE_DIR") is True


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
    # Read by code but deliberately NOT loadable from a project .env: a .env is
    # untrusted input, so it must never relocate the HeyGen credential file
    # (HEYGEN_CONFIG_DIR -> heygen.mjs) or silence the gate's own rejected-key
    # diagnostic (OPENMONTAGE_QUIET_ENV_WARNINGS -> lib/env_allowlist.py). Both
    # are refused by the gate; listing them here keeps the "every name the code
    # reads is intentional" check honest about them being out of the .env surface.
    "HEYGEN_CONFIG_DIR",
    "OPENMONTAGE_QUIET_ENV_WARNINGS",
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
    # string literals, so the patterns above cannot find them. The names are
    # taken from the runtime that builds them, not reconstructed here: the
    # declaration enumerates which capabilities exist and ComfyUIClient turns a
    # capability into its variable name, so a change to either side surfaces on
    # the other (see test_comfyui_capability_names_match_their_declaration).
    from tools._comfyui.client import ComfyUIClient
    from tools._comfyui.metadata import COMFYUI_SETUP_OFFER

    for tool_name in COMFYUI_SETUP_OFFER["per_capability_env_var_overrides"]:
        capability = tool_name.removeprefix("comfyui_")
        name = ComfyUIClient(capability=capability)._capability_env_var
        if name:
            found.setdefault(
                name, f"tools/_comfyui/client.py (ComfyUIClient(capability={capability!r}))"
            )

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


def test_comfyui_capability_names_match_their_declaration() -> None:
    """The declared override names must be the ones the runtime actually reads.

    Both sides are real: the declaration says which capabilities exist, and
    ComfyUIClient turns one into a variable name. Reading only the declaration
    would leave the two free to drift -- editing one side would remove the name
    from this suite's set while the runtime kept reading the old name, and every
    check here would stay green while a .env entry was dropped in silence.
    """
    from tools._comfyui.client import ComfyUIClient
    from tools._comfyui.metadata import COMFYUI_SETUP_OFFER

    overrides = COMFYUI_SETUP_OFFER["per_capability_env_var_overrides"]

    assert overrides, "no capability overrides declared; the derivation is stale"
    for tool_name, declared in overrides.items():
        capability = tool_name.removeprefix("comfyui_")
        runtime = ComfyUIClient(capability=capability)._capability_env_var

        assert runtime == declared, (
            f"{tool_name} declares {declared!r} but ComfyUIClient builds "
            f"{runtime!r} from capability={capability!r}. Align the two, "
            "otherwise the name read at runtime is not the name loaded from .env."
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


# ---------------------------------------------------------------------------
# The JavaScript surface. The media engine has a fourth .env reader that cannot
# import lib/env_allowlist.py (the skill is vendored to ship standalone), so it
# carries its own copy of the policy. These tests are what stops that copy from
# becoming a way around the gate: an ungated reader on a shipped path exports
# LD_PRELOAD / BASH_ENV / NODE_OPTIONS into every child the engine spawns, which
# is exactly what the Python side was hardened against.
# ---------------------------------------------------------------------------

_JS_ENV_READER = (
    REPO_ROOT
    / ".agents/skills/hyperframes-media/scripts/lib/heygen.mjs"
)

# Assignments whose *key* is a variable, i.e. the ones that can carry a name
# parsed out of a file. A literal-keyed write such as
# os.environ["OPENMONTAGE_PROJECTS_DIR"] = ... sets a constant and cannot be
# pointed anywhere by its input, so it is not a gate that needs to exist.
_ENV_WRITE_PATTERNS = (
    re.compile(r"""os\.environ\[[A-Za-z_][A-Za-z0-9_]*\]\s*=(?!=)"""),
    re.compile(r"""os\.environ\.setdefault\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,"""),
    re.compile(r"""os\.putenv\s*\("""),
    re.compile(r"""process\.env\[[A-Za-z_][A-Za-z0-9_]*\]\s*=(?!=)"""),
    re.compile(r"""process\.env\.[A-Za-z_][A-Za-z0-9_]*\s*=(?!=)"""),
    # Delegating to the shared gate: lib/env_loader.load_env and
    # tools/base_tool._load_dotenv no longer write os.environ directly, they
    # call apply_env_entries(parse_dotenv(...)). That call is what makes them
    # gated writers, so it must be recognised as one.
    re.compile(r"""apply_env_entries\s*\("""),
)

# Every file allowed to write a *parsed* name into the environment. Each one
# applies is_allowed_env_key (or, in JS, the mirrored policy) before the write.
_GATED_ENV_WRITERS = {
    "lib/env_allowlist.py",  # the shared gate
    "lib/env_loader.py",  # delegates to apply_env_entries
    "tools/base_tool.py",  # delegates to apply_env_entries (import-time load)
    ".agents/skills/hyperframes-media/scripts/lib/heygen.mjs",  # mirrors it
}


def _env_write_sites() -> dict[str, str]:
    sites: dict[str, str] = {}
    for path in _iter_source_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in _ENV_WRITE_PATTERNS:
            match = pattern.search(text)
            if match:
                location = str(path.relative_to(REPO_ROOT))
                sites.setdefault(location, f"{location}:{_line_of(text, match.start())}")
                break
    return sites


def test_only_gated_writers_touch_the_environment() -> None:
    """A new reader must route through the gate, not add another surface."""
    sites = _env_write_sites()
    unexpected = sorted(set(sites) - _GATED_ENV_WRITERS)

    assert unexpected == [], (
        "these files write an environment name that could come from a parsed "
        f".env without going through the allow-list: "
        f"{[sites[name] for name in unexpected]}. Route the write through "
        "lib.env_allowlist.apply_env_entries (or mirror its policy and add the "
        "file to _GATED_ENV_WRITERS with a reason). An ungated writer on a "
        "shipped path exports LD_PRELOAD / BASH_ENV into every child process "
        "the pipeline spawns."
    )
    assert set(_GATED_ENV_WRITERS) <= set(sites), (
        "_GATED_ENV_WRITERS lists files that no longer write to the "
        f"environment: {sorted(set(_GATED_ENV_WRITERS) - set(sites))}. Drop "
        "them so the list keeps proving it is intentional."
    )


# Names and values a project .env must never be able to install. Each one is
# consumed by the shipped readers on a real path: LD_PRELOAD / BASH_ENV /
# BLENDER_PATH reach code execution in every spawned child, MINIMAX_BASE_URL is
# the host a credential-bearing request is sent to, and
# OPENMONTAGE_QUIET_ENV_WARNINGS silences the gate's own note.
_HOSTILE_ENV_PAIRS = (
    ("LD_PRELOAD", "/tmp/evil.so"),
    ("BASH_ENV", "/tmp/evil.sh"),
    ("PYTHONPATH", "/tmp/evil"),
    ("BLENDER_PATH", "/tmp/evil-blender"),
    ("MINIMAX_BASE_URL", "https://attacker.example"),
    ("OPENMONTAGE_QUIET_ENV_WARNINGS", "1"),
    ("FAL_KEY", "legit-key"),
)


def test_python_loaders_do_not_export_hostile_names(tmp_path) -> None:
    """Drive the SHIPPED reader, not the gate it is supposed to call.

    The gated-writer test above only asserts that a delegate is invoked, and the
    allow-list tests call apply_env_entries directly, so neither can see a
    module-level reader that was reverted to the pre-PR unfiltered loop. This
    executes the delivered import path with a hostile .env in place and asserts
    what actually reaches the environment.
    """
    import json
    import subprocess
    import sys

    (tmp_path / ".env").write_text(
        "".join(f"{key}={value}\n" for key, value in _HOSTILE_ENV_PAIRS)
    )
    names = sorted(key for key, _ in _HOSTILE_ENV_PAIRS)
    code = "\n".join(
        [
            "import json, os, sys",
            "for name in " + repr(names) + ":",
            "    os.environ.pop(name, None)",
            "sys.path.insert(0, " + repr(str(REPO_ROOT)) + ")",
            "from pathlib import Path",
            "from lib.env_loader import load_env",
            "import tools.base_tool",
            "load_env(Path(" + repr(str(tmp_path)) + "))",
            "print(json.dumps({n: os.environ.get(n) for n in " + repr(names) + "}))",
        ]
    )
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)

    assert res.returncode == 0, res.stderr
    exported = sorted(k for k, v in json.loads(res.stdout).items() if v)
    assert exported == ["FAL_KEY"], (
        "a shipped Python .env reader exported names a project .env must never "
        f"set: {exported}. Either the reader stopped delegating to "
        "apply_env_entries, or the gate itself was weakened."
    )


def _js_denied_env_keys() -> set[str]:
    """Denied names as they appear in the vendored JavaScript reader."""
    text = _JS_ENV_READER.read_text(encoding="utf-8")
    block = re.search(
        r"const DENIED_ENV_KEYS = new Set\(\[(.*?)\]\);", text, re.DOTALL
    )

    assert block, f"no DENIED_ENV_KEYS set found in {_JS_ENV_READER.name}"

    return set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', block.group(1)))


def test_js_env_reader_deny_list_matches_python() -> None:
    """The two copies of the deny-list must not drift apart."""
    js_keys = _js_denied_env_keys()

    # Pin the exact reviewed size so removing an entry fails CI instead of
    # letting both copies shrink together unnoticed (a gap a scanner found in
    # the earlier "len > 20" floor).
    assert len(DENIED_ENV_KEYS) == 60, (
        f"DENIED_ENV_KEYS changed size to {len(DENIED_ENV_KEYS)}; review the "
        "diff and bump this pin only after confirming every removed/added name "
        "is intentional."
    )
    assert len(js_keys) == len(DENIED_ENV_KEYS), "the JavaScript deny-list drifted in size"
    assert js_keys == set(DENIED_ENV_KEYS), (
        "the JavaScript media engine's .env reader and lib/env_allowlist.py "
        "disagree on which names a .env must never set: "
        f"only-in-js={sorted(js_keys - DENIED_ENV_KEYS)}, "
        f"only-in-python={sorted(set(DENIED_ENV_KEYS) - js_keys)}. "
        "The reader is vendored so the skill ships standalone, so the list is "
        "duplicated on purpose -- keep the two identical."
    )


def test_trust_redirection_keys_denied_both_sides() -> None:
    """Google trust-redirection names must never be honoured out of a .env.

    A hostile project .env must not be able to pick which service-account
    credential FILE is read (GOOGLE_APPLICATION_CREDENTIALS) or which HOST the
    minted Bearer token is sent to (GOOGLE_CLOUD_LOCATION -> Vertex request
    host). The earlier scan found both the Python and the vendored JS readers
    allow-listed these because they were copied verbatim from the project-wide
    key set; this pins the fix on both halves.
    """
    trust_redirection = (
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_PROJECT_ID",
        "GOOGLE_CLOUD_LOCATION",
        "GCLOUD_PROJECT",
    )
    for name in trust_redirection:
        assert name in DENIED_ENV_KEYS, (
            f"{name} must be in DENIED_ENV_KEYS (untrusted .env must not set it)"
        )
        assert not is_allowed_env_key(name), (
            f"{name} must be refused by the Python gate"
        )

    # And the JS copy must refuse them too (verified by executing the module).
    import subprocess

    leaked = ",".join(trust_redirection)
    script = (
        "import { isSafeEnvKey } from "
        f"'{_JS_ENV_READER.as_uri()}';\n"
        f"for (const n of {leaked!r}.split(',')) {{ "
        "if (isSafeEnvKey(n)) { console.error('LEAK:'+n); process.exit(1); } }\n"
        "process.exit(0);\n"
    )
    res = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, (
        "the JS reader still allow-lists a Google trust-redirection name: "
        f"rc={res.returncode} stderr={res.stderr}"
    )


_ENDPOINT_SELECTION_KEYS = (
    "MINIMAX_BASE_URL",
    "KLING_API_BASE_URL",
    "ARK_BASE_URL",
    "AZURE_SPEECH_ENDPOINT",
    "AZURE_TTS_ENDPOINT",
    "MODAL_LTX2_ENDPOINT_URL",
    "COMFYUI_SERVER_URL",
    "COMFYUI_IMAGE_SERVER_URL",
    "COMFYUI_VIDEO_SERVER_URL",
    "COMFYUI_MUSIC_SERVER_URL",
)


def test_endpoint_selection_keys_are_denied_both_sides() -> None:
    """Endpoint-override names must never be honoured out of a .env.

    Each of these selects the *host* a credential-bearing request (or a POST of
    the operator's own media) is sent to, so a hostile project .env that carries
    one harvests the paired provider key / private asset. The values are refused
    both by name (DENIED_ENV_KEYS) and by the endpoint-selection shape rule
    (_ENDPOINT_SELECTION_RE), so a future *_URL / *_HOST / *_ENDPOINT addition
    fails closed even before it is added to the list.
    """
    for name in _ENDPOINT_SELECTION_KEYS:
        assert name in DENIED_ENV_KEYS, f"{name} must be in DENIED_ENV_KEYS"
        assert not is_allowed_env_key(name), f"{name} must be refused by the gate"

    # The shape rule must also catch names not in the explicit list.
    for shape in ("SOME_NEW_URL", "ANY_ENDPOINT", "FOO_HOST", "MY_SERVER_ADDR"):
        assert not is_allowed_env_key(shape), (
            f"{shape} matches the endpoint-selection shape and must be refused"
        )

    import subprocess

    leaked = ",".join(_ENDPOINT_SELECTION_KEYS)
    script = (
        "import { isSafeEnvKey } from "
        f"'{_JS_ENV_READER.as_uri()}';\n"
        f"for (const n of {leaked!r}.split(',')) {{ "
        "if (isSafeEnvKey(n)) { console.error('LEAK:'+n); process.exit(1); } }\n"
        "process.exit(0);\n"
    )
    res = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, (
        "the JS reader still allow-lists an endpoint-selection name: "
        f"rc={res.returncode} stderr={res.stderr}"
    )


_SHELL_ONLY_KEYS = (
    "OPENMONTAGE_QUIET_ENV_WARNINGS",
    "HYPERFRAMES_QA",
    "HYPERFRAMES_QA_RENDER",
    "RUN_KLING_DOC_LIVE_CHECK",
)


def test_shell_only_keys_are_denied_both_sides() -> None:
    """Gate-control / QA switches must be set from the shell, never a .env.

    OPENMONTAGE_QUIET_ENV_WARNINGS silences the only operator-visible signal
    that a .env tried to set process-integrity variables; the QA switches flip
    how the in-repo test run executes. Both are reachable only through the
    untrusted file, so they are refused by the SHELL_ONLY_ENV_KEYS set on both
    readers (an operator's own shell export is untouched, because the loaders
    never override an existing variable).
    """
    for name in _SHELL_ONLY_KEYS:
        assert name in SHELL_ONLY_ENV_KEYS, f"{name} must be in SHELL_ONLY_ENV_KEYS"
        assert not is_allowed_env_key(name), f"{name} must be refused by the gate"

    import subprocess

    leaked = ",".join(_SHELL_ONLY_KEYS)
    script = (
        "import { isSafeEnvKey } from "
        f"'{_JS_ENV_READER.as_uri()}';\n"
        f"for (const n of {leaked!r}.split(',')) {{ "
        "if (isSafeEnvKey(n)) { console.error('LEAK:'+n); process.exit(1); } }\n"
        "process.exit(0);\n"
    )
    res = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, (
        "the JS reader still allow-lists a shell-only gate/QA name: "
        f"rc={res.returncode} stderr={res.stderr}"
    )


def test_shape_rule_precedence_matches_both_sides() -> None:
    """Both readers must refuse shape-rule names *unconditionally*.

    vuln-0004: an earlier regeneration gave the JS ``isSafeEnvKey`` an escape
    clause (``&& !ALLOWED_ENV_KEYS.has(key)``) on the executable/endpoint-shape
    checks, so a name re-added to ALLOWED_ENV_KEYS would have been honoured on
    the JS side while Python refused it -- a drift a value-parity test could not
    see. Both sides must refuse any name matching the shape rules regardless of
    the allow-list, and the JS source must not carry the escape clause.
    """
    from lib.env_allowlist import _ENDPOINT_SELECTION_RE, _EXECUTABLE_SELECTION_RE

    # Synthetic names that match the shape rules but are in neither list.
    shape_only = (
        "FOO_BAR_PATH",
        "SPAWNER_BIN",
        "RUNNER_CMD",
        "OWN_SHELL",
        "PLUGIN_EXEC",
        "WEBHOOK_URL",
        "API_ENDPOINT",
        "DB_SERVER_ADDR",
        "PROXY_HOST",
    )
    for name in shape_only:
        assert _EXECUTABLE_SELECTION_RE.search(name) or _ENDPOINT_SELECTION_RE.search(
            name
        ), f"{name} should match a shape rule (test setup)"
        assert not is_allowed_env_key(name), (
            f"{name} matches a shape rule and must be refused by the Python gate"
        )

    # The JS copy must refuse them too, and must NOT weaken the rule with an
    # allow-list escape clause that would re-open redirect-by-.env (vuln-0004).
    js_text = _JS_ENV_READER.read_text(encoding="utf-8")
    assert "&& !ALLOWED_ENV_KEYS.has(key)" not in js_text, (
        "the JS isSafeEnvKey still lets the allow-list override a shape rule; "
        "this re-opens redirect-by-.env on the JS side (vuln-0004 regression)"
    )

    import subprocess

    leaked = ",".join(shape_only)
    script = (
        "import { isSafeEnvKey } from "
        f"'{_JS_ENV_READER.as_uri()}';\n"
        f"for (const n of {leaked!r}.split(',')) {{ "
        "if (isSafeEnvKey(n)) { console.error('LEAK:'+n); process.exit(1); } }\n"
        "process.exit(0);\n"
    )
    res = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, (
        "the JS reader allow-lists a shape-rule name: "
        f"rc={res.returncode} stderr={res.stderr}"
    )


def test_heygen_config_dir_is_refused_and_contained() -> None:
    """HEYGEN_CONFIG_DIR must not be settable from a .env.

    The variable relocates the file the HeyGen engine reads as its credential;
    a hostile .env pointing it at an attacker-chosen directory would make the
    engine send that file's contents as X-Api-Key. The Python gate refuses it,
    and the vendored JS reader refuses it *and* contains an operator-set value
    to the home directory (credentialDir()).
    """
    assert not is_allowed_env_key("HEYGEN_CONFIG_DIR"), (
        "HEYGEN_CONFIG_DIR must be refused by the Python gate"
    )

    import subprocess

    # Refused out of .env on the JS side.
    refuse = subprocess.run(
        [
            "node",
            "--input-type=module",
            "-e",
            "import { isSafeEnvKey } from "
            f"'{_JS_ENV_READER.as_uri()}';\n"
            "process.exit(isSafeEnvKey('HEYGEN_CONFIG_DIR') ? 1 : 0);\n",
        ],
        capture_output=True,
        text=True,
    )
    assert refuse.returncode == 0, (
        "the JS reader still allow-lists HEYGEN_CONFIG_DIR: "
        f"rc={refuse.returncode} stderr={refuse.stderr}"
    )

    # An operator-set value outside the home directory is contained to ~/.heygen
    # (defense in depth; the .env path can never reach this branch).
    import tempfile, textwrap
    from pathlib import Path

    loot = Path(tempfile.mkdtemp(prefix="heygen-loot-")) / "credentials"
    loot.write_text("attacker-chosen-value\n")
    contain = subprocess.run(
        [
            "node",
            "--input-type=module",
            "-e",
            textwrap.dedent(
                f"""
                import {{ credentialDir }} from '{_JS_ENV_READER.as_uri()}';
                process.env.HEYGEN_CONFIG_DIR = {str(loot.parent)!r};
                process.exit(credentialDir().endsWith('.heygen') ? 0 : 1);
                """
            ),
        ],
        capture_output=True,
        text=True,
    )
    assert contain.returncode == 0, (
        "credentialDir() did not contain an out-of-home HEYGEN_CONFIG_DIR: "
        f"rc={contain.returncode} stderr={contain.stderr}"
    )


def test_shipped_js_reader_does_not_export_hostile_names(tmp_path) -> None:
    """Drive loadEnvFromDir, not isSafeEnvKey: the write path is the sink.

    The tests above execute isSafeEnvKey in isolation, so a reader whose writer
    stopped calling it still reports a correct policy. This runs the shipped
    reader against a hostile .env and asserts what actually reaches process.env,
    which is the signal the engine's children inherit.
    """
    import json
    import subprocess

    pairs = (
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("BASH_ENV", "/tmp/evil.sh"),
        ("NODE_OPTIONS", "--require /tmp/evil.js"),
        ("PYTHONPATH", "/tmp/evil"),
        ("BLENDER_PATH", "/tmp/evil-blender"),
        ("MINIMAX_BASE_URL", "https://attacker.example"),
        ("OPENMONTAGE_QUIET_ENV_WARNINGS", "1"),
        ("FAL_KEY", "legit-key"),
    )
    (tmp_path / ".env").write_text("".join(f"{k}={v}\n" for k, v in pairs))
    refused = sorted(k for k, _ in pairs if k != "FAL_KEY")

    script = (
        "import { loadEnvFromDir } from " + json.dumps(_JS_ENV_READER.as_uri()) + ";\n"
        "for (const n of " + json.dumps(refused) + ") delete process.env[n];\n"
        "loadEnvFromDir(" + json.dumps(str(tmp_path)) + ");\n"
        "console.log(JSON.stringify(" + json.dumps(refused) + ".filter((n) => n in process.env)));\n"
    )
    res = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
    )

    assert res.returncode == 0, res.stderr
    assert json.loads(res.stdout) == [], (
        "loadEnvFromDir exported names a project .env must never set: "
        f"{json.loads(res.stdout)}. The reader stopped applying isSafeEnvKey "
        "before the write, so a .env that travels with a cloned repository "
        "reaches every child the media engine spawns."
    )


def test_js_env_reader_allow_list_matches_python() -> None:
    """The JS reader must enforce the same allow-list, not just a deny-list.

    A deny-list-only reader is allow-by-default: any name the deny-list forgot
    is exported, including process-integrity names -- the exact shape of the
    LD_PRELOAD gap. The two copies of ALLOWED_ENV_KEYS must therefore stay
    identical, or the vendored JS media engine silently becomes a way around
    the Python gate that the loaders enforce.
    """
    text = _JS_ENV_READER.read_text(encoding="utf-8")
    block = re.search(
        r"const ALLOWED_ENV_KEYS = new Set\(\[(.*?)\]\);", text, re.DOTALL
    )

    assert block, f"no ALLOWED_ENV_KEYS set found in {_JS_ENV_READER.name}"

    js_keys = set(re.findall(r"""["']([A-Za-z_][A-Za-z0-9_]*)["']""", block.group(1)))

    assert len(ALLOWED_ENV_KEYS) == 54, (
        f"ALLOWED_ENV_KEYS changed size to {len(ALLOWED_ENV_KEYS)}; review the "
        "diff and bump this pin only after confirming every removed/added name "
        "is intentional."
    )
    assert len(js_keys) == len(ALLOWED_ENV_KEYS), "the JavaScript allow-list drifted in size"
    assert js_keys == set(ALLOWED_ENV_KEYS), (
        "the JavaScript media engine's .env reader and lib/env_allowlist.py "
        "disagree on which names a .env may export: "
        f"only-in-js={sorted(js_keys - ALLOWED_ENV_KEYS)}, "
        f"only-in-python={sorted(set(ALLOWED_ENV_KEYS) - js_keys)}. "
        "The reader is vendored so the skill ships standalone, so the list is "
        "duplicated on purpose -- keep the two identical."
    )


def test_js_env_reader_is_allow_list_by_default_deny() -> None:
    """The JS reader must drop names outside the allow-list, not export them.

    This is the regression behind the earlier 7/7 process-integrity leak: a
    deny-list-only reader exported every name it forgot. ``isSafeEnvKey`` must
    return True only for allow-listed names, so a hostile ``.env`` carrying a
    process-integrity name the deny-list omitted is dropped. Verified by
    actually executing the module under node, not by reading its source.
    """
    import subprocess

    script = (
        "import { isSafeEnvKey } from "
        f"'{_JS_ENV_READER.as_uri()}';\n"
        "const leaked = ['PYTHONWARNINGS','PYTHONEXECUTABLE','PERL5OPT',"
        "'GCONV_PATH','OPENSSL_CONF','CC','MAKEFLAGS'];\n"
        "for (const n of leaked) { if (isSafeEnvKey(n)) { "
        "console.error('LEAK:'+n); process.exit(1); } }\n"
        "if (!isSafeEnvKey('FAL_KEY') || !isSafeEnvKey('HEYGEN_API_KEY')) { "
        "console.error('MISSING-LEGIT-KEY'); process.exit(2); }\n"
        "process.exit(0);\n"
    )
    res = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, (
        "isSafeEnvKey did not enforce allow-list-by-default-deny: "
        f"rc={res.returncode} stderr={res.stderr}"
    )


def test_js_env_reader_rejects_the_bash_func_prefix() -> None:
    """Shell-function smuggling is refused on the JS path too."""
    text = _JS_ENV_READER.read_text(encoding="utf-8")

    assert '"BASH_FUNC_"' in text, (
        "the JavaScript reader no longer rejects the BASH_FUNC_ prefix, so "
        "BASH_FUNC_x%%=... smuggles a shell function into every bash child"
    )
    assert "isSafeEnvKey" in text, "the JavaScript reader no longer gates writes"


def test_js_rejected_note_sanitizes_control_bytes() -> None:
    """The JS rejected-key note must not echo raw terminal control bytes.

    A ``.env`` key name that fails the gate (e.g. one carrying ESC/BEL/bidi)
    must be sanitised to printable ASCII before it is written to stderr,
    otherwise a hostile ``.env`` can forge a status line or hijack the terminal
    title (CWE-117). Verified by executing ``loadEnvFromDir`` under node against
    a crafted ``.env`` whose rejected line carries control bytes.
    """
    import subprocess
    import tempfile
    from pathlib import Path as _Path

    root = _Path(tempfile.mkdtemp())
    (root / ".env").write_text(
        "\x1b[2K\x1b[32m[ok] credential scan passed\x1b[0m=1\n"
        "PAYLOAD\x07\x1b]0;owned\x07=x\n"
        "HEYGEN_API_KEY=legit-key\n"
    )

    script = (
        "import { loadEnvFromDir } from "
        f"'{_JS_ENV_READER.as_uri()}';\n"
        "delete process.env.HEYGEN_API_KEY;\n"
        f"loadEnvFromDir({str(root)!r});\n"
        "if (process.env.HEYGEN_API_KEY !== 'legit-key') { "
        "console.error('LEGIT-KEY-NOT-APPLIED'); process.exit(2); }\n"
        "process.exit(0);\n"
    )
    res = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, (
        f"loadEnvFromDir rejected a valid key: rc={res.returncode} "
        f"stderr={res.stderr}"
    )
    # The forged status line must not survive as control bytes in the report.
    assert "\x1b" not in res.stderr, "ESC byte leaked into the JS rejected-key note"
    assert "\x07" not in res.stderr, "BEL byte leaked into the JS rejected-key note"


def test_rejected_key_report_is_not_a_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The diagnostic must survive warnings-as-errors.

    It is emitted from module scope during `import tools.base_tool`. If it went
    through `warnings.warn`, a .env with one unrecognised key would make that
    import raise under -W error / PYTHONWARNINGS=error, and abort pytest at
    collection with no tests run.
    """
    import warnings as warnings_module

    import lib.env_allowlist as env_allowlist

    monkeypatch.delenv("OPENMONTAGE_QUIET_ENV_WARNINGS", raising=False)
    monkeypatch.setattr(env_allowlist, "_REPORTED_REJECTED_KEYS", set())
    with warnings_module.catch_warnings():
        warnings_module.simplefilter("error")

        # Must not raise.
        env_allowlist.warn_rejected_keys(["NOT_ALLOW_LISTED_KEY"])


def test_rejected_key_report_can_be_silenced(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import lib.env_allowlist as env_allowlist

    monkeypatch.setenv("OPENMONTAGE_QUIET_ENV_WARNINGS", "1")
    monkeypatch.setattr(env_allowlist, "_REPORTED_REJECTED_KEYS", set())

    env_allowlist.warn_rejected_keys(["SILENCED_UNLISTED_KEY"])

    assert capsys.readouterr().err == ""


def test_rejected_key_report_names_the_dropped_keys(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import lib.env_allowlist as env_allowlist

    monkeypatch.delenv("OPENMONTAGE_QUIET_ENV_WARNINGS", raising=False)
    monkeypatch.setattr(env_allowlist, "_REPORTED_REJECTED_KEYS", set())

    env_allowlist.warn_rejected_keys(["SITE_LOCAL_UNLISTED_KEY"])

    assert "SITE_LOCAL_UNLISTED_KEY" in capsys.readouterr().err


def test_rejected_key_report_does_not_repeat_itself(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Three entry points load the same .env; report each name once."""
    import lib.env_allowlist as env_allowlist

    monkeypatch.delenv("OPENMONTAGE_QUIET_ENV_WARNINGS", raising=False)
    monkeypatch.setattr(env_allowlist, "_REPORTED_REJECTED_KEYS", set())

    env_allowlist.warn_rejected_keys(["REPEATED_UNLISTED_KEY"])
    env_allowlist.warn_rejected_keys(["REPEATED_UNLISTED_KEY"])

    assert capsys.readouterr().err.count("REPEATED_UNLISTED_KEY") == 1



