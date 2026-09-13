"""Allow-list gating for values read from a project ``.env`` file.

Three Python entry points load the project ``.env`` and copy its entries into
``os.environ``:

* ``tools.base_tool._load_dotenv`` -- runs at import time.
* ``tools.tool_registry.ToolRegistry._load_dotenv`` -- runs on ``discover()``.
* ``lib.env_loader.load_env`` -- used by scripts and QA tests.

A ``.env`` file can arrive from a cloned repository, an imported project bundle
or any other source the operator does not fully control, so its contents are
untrusted input. Copying a ``.env`` entry straight into ``os.environ`` hands
that input control over every child process the pipeline spawns:

* ``LD_PRELOAD`` / ``DYLD_INSERT_LIBRARIES`` -- native code loaded into ffmpeg,
  node, Blender and Python children.
* ``BASH_ENV`` -- shell code executed by every non-interactive bash child.
* ``PYTHONPATH`` / ``NODE_OPTIONS`` -- arbitrary modules executed by
  interpreters that inherit the environment.
* ``PATH`` / ``IFS`` / ``HOME`` -- redirect which binaries are found and where
  credentials get looked up.

None of those names belong to this project's configuration surface, so a
``.env`` must never be able to set them.

``ALLOWED_ENV_KEYS`` is the surface the code actually reads: every key
documented in ``.env.example`` plus the additional keys read directly from the
environment elsewhere in the tree. ``DENIED_ENV_KEYS`` is a second, narrower
gate that keeps the process-integrity keys out even if one is ever added to the
allow-list by mistake -- the allow-list stays the primary defence.

Scope: this module gates the Python loaders listed above. The JavaScript media
engine has a fourth reader with its own parser --
``loadEnvFromDir()`` in
``.agents/skills/hyperframes-media/scripts/lib/heygen.mjs`` -- which cannot
import this module because that skill is vendored to ship standalone. It
applies the same ``DENIED_ENV_KEYS`` policy plus the same key-shape rule, and
``tests/contracts/test_env_allowlist.py`` fails if the two copies drift apart or
if any other file starts writing a parsed ``.env`` into the environment.

``tests/contracts/test_env_allowlist.py`` also enforces both halves of the
allow-list claim: it checks the allow-list against ``.env.example`` *and*
statically collects every environment name the tree resolves, so a miss fails
CI instead of silently dropping configuration at runtime.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Iterable, List, Set, Tuple

# --- Image / video generation ------------------------------------------------
_IMAGE_VIDEO_KEYS = frozenset(
    {
        "FAL_KEY",  # fal.ai gateway (FLUX images, Veo/Kling/MiniMax video)
        "FAL_AI_API_KEY",  # alias for FAL_KEY
        # Atlas Cloud (atlas_image / atlas_video / atlas_3d). tools/atlas_client.py
        # and tools/graphics/atlas_3d.py walk this alias chain in order, and the
        # atlas tools declare "env:ATLASCLOUD_API_KEY" as a dependency, so
        # dropping any of the three disables the provider without a diagnostic.
        "ATLASCLOUD_API_KEY",
        "ATLAS_CLOUD_API_KEY",
        "ATLAS_API_KEY",
        "MINIMAX_API_KEY",
        "MINIMAX_REGION",
        "MINIMAX_BASE_URL",
        "REPLICATE_API_TOKEN",
        "HIGGSFIELD_API_KEY",
        "HIGGSFIELD_API_SECRET",
        "HIGGSFIELD_KEY",  # combined "<key>:<secret>" form
        "KLING_API_KEY",
        "KLING_API_BASE_URL",
        "BFL_API_KEY",
        "COVERR_API_KEY",
        "NARA_API_KEY",
        "POND5_API_KEY",
        "VIDEVO_API_KEY",
        "HYPERFRAMES_API_KEY",
        "HEYGEN_API_KEY",
        "HEYGEN_CONFIG_DIR",
        "RUNWAY_API_KEY",
        "RUNWAYML_API_SECRET",
        "ARK_API_KEY",
        "ARK_BASE_URL",
        "ARK_SEEDANCE_MODEL",
        "ARK_CNY_PER_USD",
        "VOLC_ACCESSKEY",
        "VOLC_SECRETKEY",
        "MODAL_LTX2_ENDPOINT_URL",
        "VIDEO_GEN_LOCAL_ENABLED",
        "VIDEO_GEN_LOCAL_MODEL",
        "COMFYUI_SERVER_URL",
        # Per-capability overrides for split-GPU ComfyUI setups. The names are
        # assembled at runtime in tools/_comfyui/client.py
        # (COMFYUI_<CAPABILITY>_SERVER_URL), so a literal scan cannot see them;
        # keep this set aligned with per_capability_env_var_overrides in
        # tools/_comfyui/metadata.py, which the contract test reads as the
        # authoritative list.
        "COMFYUI_IMAGE_SERVER_URL",
        "COMFYUI_VIDEO_SERVER_URL",
        "COMFYUI_MUSIC_SERVER_URL",
    }
)

# --- Google / Gemini ---------------------------------------------------------
_GOOGLE_KEYS = frozenset(
    {
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",  # alias for GOOGLE_API_KEY
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_PROJECT_ID",
        "GOOGLE_CLOUD_LOCATION",
        "GOOGLE_GENAI_USE_ENTERPRISE",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "GOOGLE_TTS_API_KEY",
        "GCLOUD_PROJECT",
    }
)

# --- Voice / speech / LLM ----------------------------------------------------
_VOICE_KEYS = frozenset(
    {
        "ELEVENLABS_API_KEY",
        "OPENAI_API_KEY",
        "XAI_API_KEY",
        "DOUBAO_SPEECH_API_KEY",
        "DOUBAO_SPEECH_VOICE_TYPE",
        "FISH_AUDIO_API_KEY",
        "DASHSCOPE_API_KEY",
        "TENCENT_TOKENHUB_API_KEY",
        "AZURE_SPEECH_KEY",
        "AZURE_SPEECH_REGION",
        "AZURE_SPEECH_ENDPOINT",
        "AZURE_TTS_ENDPOINT",
        "HF_TOKEN",
    }
)

# --- Music / stock media -----------------------------------------------------
_MEDIA_LIBRARY_KEYS = frozenset(
    {
        "SUNO_API_KEY",
        "PEXELS_API_KEY",
        "PIXABAY_API_KEY",
        "UNSPLASH_ACCESS_KEY",
        "FREESOUND_API_KEY",
    }
)

# --- Local tooling and storage paths ----------------------------------------
_LOCAL_TOOLING_KEYS = frozenset(
    {
        "BACKLOT_PORT",
        "BLENDER_PATH",
        "MUSIC_LIBRARY_DIR",
        "OPENMONTAGE_CACHE_DIR",
        "OPENMONTAGE_CACHE_MAX_GB",
        "OPENMONTAGE_PROJECTS_DIR",
        # Silences the "ignored .env keys" note (see warn_rejected_keys).
        "OPENMONTAGE_QUIET_ENV_WARNINGS",
        "SADTALKER_PATH",
        "WAV2LIP_PATH",
    }
)

# --- QA harness switches -----------------------------------------------------
_QA_HARNESS_KEYS = frozenset(
    {
        "HYPERFRAMES_QA",
        "HYPERFRAMES_QA_RENDER",
        "RUN_KLING_DOC_LIVE_CHECK",
    }
)

ALLOWED_ENV_KEYS = frozenset(
    _IMAGE_VIDEO_KEYS
    | _GOOGLE_KEYS
    | _VOICE_KEYS
    | _MEDIA_LIBRARY_KEYS
    | _LOCAL_TOOLING_KEYS
    | _QA_HARNESS_KEYS
)

# Process-integrity names that must never be honoured, whatever the allow-list
# says. These are the variables that turn "read a config file" into "run
# attacker-supplied code in every child process".
DENIED_ENV_KEYS = frozenset(
    {
        # Dynamic loader / injected libraries.
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        # Shell startup hooks.
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "PROMPT_COMMAND",
        "IFS",
        # Interpreter search paths and startup hooks.
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "NODE_PATH",
        "NODE_EXTRA_CA_CERTS",
        "PERL5LIB",
        "RUBYLIB",
        "CLASSPATH",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        # Process and session basics.
        "PATH",
        "HOME",
        "TMPDIR",
        "PWD",
        "OLDPWD",
        "SHELL",
        "USER",
        "LOGNAME",
        # Credential and trust-store redirection.
        "SSH_AUTH_SOCK",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "PIP_CONFIG_FILE",
        "PIP_INDEX_URL",
    }
)

# Bash exports shell functions as BASH_FUNC_<name>%%; never honour those.
_BASH_FUNC_PREFIX = "BASH_FUNC_"

_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

# Rejected names already reported, so the three entry points together produce
# one note per key per process instead of repeating it on every load.
_REPORTED_REJECTED_KEYS: Set[str] = set()


def is_allowed_env_key(key: str) -> bool:
    """Return True only for keys this project deliberately reads from ``.env``."""
    if key in DENIED_ENV_KEYS or key.startswith(_BASH_FUNC_PREFIX):
        return False
    return key in ALLOWED_ENV_KEYS


def parse_dotenv(text: str) -> List[Tuple[str, str]]:
    """Parse ``KEY=value`` lines into pairs.

    Semantics are kept identical to the loader that used to live in
    ``tools/base_tool.py``: unquoted values lose an inline ``#`` comment,
    quoted values are taken verbatim, blank lines and comments are skipped.
    """
    pairs: List[Tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if value[:1] in ("'", '"'):
            quote = value[0]
            end = value.find(quote, 1)
            value = value[1:end] if end != -1 else value[1:]
        else:
            # Strip an inline comment ('#' at line start or after whitespace) so
            # "VAR=   # note" yields "" rather than "# note".
            match = re.search(r"(^|\s)#", value)
            if match:
                value = value[: match.start()]
            value = value.strip()
        if key and _KEY_RE.match(key):
            pairs.append((key, value))
    return pairs


def apply_env_entries(
    pairs: Iterable[Tuple[str, str]],
    *,
    override: bool = False,
    warn: bool = True,
) -> Tuple[List[str], List[str]]:
    """Write allow-listed pairs into ``os.environ``.

    Returns ``(applied, rejected)``. Keys outside the allow-list are dropped
    rather than exported, and (when ``warn``) reported once so an operator who
    put a custom variable in ``.env`` can see why it had no effect.
    """
    applied: List[str] = []
    rejected: List[str] = []
    for key, value in pairs:
        if not is_allowed_env_key(key):
            rejected.append(key)
            continue
        if override or key not in os.environ:
            os.environ[key] = value
            applied.append(key)
    if warn:
        warn_rejected_keys(rejected)
    return applied, rejected


def warn_rejected_keys(rejected: Iterable[str]) -> None:
    """Report dropped keys once per process, with a hint on how one is added.

    Deliberately *not* ``warnings.warn``. This is a note about configuration
    lines that were ignored, and the primary caller runs at module scope in
    ``tools/base_tool.py``. Under ``-W error`` / ``PYTHONWARNINGS=error`` a
    warning is raised as an exception, which made importing the tool package
    abort the caller and stopped pytest at collection with no tests run -- a
    line in ``.env`` must never be able to do that. Writing to stderr keeps the
    note visible and immune to warning filters; set
    ``OPENMONTAGE_QUIET_ENV_WARNINGS=1`` to silence it.
    """
    if os.environ.get("OPENMONTAGE_QUIET_ENV_WARNINGS") == "1":
        return
    unique = sorted(set(rejected) - _REPORTED_REJECTED_KEYS)
    if not unique:
        return
    _REPORTED_REJECTED_KEYS.update(unique)
    shown = ", ".join(unique[:10])
    suffix = f" (+{len(unique) - 10} more)" if len(unique) > 10 else ""
    print(
        "! ignored .env keys outside the OpenMontage allow-list: "
        f"{shown}{suffix}. Add the variable to lib/env_allowlist.py if the "
        "project is meant to read it.",
        file=sys.stderr,
    )
