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
        # MINIMAX_BASE_URL is NOT here on purpose: see the endpoint-selection
        # note in DENIED_ENV_KEYS. Its value is the *host* the request is sent
        # to, and that request carries "Authorization: Bearer $MINIMAX_API_KEY"
        # (tools/graphics/minimax_image.py), so a .env must never pick it.
        "REPLICATE_API_TOKEN",
        "HIGGSFIELD_API_KEY",
        "HIGGSFIELD_API_SECRET",
        "HIGGSFIELD_KEY",  # combined "<key>:<secret>" form
        "KLING_API_KEY",
        # KLING_API_BASE_URL is NOT here on purpose (see DENIED_ENV_KEYS):
        # tools/_kling/client.py sends "Authorization: Bearer $KLING_API_KEY"
        # to whatever host it names.
        "BFL_API_KEY",
        "COVERR_API_KEY",
        "NARA_API_KEY",
        "POND5_API_KEY",
        "VIDEVO_API_KEY",
        "HYPERFRAMES_API_KEY",
        "HEYGEN_API_KEY",
        # HEYGEN_CONFIG_DIR is NOT here on purpose: see the config-dir note in
        # DENIED_ENV_KEYS. Its value relocates the file the engine reads as its
        # HeyGen credential, so a .env must never pick it.
        "RUNWAY_API_KEY",
        "RUNWAYML_API_SECRET",
        "ARK_API_KEY",
        # ARK_BASE_URL is NOT here on purpose (see DENIED_ENV_KEYS):
        # tools/video/seedance_ark.py sends "Authorization: Bearer $ARK_API_KEY"
        # to the host it names (https-only, but any https host still receives
        # the key).
        "ARK_SEEDANCE_MODEL",
        "ARK_CNY_PER_USD",
        "VOLC_ACCESSKEY",
        "VOLC_SECRETKEY",
        # MODAL_LTX2_ENDPOINT_URL is NOT here on purpose (see DENIED_ENV_KEYS):
        # tools/video/_shared.py POSTs the operator's own reference image to it.
        "VIDEO_GEN_LOCAL_ENABLED",
        "VIDEO_GEN_LOCAL_MODEL",
        # COMFYUI_SERVER_URL and the COMFYUI_<CAPABILITY>_SERVER_URL family are
        # NOT here on purpose (see DENIED_ENV_KEYS): tools/_comfyui/client.py
        # POSTs the operator's own images to whichever server they name. The
        # runtime-assembled per-capability names (COMFYUI_<CAPABILITY>_SERVER_URL)
        # are still covered by the endpoint-selection shape rule in
        # is_allowed_env_key, so this set no longer needs to track them by hand.
    }
)

# --- Google / Gemini ---------------------------------------------------------
_GOOGLE_KEYS = frozenset(
    {
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",  # alias for GOOGLE_API_KEY
        "GOOGLE_GENAI_USE_ENTERPRISE",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "GOOGLE_TTS_API_KEY",
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
        # AZURE_SPEECH_ENDPOINT / AZURE_TTS_ENDPOINT are NOT here on purpose
        # (see DENIED_ENV_KEYS): tools/analysis/azure_stt.py and
        # tools/audio/azure_tts.py send "Ocp-Apim-Subscription-Key:
        # $AZURE_SPEECH_KEY" to whichever host they name. AZURE_SPEECH_REGION
        # stays allow-listed because it selects a fixed
        # *.api.cognitive.microsoft.com host owned by Microsoft.
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
        "MUSIC_LIBRARY_DIR",
        "OPENMONTAGE_CACHE_DIR",
        "OPENMONTAGE_CACHE_MAX_GB",
        "OPENMONTAGE_PROJECTS_DIR",
        # BLENDER_PATH / SADTALKER_PATH / WAV2LIP_PATH are NOT here on purpose:
        # their values are the *program* a tool spawns (argv[0]), not a config
        # string, so a .env line for one of them is remote-code-execution. They
        # live in DENIED_ENV_KEYS instead (see the executable-selection note
        # there) and are therefore never honoured out of a project .env.
    }
)

# Names the operator may export but a project .env must never set. These are
# read by code that decides how this process behaves rather than by a tool as
# configuration: a .env that can silence the rejected-key note below, or flip a
# QA switch that lives in the same process as the test run, is a file control
# over the gate it is being measured against. The loaders never override an
# existing variable (setdefault), so an operator's own shell export is
# unaffected -- only the untrusted .env override path is closed.
SHELL_ONLY_ENV_KEYS = frozenset(
    {
        # Suppression switch for warn_rejected_keys(). A .env that sets it hides
        # the note that would otherwise tell the operator the file was tampered
        # with, so it must be honoured from the operator's shell only.
        "OPENMONTAGE_QUIET_ENV_WARNINGS",
        # Per-invocation harness arguments, not project configuration.
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
)

# Process-integrity names that must never be honoured, whatever the allow-list
# says. These are the variables that turn "read a config file" into "run
# attacker-supplied code in every child process".
DENIED_ENV_KEYS = frozenset(
    {
        # Executable selection. These names are consumed as the program to run
        # (argv[0]) rather than as configuration, so honouring one out of a .env
        # lets the file's author choose what the pipeline executes:
        #   tools/graphics/blender_world.py   -> BLENDER_PATH
        #   tools/avatar/talking_head.py      -> SADTALKER_PATH
        #   tools/avatar/lip_sync.py          -> WAV2LIP_PATH
        # Keeping them denied means a future allow-list edit cannot reintroduce
        # the redirect; operators who genuinely need them export their own shell.
        "BLENDER_PATH",
        "SADTALKER_PATH",
        "WAV2LIP_PATH",
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
        # Google trust redirection. A project .env is untrusted input, so it must
        # never choose which service-account credential FILE is read
        # (GOOGLE_APPLICATION_CREDENTIALS -> tools/google_credentials.py reads it
        # unvalidated) or which host the minted Bearer token is sent to
        # (GOOGLE_CLOUD_LOCATION is interpolated into the Vertex request host in
        # tools/graphics/google_imagen.py). The two project-id aliases select
        # which project the token is used against. Operators set these in their
        # own shell, where the loaders never override them (setdefault).
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_PROJECT_ID",
        "GOOGLE_CLOUD_LOCATION",
        "GCLOUD_PROJECT",
        # Endpoint selection. These names are consumed as the *host* a request
        # is sent to, and the request carries one of the project's credentials
        # or the operator's own media. Honouring one out of a project .env lets
        # the file's author choose where a secret or a private asset is
        # delivered, the same rule that keeps GOOGLE_CLOUD_LOCATION out of the
        # allow-list:
        #   tools/graphics/minimax_image.py -> MINIMAX_BASE_URL, sent with
        #     "Authorization: Bearer $MINIMAX_API_KEY"
        #   tools/_kling/client.py -> KLING_API_BASE_URL, sent with
        #     "Authorization: Bearer $KLING_API_KEY"
        #   tools/video/seedance_ark.py -> ARK_BASE_URL (https-only, but an
        #     attacker-controlled https host still receives "$ARK_API_KEY")
        #   tools/analysis/azure_stt.py + tools/audio/azure_tts.py ->
        #     AZURE_SPEECH_ENDPOINT / AZURE_TTS_ENDPOINT, sent with
        #     "Ocp-Apim-Subscription-Key: $AZURE_SPEECH_KEY"
        #   tools/video/_shared.py -> MODAL_LTX2_ENDPOINT_URL, which POSTs the
        #     operator's reference image to the chosen endpoint
        #   tools/_comfyui/client.py -> COMFYUI_SERVER_URL and the
        #     COMFYUI_<CAPABILITY>_SERVER_URL family, which POST the operator's
        #     local images to the chosen server
        # Operators who need an override export it in their own shell, where
        # the loaders never replace it.
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
    }
)

# Bash exports shell functions as BASH_FUNC_<name>%%; never honour those.
_BASH_FUNC_PREFIX = "BASH_FUNC_"

_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

# Executable-selection shape: a name ending in _PATH or containing _EXEC / _BIN
# / _CMD / _SHELL / _RUNNER is conventionally a program the tool spawns. A .env
# must never be able to pick which binary runs, so fail closed on this shape
# before the allow-list is consulted. Operators set these in their own shell,
# where the loaders never override them.
_EXECUTABLE_SELECTION_RE = re.compile(r"_PATH$|_EXEC|_BIN|_CMD|_SHELL|_RUNNER", re.IGNORECASE)

# Endpoint-selection shape: a name ending in _URL / _ENDPOINT / _SERVER_ADDR /
# _HOST conventionally names the recipient of a request, and that request
# usually carries a credential or the operator's own media. Fail closed on the
# shape before the allow-list is consulted, so re-adding one of these names to
# ALLOWED_ENV_KEYS cannot reintroduce the redirect. Operators set these in
# their own shell, where the loaders never replace them.
_ENDPOINT_SELECTION_RE = re.compile(r"_URL$|_ENDPOINT$|_SERVER_ADDR$|_HOST$", re.IGNORECASE)

# Rejected names already reported, so the three entry points together produce
# one note per key per process instead of repeating it on every load.
_REPORTED_REJECTED_KEYS: Set[str] = set()


def is_allowed_env_key(key: str) -> bool:
    """Return True only for keys this project deliberately reads from ``.env``."""
    if key in DENIED_ENV_KEYS or key.startswith(_BASH_FUNC_PREFIX):
        return False
    if key in SHELL_ONLY_ENV_KEYS:
        return False
    if _EXECUTABLE_SELECTION_RE.search(key):
        return False
    if _ENDPOINT_SELECTION_RE.search(key):
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
        # A NUL byte cannot be represented in a process environment: CPython
        # raises ValueError from ``os.environ[key] = value``, and os.putenv /
        # execve do the same. A .env line must never be able to abort the caller
        # -- ``_load_dotenv()`` runs at module scope in tools/base_tool.py, so an
        # uncaught raise here would turn one corrupt-looking byte into a failed
        # ``import tools.base_tool``. The vendored JS reader truncates at the NUL
        # instead of throwing, so drop the entry and report it like any other
        # refused key to keep the two readers consistent.
        if "\x00" in value:
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
