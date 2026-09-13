// heygen.mjs — vendored HeyGen REST helpers (auth + transport) for the audio
// pipeline. The credential resolver is copied from hyperframes-media's
// heygen-tts.mjs (and matches the hyperframes CLI auth): first usable source
// wins — $HEYGEN_API_KEY / $HYPERFRAMES_API_KEY → a nearby .env → ~/.heygen/
// credentials (oauth → Bearer, else api_key → X-Api-Key; $HEYGEN_CONFIG_DIR
// overrides the dir). Vendored so the skill ships standalone. Pure node.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";

export const HEYGEN_BASE = "https://api.heygen.com/v3";

// Process-integrity names a .env must never be able to set.
//
// A .env is untrusted input: it can arrive with a cloned repository, an
// imported project bundle or a shared template. These names decide which
// libraries, shell startup files and interpreter options every child the media
// engine spawns (python3, node, ffmpeg) picks up, so honouring one out of a
// .env hands the file's author code execution in those children.
//
// This mirrors DENIED_ENV_KEYS in lib/env_allowlist.py, which the Python
// loaders (tools/base_tool.py, tools/tool_registry.py, lib/env_loader.py)
// enforce. The list is inlined rather than imported because this file is
// vendored so the skill ships standalone; tests/contracts/test_env_allowlist.py
// fails if the two copies drift apart.
const DENIED_ENV_KEYS = new Set([
  "ARK_BASE_URL",
  "AZURE_SPEECH_ENDPOINT",
  "AZURE_TTS_ENDPOINT",
  "BASHOPTS",
  "BASH_ENV",
  "BLENDER_PATH",
  "CLASSPATH",
  "COMFYUI_IMAGE_SERVER_URL",
  "COMFYUI_MUSIC_SERVER_URL",
  "COMFYUI_SERVER_URL",
  "COMFYUI_VIDEO_SERVER_URL",
  "CURL_CA_BUNDLE",
  "DYLD_FRAMEWORK_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "ENV",
  "GCLOUD_PROJECT",
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_SYSTEM",
  "GIT_SSH",
  "GIT_SSH_COMMAND",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GOOGLE_CLOUD_LOCATION",
  "GOOGLE_CLOUD_PROJECT",
  "GOOGLE_CLOUD_PROJECT_ID",
  "HOME",
  "IFS",
  "JAVA_TOOL_OPTIONS",
  "KLING_API_BASE_URL",
  "LD_AUDIT",
  "LD_LIBRARY_PATH",
  "LD_PRELOAD",
  "LOGNAME",
  "MINIMAX_BASE_URL",
  "MODAL_LTX2_ENDPOINT_URL",
  "NODE_EXTRA_CA_CERTS",
  "NODE_OPTIONS",
  "NODE_PATH",
  "OLDPWD",
  "PATH",
  "PERL5LIB",
  "PIP_CONFIG_FILE",
  "PIP_INDEX_URL",
  "PROMPT_COMMAND",
  "PWD",
  "PYTHONHOME",
  "PYTHONPATH",
  "PYTHONSTARTUP",
  "REQUESTS_CA_BUNDLE",
  "RUBYLIB",
  "SADTALKER_PATH",
  "SHELL",
  "SHELLOPTS",
  "SSH_AUTH_SOCK",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "TMPDIR",
  "USER",
  "WAV2LIP_PATH",
  "_JAVA_OPTIONS",
]);

const SHELL_ONLY_ENV_KEYS = new Set([
  "HYPERFRAMES_QA",
  "HYPERFRAMES_QA_RENDER",
  "OPENMONTAGE_QUIET_ENV_WARNINGS",
  "RUN_KLING_DOC_LIVE_CHECK",
]);




// Bash exports shell functions as BASH_FUNC_<name>%%; never honour those.
const BASH_FUNC_PREFIX = "BASH_FUNC_";

// Key-shape rule, matching _KEY_RE in lib/env_allowlist.py.
const SAFE_ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

// Allow-list: names a project .env may export. Mirrors ALLOWED_ENV_KEYS in
// lib/env_allowlist.py (enforced by the Python loaders). A .env is untrusted
// input, so the policy is allow-list by default-deny: anything not on this
// list is dropped, not exported. tests/contracts/test_env_allowlist.py fails
// if the two copies drift apart.
const ALLOWED_ENV_KEYS = new Set([
  "ARK_API_KEY",
  "ARK_CNY_PER_USD",
  "ARK_SEEDANCE_MODEL",
  "ATLASCLOUD_API_KEY",
  "ATLAS_API_KEY",
  "ATLAS_CLOUD_API_KEY",
  "AZURE_SPEECH_KEY",
  "AZURE_SPEECH_REGION",
  "BACKLOT_PORT",
  "BFL_API_KEY",
  "COVERR_API_KEY",
  "DASHSCOPE_API_KEY",
  "DOUBAO_SPEECH_API_KEY",
  "DOUBAO_SPEECH_VOICE_TYPE",
  "ELEVENLABS_API_KEY",
  "FAL_AI_API_KEY",
  "FAL_KEY",
  "FISH_AUDIO_API_KEY",
  "FREESOUND_API_KEY",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "GOOGLE_GENAI_USE_ENTERPRISE",
  "GOOGLE_GENAI_USE_VERTEXAI",
  "GOOGLE_TTS_API_KEY",
  "HEYGEN_API_KEY",
  "HF_TOKEN",
  "HIGGSFIELD_API_KEY",
  "HIGGSFIELD_API_SECRET",
  "HIGGSFIELD_KEY",
  "HYPERFRAMES_API_KEY",
  "KLING_API_KEY",
  "MINIMAX_API_KEY",
  "MINIMAX_REGION",
  "MUSIC_LIBRARY_DIR",
  "NARA_API_KEY",
  "OPENAI_API_KEY",
  "OPENMONTAGE_CACHE_DIR",
  "OPENMONTAGE_CACHE_MAX_GB",
  "OPENMONTAGE_PROJECTS_DIR",
  "PEXELS_API_KEY",
  "PIXABAY_API_KEY",
  "POND5_API_KEY",
  "REPLICATE_API_TOKEN",
  "RUNWAYML_API_SECRET",
  "RUNWAY_API_KEY",
  "SUNO_API_KEY",
  "TENCENT_TOKENHUB_API_KEY",
  "UNSPLASH_ACCESS_KEY",
  "VIDEO_GEN_LOCAL_ENABLED",
  "VIDEO_GEN_LOCAL_MODEL",
  "VIDEVO_API_KEY",
  "VOLC_ACCESSKEY",
  "VOLC_SECRETKEY",
  "XAI_API_KEY",
]);

// Executable-selection shape, matching _EXECUTABLE_SELECTION_RE in
// lib/env_allowlist.py. A name ending in _PATH or containing _EXEC / _BIN /
// _CMD / _SHELL / _RUNNER conventionally names the *program* a tool spawns, so
// fail closed on it even if a later edit re-adds it to the allow-list. Operators
// set these in their own shell, where this reader never overrides them.
const EXECUTABLE_SELECTION = /_PATH$|_EXEC|_BIN|_CMD|_SHELL|_RUNNER/i;
// Endpoint-selection shape, matching _ENDPOINT_SELECTION_RE in
// lib/env_allowlist.py. A name ending in _URL / _ENDPOINT / _SERVER_ADDR /
// _HOST conventionally names the recipient of a request that carries a
// credential or the operator's own media, so fail closed on it.
const ENDPOINT_SELECTION = /_URL$|_ENDPOINT$|_SERVER_ADDR$|_HOST$/i;

// True only for names a project .env is allowed to export.
export function isSafeEnvKey(key) {
  if (key.startsWith(BASH_FUNC_PREFIX)) return false;
  if (SHELL_ONLY_ENV_KEYS.has(key)) return false;
  if (DENIED_ENV_KEYS.has(key)) return false;
  // Executable-selection shape: a name ending in _PATH or containing _EXEC /
  // _BIN / _CMD / _SHELL / _RUNNER names the *program* a tool spawns, so a
  // project .env must never pick it. Mirrors _EXECUTABLE_SELECTION_RE. This
  // check is unconditional and runs before the allow-list, so a future
  // allow-list edit can never re-open redirect-by-.env on the JS side.
  if (EXECUTABLE_SELECTION.test(key)) return false;
  // Endpoint-selection shape: a name ending in _URL / _ENDPOINT / _SERVER_ADDR
  // / _HOST names the recipient of a credential-bearing request, so a project
  // .env must never pick it either. Mirrors _ENDPOINT_SELECTION_RE, applied
  // unconditionally and before the allow-list is consulted (matches Python).
  if (ENDPOINT_SELECTION.test(key)) return false;
  if (!SAFE_ENV_KEY.test(key)) return false;
  return ALLOWED_ENV_KEYS.has(key);
}

// Walk up ≤5 dirs from startDir; load the first .env (shell env always wins).
export function loadEnvFromDir(startDir) {
  let dir = resolve(startDir);
  for (let i = 0; i < 5; i++) {
    const envPath = join(dir, ".env");
    if (existsSync(envPath)) {
      const rejected = new Set();
      for (const raw of readFileSync(envPath, "utf8").split("\n")) {
        let line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        if (line.startsWith("export ")) line = line.slice(7).trim();
        const eq = line.indexOf("=");
        if (eq < 1) continue;
        const key = line.slice(0, eq).trim();
        let val = line.slice(eq + 1).trim();
        if (val.startsWith('"') || val.startsWith("'")) {
          const q = val[0];
          const end = val.indexOf(q, 1);
          val = end > 0 ? val.slice(1, end) : val.slice(1);
        }
        // Dropping a key is not a reason to fail the engine: a .env carrying a
        // site-local variable must still let the pipeline run.
        if (!isSafeEnvKey(key)) {
          rejected.add(key);
          continue;
        }
        // The VALUE is untrusted input too. A NUL byte cannot be represented in
        // a process environment (execve rejects it), and storing the line would
        // silently truncate it here while apply_env_entries in
        // lib/env_allowlist.py refuses the entry outright -- the two readers
        // would then disagree on what a .env may export. Drop it and report it
        // like any other refused key, mirroring that check.
        if (val.includes("\u0000")) {
          rejected.add(key);
          continue;
        }
        if (!(key in process.env)) process.env[key] = val;
      }
      if (rejected.size > 0 && process.env.OPENMONTAGE_QUIET_ENV_WARNINGS !== "1") {
        // A .env is untrusted input, so a rejected key name may carry terminal
        // control bytes (ESC/BEL/bidi/OSC). Strip everything outside printable
        // ASCII before echoing, cap each name, and cap the list -- mirroring the
        // Python reporter (lib/env_allowlist.warn_rejected_keys) and never
        // letting a hostile .env paint a forged status line on the operator's
        // terminal.
        const sanitize = (s) => s.replace(/[^\x20-\x7e]/g, "?").slice(0, 64);
        const names = [...rejected].map(sanitize).sort();
        const shown = names.slice(0, 10).join(", ");
        const more = names.length > 10 ? ` (+${names.length - 10} more)` : "";
        process.stderr.write(
          `! ignored .env keys that could redirect the child processes this engine spawns: ` +
            `${shown}${more}\n`,
        );
      }
      return;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
}

// Resolve the credential directory. A project .env is untrusted input, so it
// must not be able to relocate the credential lookup; only a directory inside
// the operator's home directory is accepted. If HEYGEN_CONFIG_DIR points
// elsewhere (or is unset), fall back to ~/.heygen so a hostile value can never
// redirect which file becomes the HeyGen key.
export function credentialDir() {
  const home = homedir();
  const raw = process.env.HEYGEN_CONFIG_DIR;
  if (!raw) return join(home, ".heygen");
  const resolved = resolve(raw);
  if (resolved !== home && !resolved.startsWith(home + sep)) {
    process.stderr.write(
      "note: ignoring HEYGEN_CONFIG_DIR outside the home directory\n",
    );
    return join(home, ".heygen");
  }
  return resolved;
}

// → { headers } | { expired: true } | null. Never throws.
export function heygenCredential() {
  const envKey = process.env.HEYGEN_API_KEY || process.env.HYPERFRAMES_API_KEY;
  if (envKey) return { headers: { "X-Api-Key": envKey } };

  const file = join(credentialDir(), "credentials");
  if (!existsSync(file)) return null;
  const raw = readFileSync(file, "utf8").trim();
  if (!raw) return null;
  if (!raw.startsWith("{")) return { headers: { "X-Api-Key": raw } };

  // A malformed credentials file (partial write / wrong shape) must degrade to
  // "no credential", not crash the engine at startup — this function never throws.
  let cred;
  try {
    cred = JSON.parse(raw);
  } catch {
    return null;
  }
  const oauth = cred.oauth;
  if (oauth?.access_token) {
    const expired = oauth.expires_at && new Date(oauth.expires_at).getTime() - 60_000 < Date.now();
    if (!expired) return { headers: { Authorization: `Bearer ${oauth.access_token}` } };
    if (!cred.api_key) return { expired: true };
  }
  if (cred.api_key) return { headers: { "X-Api-Key": cred.api_key } };
  return null;
}

// → auth headers object, or throw with a fix hint.
export function heygenAuthHeaders() {
  const cred = heygenCredential();
  if (cred?.headers) return cred.headers;
  if (cred?.expired)
    throw new Error(
      "HeyGen OAuth token expired — run `npx hyperframes auth refresh` (or `npx hyperframes auth login`)",
    );
  throw new Error(
    "no HeyGen credentials — set $HEYGEN_API_KEY, or run `npx hyperframes auth login` (writes ~/.heygen/credentials)",
  );
}

// Authed JSON request against the v3 API; throws on a non-OK status.
export async function heygenJSON(path, { method = "GET", headers = {}, body } = {}) {
  const opts = { method, headers: { ...headers } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(`${HEYGEN_BASE}${path}`, opts);
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(
      `HeyGen ${method} ${path} → HTTP ${res.status}${detail ? `\n${detail.slice(0, 300)}` : ""}`,
    );
  }
  return res.json();
}

// Download a (presigned) URL to destPath; returns byte length.
export async function downloadTo(url, destPath) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download HTTP ${res.status}: ${String(url).slice(0, 80)}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  mkdirSync(dirname(destPath), { recursive: true });
  writeFileSync(destPath, bytes);
  return bytes.length;
}

// Retrieval search over HeyGen's audio catalog (NOT generation). type =
// "music" | "sound_effects". Returns the ranked results array (best first); each
// item has a presigned `audio_url` (+ `duration`, `description`, `name`, `score`).
// `query` is required (≥1 char, empty → HTTP 400) and `limit` is capped at 50.
// `minScore`: omit to use the server default (0.7). That default is TOO HIGH for
// sound_effects — good SFX hits score ~0.5–0.67, so callers wanting SFX should
// pass a lower floor (~0.4); music scores high and is fine at the default.
export async function searchSounds(query, type, headers, { limit = 5, minScore } = {}) {
  const params = new URLSearchParams({ query, type, limit: String(limit) });
  if (minScore != null) params.set("min_score", String(minScore));
  const payload = await heygenJSON(`/audio/sounds?${params.toString()}`, { headers });
  // `data` comes back as a ranked array (best first). Older responses keyed it by
  // numeric index ("0","1",…); normalize both shapes to an array (empty → []).
  const data = payload?.data ?? payload;
  if (Array.isArray(data)) return data;
  if (data && typeof data === "object") return Object.values(data);
  throw new Error(
    `unexpected /audio/sounds shape — top keys: ${Object.keys(payload ?? {}).join(", ")}`,
  );
}
