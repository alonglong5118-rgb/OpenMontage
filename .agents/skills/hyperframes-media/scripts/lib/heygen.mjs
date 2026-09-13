// heygen.mjs — vendored HeyGen REST helpers (auth + transport) for the audio
// pipeline. The credential resolver is copied from hyperframes-media's
// heygen-tts.mjs (and matches the hyperframes CLI auth): first usable source
// wins — $HEYGEN_API_KEY / $HYPERFRAMES_API_KEY → a nearby .env → ~/.heygen/
// credentials (oauth → Bearer, else api_key → X-Api-Key; $HEYGEN_CONFIG_DIR
// overrides the dir). Vendored so the skill ships standalone. Pure node.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

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
  // Dynamic loader / injected libraries.
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "LD_AUDIT",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "DYLD_FRAMEWORK_PATH",
  // Shell startup hooks.
  "BASH_ENV",
  "ENV",
  "SHELLOPTS",
  "BASHOPTS",
  "PROMPT_COMMAND",
  "IFS",
  // Interpreter search paths and startup hooks.
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
  // Process and session basics.
  "PATH",
  "HOME",
  "TMPDIR",
  "PWD",
  "OLDPWD",
  "SHELL",
  "USER",
  "LOGNAME",
  // Credential and trust-store redirection.
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
]);

// Bash exports shell functions as BASH_FUNC_<name>%%; never honour those.
const BASH_FUNC_PREFIX = "BASH_FUNC_";

// Key-shape rule, matching _KEY_RE in lib/env_allowlist.py.
const SAFE_ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

// True only for names a project .env is allowed to export.
export function isSafeEnvKey(key) {
  if (key.startsWith(BASH_FUNC_PREFIX)) return false;
  if (DENIED_ENV_KEYS.has(key)) return false;
  return SAFE_ENV_KEY.test(key);
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
        if (!(key in process.env)) process.env[key] = val;
      }
      if (rejected.size > 0) {
        process.stderr.write(
          `! ignored .env keys that could redirect the child processes this engine spawns: ` +
            `${[...rejected].sort().join(", ")}\n`,
        );
      }
      return;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
}

// → { headers } | { expired: true } | null. Never throws.
export function heygenCredential() {
  const envKey = process.env.HEYGEN_API_KEY || process.env.HYPERFRAMES_API_KEY;
  if (envKey) return { headers: { "X-Api-Key": envKey } };

  const file = join(process.env.HEYGEN_CONFIG_DIR || join(homedir(), ".heygen"), "credentials");
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
