"""
SentinelOne Management Console API client.

Loads credentials (in priority order, highest wins):
  1. Environment variables: S1_CONSOLE_URL, S1_CONSOLE_API_TOKEN
     (S1_BASE_URL, S1_API_TOKEN, and SDL_CONSOLE_API_TOKEN accepted as
     deprecated aliases.)
  2. $COWORK_WORKSPACE/credentials.json   (recommended: drop credentials.json
     directly in your Cowork project folder.)
  3. Auto-discovered <workspace>/credentials.json (cwd walk-up, then scan
     ~/mnt/* for any Cowork-accessible folder containing credentials.json).
  4. $CLAUDE_CONFIG_DIR/sentinelone/credentials.json  (Cowork session)
  5. ~/.config/sentinelone/credentials.json           (host terminal fallback)
  6. <skill>/config.json                              (last resort, not recommended)

  Legacy layouts (.sentinelone/credentials.json and
  .claude/sentinelone/credentials.json under the same workspace roots)
  are still accepted at every workspace pass, so existing setups keep
  working without migration.

Canonical keys in credentials.json:
  S1_CONSOLE_URL                       tenant console URL (e.g. https://usea1-acme.sentinelone.net)
  S1_CONSOLE_API_TOKEN                 management-console API token (Service Users)
  S1_CONSOLE_API_TOKEN_SINGLE_SCOPE    optional single-scope token for endpoints that
                                       reject multi-scope tokens (e.g. /threat-intelligence/iocs)
  S1_HEC_INGEST_URL                    HEC ingest host (logs + alerts/indicators)

Deprecated aliases (still read but logged once):
  S1_BASE_URL                  -> S1_CONSOLE_URL
  S1_API_TOKEN                 -> S1_CONSOLE_API_TOKEN  (former canonical)
  SDL_CONSOLE_API_TOKEN        -> S1_CONSOLE_API_TOKEN  (it's the same JWT)
  S1_API_TOKEN_SINGLE_SCOPE    -> S1_CONSOLE_API_TOKEN_SINGLE_SCOPE
  S1_UAM_ALERT_INTERFACE_URL   -> S1_HEC_INGEST_URL  (former canonical)
  uam_alert_interface_url      -> S1_HEC_INGEST_URL  (legacy snake_case)

Usage:
    from s1_client import S1Client
    c = S1Client()
    # list first page
    r = c.get("/web/api/v2.1/agents", params={"limit": 50})
    # paginate everything (cursor-based)
    for page in c.paginate("/web/api/v2.1/threats", params={"limit": 200}):
        for item in page["data"]:
            ...
    # fan out independent GETs in parallel (I/O-bound, thread-safe)
    results = c.get_many([
        ("/web/api/v2.1/accounts", {"limit": 1}),
        ("/web/api/v2.1/sites",    {"limit": 1}),
        ("/web/api/v2.1/groups",   {"limit": 1}),
    ])

All paths are relative to base_url. The client injects the Authorization
header automatically. Errors surface as S1APIError with status + body.

Performance:
- HTTP connection pooling via sized HTTPAdapter (pool_maxsize=32 default).
  Re-uses sockets across sequential and parallel calls — big win vs. the
  default 10 when fanning out.
- Retries on 429/5xx with exponential backoff, honoring Retry-After.
- Optional short-TTL response cache for rarely-changing read endpoints
  (accounts, sites, groups, system/info, users, rbac/roles, filters,
  service-users, tags). Disabled by default; enable with cache_ttl= in
  the constructor or env S1_CACHE_TTL.
- Parallel fan-out via get_many() using a ThreadPoolExecutor. Each thread
  shares the same pooled session; requests.Session is safe for concurrent
  use across threads when the adapter pool is sized >= worker count.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter


SKILL_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = SKILL_DIR / "config.json"
# Legacy terminal fallback; kept for backward compat.
HOME_CREDS_PATH = Path.home() / ".config" / "sentinelone" / "credentials.json"
# Recommended persistent Mac path; aligns with $CLAUDE_CONFIG_DIR conventions
# and is editable from outside the sandbox without knowing CLAUDE_CONFIG_DIR.
DOTCLAUDE_CREDS_PATH = Path.home() / ".claude" / "sentinelone" / "credentials.json"
# Cowork session creds (shared across plugins) when CLAUDE_CONFIG_DIR is set.
_CLAUDE_CONFIG_DIR = os.environ.get("CLAUDE_CONFIG_DIR", "")
PLUGIN_CREDS_PATH = (Path(_CLAUDE_CONFIG_DIR) / "sentinelone" / "credentials.json"
                     if _CLAUDE_CONFIG_DIR else None)


# Workspace creds layout. The recommended path is just credentials.json
# directly in the project folder. The legacy .sentinelone/ and
# .claude/sentinelone/ subfolder layouts are still accepted so existing
# setups keep working without migration.
_WORKSPACE_CREDS_RELS = (
    Path("credentials.json"),
    Path(".sentinelone") / "credentials.json",
    Path(".claude") / "sentinelone" / "credentials.json",
)
# Mount points under $HOME/mnt that are not user workspaces.
_MNT_SKIP = frozenset({".claude", ".auto-memory", ".remote-plugins", "outputs", "uploads"})


# ─── isLegacy=false safety net ────────────────────────────────────────────
#
# GET /cloud-detection/rules silently drops queryType="scheduled" PowerQuery
# rules unless isLegacy=false is on the query string. There is no error and
# no warning — the response just lies by omission. This is the #1 way
# "list my scheduled detections" returns 0 when scheduled rules actually
# exist. Auto-inject the parameter so callers cannot forget. Honors an
# explicit override if the caller already set isLegacy in params.
#
# Mirrors normalizeS1ApiGetParams in s1-secops-mcp/tools/mgmt-console.js;
# keep the two in sync. Regression test: tests/test_islegacy_guard.py.
#
# Match `/cloud-detection/rules` when it's immediately followed by `/`, `?`,
# or end-of-string. This covers the listing endpoint, the trailing-slash form,
# the single-rule /{id} variant, AND callers that inline query params in the
# path (e.g. ".../rules?limit=200"). The previous end-anchored pattern silently
# skipped the query-suffix form and let scheduled rules drop out. Requiring one
# of `/ ? <end>` after `rules` keeps adjacent names like `/rules-export` or
# `/ruleset` from matching.
_CLOUD_DETECTION_RULES_RE = re.compile(r"/cloud-detection/rules(?:[/?]|$)")


def _maybe_inject_islegacy(
    method: str,
    path: str,
    params: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Return a params dict with isLegacy=false injected when appropriate.

    Triggers on GET to /cloud-detection/rules, /cloud-detection/rules/,
    /cloud-detection/rules/{id}, and any of these with an inline query
    suffix (e.g. /cloud-detection/rules?limit=200). Always returns a fresh
    dict so the caller's input is not mutated.
    """
    out = dict(params or {})
    if method.upper() != "GET":
        return out
    if not _CLOUD_DETECTION_RULES_RE.search(path):
        return out
    if "isLegacy" in out or "is_legacy" in out:
        return out
    out["isLegacy"] = "false"
    return out


def _walk_up_for_workspace_creds() -> Optional[Path]:
    """Find workspace-scoped credentials inside a Cowork-accessible folder.

    Three-pass search (in priority order):

      1. $COWORK_WORKSPACE env var. If set, look for
         $COWORK_WORKSPACE/credentials.json (the recommended convention).
         Falls through to walk-up if not found, rather than failing —
         defensive against typos.

      2. Walk up from cwd looking for credentials.json. Catches the common
         case where the user has cd'd into their project, or a script lives
         there.

      3. Scan $HOME/mnt/<folder>/ for any Cowork-accessible folder that
         contains credentials.json. This is the "drop the file in any
         folder Cowork can see" backup: in a sandbox, the user's project
         folder is mounted at ~/mnt/<projectname>/ but cwd is often
         /outputs, so walk-up alone misses it.

    All three passes also accept the legacy .sentinelone/credentials.json
    and .claude/sentinelone/credentials.json layouts so existing setups
    keep working without migration.

    Stops at filesystem root or after 20 levels of cwd walk-up
    (defensive against unusual mount layouts).
    """
    # Pass 1: explicit $COWORK_WORKSPACE override.
    explicit = os.environ.get("COWORK_WORKSPACE", "").strip()
    if explicit:
        explicit_path = Path(explicit)
        for rel in _WORKSPACE_CREDS_RELS:
            candidate = explicit_path / rel
            if candidate.is_file():
                return candidate

    # Pass 2: cwd walk-up.
    try:
        cwd = Path.cwd().resolve()
    except (OSError, RuntimeError):
        cwd = None
    if cwd is not None:
        for i, parent in enumerate([cwd, *cwd.parents]):
            if i >= 20:
                break
            for rel in _WORKSPACE_CREDS_RELS:
                candidate = parent / rel
                if candidate.is_file():
                    return candidate

    # Pass 3: scan $HOME/mnt for any Cowork-accessible folder.
    home_mnt = Path.home() / "mnt"
    if home_mnt.is_dir():
        try:
            entries = sorted(home_mnt.iterdir())
        except OSError:
            entries = []
        for entry in entries:
            if not entry.is_dir() or entry.name in _MNT_SKIP:
                continue
            for rel in _WORKSPACE_CREDS_RELS:
                candidate = entry / rel
                if candidate.is_file():
                    return candidate
    return None


# One-time deprecation warning flags so we don't spam the log on every load.
_warned_legacy_url = False
_warned_legacy_token = False


def _apply_s1_keys(creds: Dict[str, Any], cfg: Dict[str, Any], source: str) -> None:
    """Populate cfg[base_url]/cfg[api_token] from a creds dict.

    Accepts canonical keys (S1_CONSOLE_URL, S1_CONSOLE_API_TOKEN) and the
    deprecated aliases (S1_BASE_URL, SDL_CONSOLE_API_TOKEN). Emits a
    one-time deprecation warning when only the legacy key is present.
    """
    global _warned_legacy_url, _warned_legacy_token
    url = creds.get("S1_CONSOLE_URL") or creds.get("S1_BASE_URL")
    if url:
        cfg["base_url"] = url
        if (not creds.get("S1_CONSOLE_URL")) and creds.get("S1_BASE_URL") and not _warned_legacy_url:
            import warnings as _w
            _w.warn(
                f"{source}: S1_BASE_URL is deprecated, rename to S1_CONSOLE_URL",
                DeprecationWarning,
                stacklevel=2,
            )
            _warned_legacy_url = True
    # Token: canonical S1_CONSOLE_API_TOKEN; aliases: S1_API_TOKEN (former
    # canonical), SDL_CONSOLE_API_TOKEN (legacy duplicate of the same JWT).
    token = (
        creds.get("S1_CONSOLE_API_TOKEN")
        or creds.get("S1_API_TOKEN")
        or creds.get("SDL_CONSOLE_API_TOKEN")
    )
    if token:
        cfg["api_token"] = token
        if not creds.get("S1_CONSOLE_API_TOKEN") and not _warned_legacy_token:
            legacy_name = "S1_API_TOKEN" if creds.get("S1_API_TOKEN") else "SDL_CONSOLE_API_TOKEN"
            import warnings as _w
            _w.warn(
                f"{source}: {legacy_name} is deprecated, rename to S1_CONSOLE_API_TOKEN",
                DeprecationWarning,
                stacklevel=2,
            )
            _warned_legacy_token = True
    # Single-scope token: canonical S1_CONSOLE_API_TOKEN_SINGLE_SCOPE,
    # legacy alias S1_API_TOKEN_SINGLE_SCOPE.
    sscope = (
        creds.get("S1_CONSOLE_API_TOKEN_SINGLE_SCOPE")
        or creds.get("S1_API_TOKEN_SINGLE_SCOPE")
    )
    if sscope:
        cfg["api_token_single_scope"] = sscope
    # HEC ingest URL (used for both log ingest and OCSF alert/indicator ingest).
    # Canonical: S1_HEC_INGEST_URL. Aliases (read in priority order):
    # S1_UAM_ALERT_INTERFACE_URL (former canonical), uam_alert_interface_url
    # (legacy snake_case).
    hec_url = (
        creds.get("S1_HEC_INGEST_URL")
        or creds.get("S1_UAM_ALERT_INTERFACE_URL")
        or creds.get("uam_alert_interface_url")
    )
    if hec_url:
        cfg["hec_ingest_url"] = hec_url
        # Keep the legacy field name populated too so downstream callers
        # that still read cfg["uam_alert_interface_url"] keep working.
        cfg["uam_alert_interface_url"] = hec_url

# Endpoints where caching is safe — they change rarely during a session.
# Prefix match, base_url stripped.
_CACHEABLE_PATHS = (
    "/web/api/v2.1/accounts",
    "/web/api/v2.1/sites",
    "/web/api/v2.1/groups",
    "/web/api/v2.1/system/info",
    "/web/api/v2.1/system/status",
    "/web/api/v2.1/users",
    "/web/api/v2.1/rbac/roles",
    "/web/api/v2.1/filters",
    "/web/api/v2.1/service-users",
    "/web/api/v2.1/tags",
)


class S1APIError(RuntimeError):
    def __init__(self, status: int, message: str, body: Any = None):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.body = body


class SandboxProxyBlockedError(RuntimeError):
    """Raised when the Cowork sandbox proxy blocks HTTPS to sentinelone.net.

    The sandbox egress proxy returns 403 on CONNECT, so no S1 API call can
    succeed from inside the sandbox. Fix: use s1-secops-mcp MCP tools instead,
    which run on your local machine and bypass the sandbox proxy entirely.

    Recovery steps:
      1. Use s1-secops-mcp MCP tools (s1_api_get, s1_api_post, uam_list_alerts, etc.)
         instead of running this script.
      2. These tools run locally and make direct HTTPS calls without proxy interference.
      3. This is not a credential issue. Do not change query logic to debug it.
    """
    pass


def _load_config() -> Dict[str, Any]:
    """Resolve credentials across all configured layers.

    Priority order (highest wins, applied last):
      7. environment variables
      6. workspace credentials.json — resolved by
         _walk_up_for_workspace_creds() in this order:
           a. $COWORK_WORKSPACE/credentials.json (recommended)
           b. cwd walk-up for credentials.json
           c. ~/mnt/*/credentials.json (any Cowork-accessible folder; this
              is the simple "drop the file in your workspace" backup)
         Legacy .sentinelone/credentials.json and
         .claude/sentinelone/credentials.json layouts are accepted at
         each step for back-compat.
      5. $CLAUDE_CONFIG_DIR/sentinelone/credentials.json (Cowork session)
      4. ~/.claude/sentinelone/credentials.json (persistent host path)
      3. ~/.config/sentinelone/credentials.json (legacy terminal fallback)
      2. <skill>/config.json (last resort)
      1. (none)

    Each file layer is applied in turn so a higher layer overrides a
    lower one only for the keys it actually defines. Missing keys at a
    higher layer fall back to the lower layer's value.
    """
    cfg: Dict[str, Any] = {}

    # Layer 1: skill-local config.json (last resort; not recommended).
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text())
        except json.JSONDecodeError as e:
            raise RuntimeError(f"config.json is not valid JSON: {e}")

    # Layered file lookup, applied lowest-to-highest priority.
    file_layers: List[Tuple[Path, str]] = []
    if HOME_CREDS_PATH.exists():
        file_layers.append((HOME_CREDS_PATH, "~/.config/sentinelone/credentials.json"))
    if DOTCLAUDE_CREDS_PATH.exists():
        file_layers.append((DOTCLAUDE_CREDS_PATH, "~/.claude/sentinelone/credentials.json"))
    if PLUGIN_CREDS_PATH and PLUGIN_CREDS_PATH.exists():
        file_layers.append((PLUGIN_CREDS_PATH, "$CLAUDE_CONFIG_DIR/sentinelone/credentials.json"))
    workspace_creds = _walk_up_for_workspace_creds()
    if workspace_creds is not None:
        file_layers.append((workspace_creds, str(workspace_creds)))

    for path, label in file_layers:
        try:
            creds = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise RuntimeError(f"{path} is not valid JSON: {e}")
        _apply_s1_keys(creds, cfg, label)

    # Highest priority: environment variables.
    env_url = os.environ.get("S1_CONSOLE_URL") or os.environ.get("S1_BASE_URL")
    if env_url:
        cfg["base_url"] = env_url
    env_token = (
        os.environ.get("S1_CONSOLE_API_TOKEN")
        or os.environ.get("S1_API_TOKEN")
        or os.environ.get("SDL_CONSOLE_API_TOKEN")
    )
    if env_token:
        cfg["api_token"] = env_token
    env_sscope = (
        os.environ.get("S1_CONSOLE_API_TOKEN_SINGLE_SCOPE")
        or os.environ.get("S1_API_TOKEN_SINGLE_SCOPE")
    )
    if env_sscope:
        cfg["api_token_single_scope"] = env_sscope
    env_hec_url = (
        os.environ.get("S1_HEC_INGEST_URL")
        or os.environ.get("S1_UAM_ALERT_INTERFACE_URL")
    )
    if env_hec_url:
        cfg["hec_ingest_url"] = env_hec_url
        cfg["uam_alert_interface_url"] = env_hec_url
    if os.environ.get("S1_VERIFY_TLS"):
        cfg["verify_tls"] = os.environ["S1_VERIFY_TLS"].lower() not in ("0", "false", "no")
    if os.environ.get("S1_CACHE_TTL"):
        try:
            cfg["cache_ttl"] = float(os.environ["S1_CACHE_TTL"])
        except ValueError:
            pass
    return cfg


class S1Client:
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_token: Optional[str] = None,
        verify_tls: Optional[bool] = None,
        timeout: Optional[float] = None,
        pool_maxsize: int = 32,
        cache_ttl: Optional[float] = None,
        token_kind: str = "default",
    ):
        """
        token_kind selects which token to read from credentials.json when no
        explicit `api_token` argument or S1_CONSOLE_API_TOKEN env var is supplied.

          - "default"       → `api_token` (typically multi-scope).
                              Falls back to `api_token_single_scope` if
                              `api_token` is not configured.
          - "single_scope"  → `api_token_single_scope`. Required for
                              endpoints that reject multi-scope tokens
                              (e.g. /threat-intelligence/iocs). Falls back
                              to `api_token` if `api_token_single_scope`
                              is not configured — callers that strictly
                              need a single-scope token should check the
                              resulting `self.token_kind_effective`.

        Both tokens are optional in credentials.json: the skill works with
        either one alone, or both. Explicit `api_token=` or S1_CONSOLE_API_TOKEN
        always wins over the config selection.
        """
        cfg = _load_config()
        self.base_url = (base_url or cfg.get("base_url") or "").rstrip("/")

        cfg_default = cfg.get("api_token") or ""
        cfg_single  = cfg.get("api_token_single_scope") or ""
        if token_kind == "single_scope":
            token_from_cfg = cfg_single or cfg_default
            self.token_kind_effective = (
                "single_scope" if cfg_single else
                ("default_fallback" if cfg_default else "none")
            )
        else:
            token_from_cfg = cfg_default or cfg_single
            self.token_kind_effective = (
                "default" if cfg_default else
                ("single_scope_fallback" if cfg_single else "none")
            )
        if api_token:
            self.token_kind_effective = "explicit"
        self.api_token = api_token or token_from_cfg
        self.verify_tls = cfg.get("verify_tls", True) if verify_tls is None else verify_tls
        self.timeout = timeout or cfg.get("timeout_seconds", 30)
        self.cache_ttl = cache_ttl if cache_ttl is not None else cfg.get("cache_ttl", 0)

        if not self.base_url or "REPLACE-ME" in self.base_url:
            raise RuntimeError(
                "S1 console URL is not set. Add S1_CONSOLE_URL to "
                "$COWORK_WORKSPACE/credentials.json (or any "
                "folder Cowork can access) or export S1_CONSOLE_URL."
            )
        if not self.api_token or "REPLACE" in self.api_token:
            raise RuntimeError(
                "S1 api_token is not set. Add S1_CONSOLE_API_TOKEN to "
                "$COWORK_WORKSPACE/credentials.json (or any "
                "folder Cowork can access) or export S1_CONSOLE_API_TOKEN."
            )

        # Session with pooled connection adapter — allows many parallel GETs
        # to share sockets to the same host without tearing them down.
        self.session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=pool_maxsize,
            pool_maxsize=pool_maxsize,
            pool_block=False,
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update({
            "Authorization": f"ApiToken {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "s1-mgmt-api-skill/1.1 (+claude)",
        })

        # response cache — (path, sorted-params-tuple) -> (expires_ts, body)
        self._cache: Dict[Tuple[str, Tuple], Tuple[float, Dict[str, Any]]] = {}
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------ core
    def _cache_key(self, path: str, params: Optional[Dict[str, Any]]):
        return (path, tuple(sorted((params or {}).items())))

    def _is_cacheable(self, method: str, path: str) -> bool:
        if self.cache_ttl <= 0 or method != "GET":
            return False
        return any(path.startswith(p) for p in _CACHEABLE_PATHS)

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        retries: int = 3,
    ) -> Dict[str, Any]:
        """Raw request. Retries on 429/5xx with exponential backoff."""
        if not path.startswith("/"):
            path = "/" + path

        # Auto-inject isLegacy=false on GET /cloud-detection/rules so scheduled
        # PowerQuery rules don't get silently dropped. See _maybe_inject_islegacy
        # for the contract; mirror it in s1-secops-mcp/tools/mgmt-console.js.
        params = _maybe_inject_islegacy(method, path, params)

        if self._is_cacheable(method, path):
            key = self._cache_key(path, params)
            with self._cache_lock:
                entry = self._cache.get(key)
                if entry and entry[0] > time.time():
                    return entry[1]

        url = self.base_url + path
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self.session.request(
                    method.upper(),
                    url,
                    params=params,
                    json=json_body,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                )
            except requests.exceptions.ProxyError as exc:
                raise SandboxProxyBlockedError(
                    f"Sandbox proxy blocked HTTPS to {self.base_url}. "
                    f"Use s1-secops-mcp MCP tools instead (s1_api_get, s1_api_post, "
                    f"uam_list_alerts, etc.), which run locally and bypass the sandbox proxy. "
                    f"This is not a credential issue."
                ) from exc
            if resp.status_code < 400:
                if resp.content:
                    try:
                        body = resp.json()
                    except ValueError:
                        body = {"_raw": resp.text}
                else:
                    body = {}
                if self._is_cacheable(method, path):
                    key = self._cache_key(path, params)
                    with self._cache_lock:
                        self._cache[key] = (time.time() + self.cache_ttl, body)
                return body
            # retryable?
            retryable = resp.status_code == 429 or 500 <= resp.status_code < 600
            if retryable and attempt <= retries:
                wait = min(2 ** attempt, 30)
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    wait = int(retry_after)
                time.sleep(wait)
                continue
            # error path
            try:
                body = resp.json()
                msg = (
                    (body.get("errors") or [{}])[0].get("detail")
                    or body.get("detail")
                    or resp.text[:500]
                )
            except Exception:
                body = resp.text
                msg = resp.text[:500]
            raise S1APIError(resp.status_code, msg, body)

    # ----------------------------------------------------------- convenience
    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.request("GET", path, params=params)

    def post(self, path: str, json_body: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.request("POST", path, params=params, json_body=json_body)

    def put(self, path: str, json_body: Any = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.request("PUT", path, params=params, json_body=json_body)

    def delete(self, path: str, params: Optional[Dict[str, Any]] = None, json_body: Any = None) -> Dict[str, Any]:
        return self.request("DELETE", path, params=params, json_body=json_body)

    # ------------------------------------------------------------ pagination
    def paginate(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        max_pages: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Yields raw response pages for cursor-based list endpoints.
        Stops when `pagination.nextCursor` is missing/empty.
        """
        params = dict(params or {})
        pages = 0
        while True:
            resp = self.get(path, params=params)
            yield resp
            pages += 1
            if max_pages and pages >= max_pages:
                return
            pag = resp.get("pagination") or {}
            nxt = pag.get("nextCursor")
            if not nxt:
                return
            params["cursor"] = nxt

    def iter_items(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        max_items: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yields individual items across paginated responses."""
        count = 0
        for page in self.paginate(path, params=params):
            for item in page.get("data", []) or []:
                yield item
                count += 1
                if max_items and count >= max_items:
                    return

    # ------------------------------------------------------------ parallel fan-out
    def get_many(
        self,
        calls: Iterable[Tuple[str, Optional[Dict[str, Any]]]],
        max_workers: int = 8,
        on_error: Optional[Callable[[str, Dict[str, Any], Exception], None]] = None,
        retries: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Run many independent GETs in parallel. Each element of ``calls`` is
        ``(path, params)``. Returns one result dict per call, in input order:

            {"path": ..., "params": ..., "ok": bool, "status": int|None,
             "data": <body>|None, "error": str|None, "elapsed_ms": float}

        Thread-safe: the underlying ``requests.Session`` and pooled adapter
        are safe for concurrent use so long as pool_maxsize >= max_workers.
        """
        calls = list(calls)
        results: List[Optional[Dict[str, Any]]] = [None] * len(calls)

        def _one(i: int, path: str, params: Optional[Dict[str, Any]]):
            t0 = time.time()
            try:
                body = self.request("GET", path, params=params, retries=retries)
                return i, {
                    "path": path,
                    "params": params,
                    "ok": True,
                    "status": 200,
                    "data": body,
                    "error": None,
                    "elapsed_ms": (time.time() - t0) * 1000.0,
                }
            except S1APIError as e:
                out = {
                    "path": path,
                    "params": params,
                    "ok": False,
                    "status": e.status,
                    "data": None,
                    "error": str(e),
                    "elapsed_ms": (time.time() - t0) * 1000.0,
                }
                if on_error:
                    try:
                        on_error(path, params or {}, e)
                    except Exception:
                        pass
                return i, out
            except Exception as e:
                out = {
                    "path": path,
                    "params": params,
                    "ok": False,
                    "status": None,
                    "data": None,
                    "error": f"{type(e).__name__}: {e}",
                    "elapsed_ms": (time.time() - t0) * 1000.0,
                }
                if on_error:
                    try:
                        on_error(path, params or {}, e)
                    except Exception:
                        pass
                return i, out

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(_one, i, p, q) for i, (p, q) in enumerate(calls)]
            for f in as_completed(futs):
                i, r = f.result()
                results[i] = r
        return results  # type: ignore[return-value]

    # ------------------------------------------------------------ cache management
    def cache_clear(self) -> None:
        with self._cache_lock:
            self._cache.clear()


if __name__ == "__main__":
    # Smoke test — lists accounts, then fans out four parallel GETs
    c = S1Client(cache_ttl=60)
    r = c.get("/web/api/v2.1/accounts", params={"limit": 5})
    print("accounts page:", len(r.get("data", []) or []))
    parallel = c.get_many([
        ("/web/api/v2.1/accounts", {"limit": 1}),
        ("/web/api/v2.1/sites", {"limit": 1}),
        ("/web/api/v2.1/groups", {"limit": 1}),
        ("/web/api/v2.1/system/info", None),
    ])
    for row in parallel:
        print(f"  {row['status']} {row['elapsed_ms']:.0f}ms {row['path']}")
