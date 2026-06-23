"""
SentinelOne Singularity Data Lake (SDL) API client.

The SDL API has four scoped key types plus the management-console user
API token. Each method below picks the correct key automatically;
callers do not need to worry about which token to send.

Credential resolution order (highest wins, applied last):
  1. Environment variables
  2. $COWORK_WORKSPACE/credentials.json   (recommended: drop credentials.json
     directly in your Cowork project folder.)
  3. Auto-discovered <workspace>/credentials.json (cwd walk-up, then scan
     ~/mnt/* for any Cowork-accessible folder containing credentials.json).
  4. $CLAUDE_CONFIG_DIR/sentinelone/credentials.json  (Cowork session)
  5. ~/.config/sentinelone/credentials.json           (host terminal fallback)
  6. <skill>/config.json                              (last resort)

  Legacy layouts (.sentinelone/credentials.json and
  .claude/sentinelone/credentials.json under the same workspace roots)
  are still accepted at every workspace pass, so existing setups keep
  working without migration.

Canonical keys:
  SDL_XDR_URL            -> base_url  (e.g. https://xdr.us1.sentinelone.net)
  SDL_LOG_READ_KEY       -> log_read_key      (query/numeric/facet/timeseries/powerQuery)
  SDL_CONFIG_READ_KEY    -> config_read_key   (listFiles, getFile)
  SDL_CONFIG_WRITE_KEY   -> config_write_key  (putFile and everything above)
  S1_CONSOLE_API_TOKEN   -> console_api_token (mgmt-console JWT; works for
                                               SDL query and config methods,
                                               not raw-log ingestion. Same JWT used
                                               by S1Client.)
  SDL_S1_SCOPE           -> s1_scope          (required with console token when multi-site/account)
  SDL_VERIFY_TLS         -> verify_tls        (default true)

Deprecated aliases (still read but logged once):
  SDL_BASE_URL           -> SDL_XDR_URL  (former canonical)
  S1_API_TOKEN           -> S1_CONSOLE_API_TOKEN  (former canonical)
  SDL_CONSOLE_API_TOKEN  -> S1_CONSOLE_API_TOKEN  (legacy duplicate, same JWT)

Usage:
    from sdl_client import SDLClient
    c = SDLClient()

    # log read
    c.power_query("dataset='accesslog' | group count() by status", start_time="1h")
    c.query(filter="*", max_count=5, start_time="5m")

    # config files
    c.list_files()
    c.get_file("/alerts")
    # Parsers: use /logParsers/<name> — /parsers/ is API-accepted but invisible in the UI.
    c.put_file("/logParsers/MyParser", content="// parser body")

The client retries 429 and 5xx with exponential backoff and honours
Retry-After. All responses are returned as parsed JSON dicts. Errors
surface as SDLAPIError with .status and .body.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

import requests


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


def _walk_up_for_workspace_creds() -> Optional[Path]:
    """Find workspace-scoped credentials inside a Cowork-accessible folder.

    Three-pass search (in priority order):

      1. $COWORK_WORKSPACE env var. If set, look for
         $COWORK_WORKSPACE/credentials.json (the recommended convention).
         Falls through if not found.

      2. Walk up from cwd looking for credentials.json.

      3. Scan $HOME/mnt/<folder>/ for any Cowork-accessible folder that
         contains credentials.json. This is the simple "drop the file in
         any folder Cowork can see" backup: in a sandbox, the user's
         project folder is mounted at ~/mnt/<projectname>/ but cwd is
         often /outputs.

    All three passes also accept the legacy .sentinelone/credentials.json
    and .claude/sentinelone/credentials.json layouts so existing setups
    keep working without migration.
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


# One-time deprecation warning flags.
_warned_legacy_token = False
_warned_legacy_url = False


class SDLAPIError(RuntimeError):
    def __init__(self, status: int, message: str, body: Any = None):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.body = body


class SandboxProxyBlockedError(RuntimeError):
    """Raised when the Cowork sandbox proxy blocks HTTPS to sentinelone.net.

    The sandbox egress proxy returns 403 on CONNECT, so no SDL API call can
    succeed from inside the sandbox. Fix: use s1-secops-mcp MCP tools instead,
    which run on your local machine and bypass the sandbox proxy entirely.

    Recovery steps:
      1. Use mcp__s1-secops-mcp__sdl_get_file, sdl_put_file, sdl_list_files,
         or powerquery_run instead of running this script.
      2. These tools run locally and make direct HTTPS calls without proxy interference.
      3. This is not a credential issue. Do not change query logic to debug it.
    """
    pass


def _apply_sdl_keys(creds: Dict[str, Any], cfg: Dict[str, Any], source: str) -> None:
    """Populate cfg from a creds dict, accepting canonical and legacy keys.

    Token canonical: S1_CONSOLE_API_TOKEN drives console_api_token (same JWT
    as mgmt console). Aliases: S1_API_TOKEN (former canonical),
    SDL_CONSOLE_API_TOKEN (legacy duplicate).

    URL canonical: SDL_XDR_URL drives base_url. Alias: SDL_BASE_URL
    (former canonical).
    """
    global _warned_legacy_token, _warned_legacy_url
    # SDL XDR URL: canonical SDL_XDR_URL; alias SDL_BASE_URL.
    xdr_url = creds.get("SDL_XDR_URL") or creds.get("SDL_BASE_URL")
    if xdr_url:
        cfg["base_url"] = xdr_url
        if not creds.get("SDL_XDR_URL") and creds.get("SDL_BASE_URL") and not _warned_legacy_url:
            import warnings as _w
            _w.warn(
                f"{source}: SDL_BASE_URL is deprecated, rename to SDL_XDR_URL",
                DeprecationWarning,
                stacklevel=2,
            )
            _warned_legacy_url = True
    direct_map = {
        "SDL_LOG_READ_KEY": "log_read_key",
        "SDL_CONFIG_READ_KEY": "config_read_key",
        "SDL_CONFIG_WRITE_KEY": "config_write_key",
        "SDL_S1_SCOPE": "s1_scope",
    }
    for env, field in direct_map.items():
        if creds.get(env):
            cfg[field] = creds[env]
    # Console token: canonical S1_CONSOLE_API_TOKEN; aliases: S1_API_TOKEN
    # (former canonical), SDL_CONSOLE_API_TOKEN (legacy duplicate of the
    # same JWT). All three name the same token.
    token = (
        creds.get("S1_CONSOLE_API_TOKEN")
        or creds.get("S1_API_TOKEN")
        or creds.get("SDL_CONSOLE_API_TOKEN")
    )
    if token:
        cfg["console_api_token"] = token
        if not creds.get("S1_CONSOLE_API_TOKEN") and not _warned_legacy_token:
            legacy_name = "S1_API_TOKEN" if creds.get("S1_API_TOKEN") else "SDL_CONSOLE_API_TOKEN"
            import warnings as _w
            _w.warn(
                f"{source}: {legacy_name} is deprecated, rename to S1_CONSOLE_API_TOKEN",
                DeprecationWarning,
                stacklevel=2,
            )
            _warned_legacy_token = True


def _load_config() -> Dict[str, Any]:
    """Resolve credentials across all configured layers.

    Priority (highest wins): env vars > workspace .sentinelone (resolved
    via $COWORK_WORKSPACE, cwd walk-up, or ~/mnt/* scan; legacy
    .claude/sentinelone/ accepted) > $CLAUDE_CONFIG_DIR > ~/.claude
    > ~/.config > skill config.json.
    """
    cfg: Dict[str, Any] = {}

    # Layer 1: skill-local config.json (last resort).
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text())
        except json.JSONDecodeError as e:
            raise RuntimeError(f"config.json is not valid JSON: {e}")

    # Layered file lookup, applied lowest-to-highest priority.
    file_layers: List = []
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
        _apply_sdl_keys(creds, cfg, label)

    # Highest priority: environment variables.
    env_xdr_url = os.environ.get("SDL_XDR_URL") or os.environ.get("SDL_BASE_URL")
    if env_xdr_url:
        cfg["base_url"] = env_xdr_url
    direct_env = {
        "SDL_LOG_READ_KEY": "log_read_key",
        "SDL_CONFIG_READ_KEY": "config_read_key",
        "SDL_CONFIG_WRITE_KEY": "config_write_key",
        "SDL_S1_SCOPE": "s1_scope",
    }
    for env, field in direct_env.items():
        if os.environ.get(env):
            cfg[field] = os.environ[env]
    env_token = (
        os.environ.get("S1_CONSOLE_API_TOKEN")
        or os.environ.get("S1_API_TOKEN")
        or os.environ.get("SDL_CONSOLE_API_TOKEN")
    )
    if env_token:
        cfg["console_api_token"] = env_token
    if os.environ.get("SDL_VERIFY_TLS"):
        cfg["verify_tls"] = os.environ["SDL_VERIFY_TLS"].lower() not in ("0", "false", "no")
    return cfg


class SDLClient:
    """SDL API client. Picks the right token per method automatically."""

    # --- key selection table -------------------------------------------------
    # Read-log methods fall back: log_read -> config_read -> config_write -> console
    # Config-read methods: config_read -> config_write -> console
    # Config-write methods: config_write -> console
    KEY_CHAINS = {
        "log_read": ("log_read_key", "config_read_key", "config_write_key", "console_api_token"),
        "config_read": ("config_read_key", "config_write_key", "console_api_token"),
        "config_write": ("config_write_key", "console_api_token"),
    }

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        verify_tls: Optional[bool] = None,
        **overrides: str,
    ):
        cfg = _load_config()
        for k, v in overrides.items():
            if v:
                cfg[k] = v

        self.base_url = (base_url or cfg.get("base_url") or "").rstrip("/")
        if not self.base_url or "REPLACE-ME" in self.base_url:
            raise RuntimeError(
                "SDL base_url is not set. Add SDL_XDR_URL to "
                "$COWORK_WORKSPACE/credentials.json (or any "
                "folder Cowork can access) or export SDL_XDR_URL."
            )

        self.keys = {
            "log_read_key": cfg.get("log_read_key") or "",
            "config_read_key": cfg.get("config_read_key") or "",
            "config_write_key": cfg.get("config_write_key") or "",
            "console_api_token": cfg.get("console_api_token") or "",
        }
        self.s1_scope = cfg.get("s1_scope") or ""
        self.verify_tls = cfg.get("verify_tls", True) if verify_tls is None else verify_tls
        self.timeout = timeout or cfg.get("timeout_seconds", 30)

        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    # ------------------------------------------------------------------ auth
    def _pick_key(self, chain_name: str) -> str:
        """Return the first configured key from the chain for this method."""
        chain = self.KEY_CHAINS[chain_name]
        for field in chain:
            if self.keys.get(field):
                return self.keys[field]
        raise RuntimeError(
            f"No API key configured for chain '{chain_name}'. Tried {chain}. "
            "Check $COWORK_WORKSPACE/credentials.json (or any "
            "folder Cowork can access)."
        )

    def _auth_headers(self, chain_name: str, content_type: str = "application/json") -> Dict[str, str]:
        token = self._pick_key(chain_name)
        h = {"Authorization": f"Bearer {token}", "Content-Type": content_type}
        # Console API tokens need S1-Scope when the user has access to multiple sites/accounts.
        # We look up which field produced the token; only set the header if the token actually
        # came from the console_api_token field AND a scope is configured.
        if self.keys.get("console_api_token") == token and self.s1_scope:
            h["S1-Scope"] = self.s1_scope
        return h

    # --------------------------------------------------------------- request
    def _request(
        self,
        method: str,
        path: str,
        chain: str,
        json_body: Optional[Any] = None,
        data: Optional[Union[str, bytes]] = None,
        params: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        content_type: str = "application/json",
        retries: int = 3,
    ) -> Dict[str, Any]:
        if not path.startswith("/"):
            path = "/" + path
        url = self.base_url + path
        headers = self._auth_headers(chain, content_type=content_type)
        if extra_headers:
            headers.update(extra_headers)

        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self.session.request(
                    method.upper(),
                    url,
                    params=params,
                    json=json_body if data is None else None,
                    data=data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                )
            except requests.exceptions.ProxyError as exc:
                raise SandboxProxyBlockedError(
                    f"Sandbox proxy blocked HTTPS to {self.base_url}. "
                    f"Use s1-secops-mcp MCP tools instead (sdl_get_file, sdl_put_file, "
                    f"sdl_list_files, powerquery_run), which run locally "
                    f"and bypass the sandbox proxy entirely. This is not a credential issue."
                ) from exc
            status = resp.status_code
            # Parse body once
            try:
                body: Any = resp.json() if resp.content else {}
            except ValueError:
                body = {"_raw": resp.text}

            # SDL API treats 200 + status='error/server/backoff' as retryable.
            sdl_status = body.get("status") if isinstance(body, dict) else None
            retryable = (
                status == 429
                or 500 <= status < 600
                or (sdl_status and isinstance(sdl_status, str) and sdl_status.startswith("error/server/backoff"))
            )
            if status < 400 and not (isinstance(sdl_status, str) and sdl_status.startswith("error/")):
                return body
            if retryable and attempt <= retries:
                wait = min(2 ** attempt, 30)
                ra = resp.headers.get("Retry-After")
                if ra and ra.isdigit():
                    wait = int(ra)
                time.sleep(wait)
                continue
            # non-retryable failure
            msg = ""
            if isinstance(body, dict):
                msg = body.get("message") or body.get("status") or ""
            if not msg:
                msg = resp.text[:500]
            raise SDLAPIError(status, msg or f"status={sdl_status}", body)

    # =========================================================================
    # Log read (queries)
    # =========================================================================
    def query(
        self,
        filter: str = "",
        start_time: Optional[Union[str, int]] = None,
        end_time: Optional[Union[str, int]] = None,
        max_count: int = 100,
        page_mode: Optional[str] = None,
        columns: Optional[str] = None,
        continuation_token: Optional[str] = None,
        priority: Optional[str] = None,
        team_emails: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """POST /api/query — retrieve log events matching `filter`.

        `filter` uses the same syntax as the UI search bar. Escape double
        quotes with \\". `start_time`/`end_time` accept UI time strings
        ("1h", "24h", "10/27 4 PM") or epoch seconds/ms/ns. Omit both to
        default to the last 24h.

        `max_count` range is 1..5000 (default 100). Use `continuation_token`
        to page beyond max_count — reuse the same query params and pin
        start/end to absolute times to avoid drift.
        """
        body: Dict[str, Any] = {"queryType": "log", "maxCount": max_count}
        if filter:
            body["filter"] = filter
        if start_time is not None:
            body["startTime"] = start_time
        if end_time is not None:
            body["endTime"] = end_time
        if page_mode:
            body["pageMode"] = page_mode
        if columns:
            body["columns"] = columns
        if continuation_token:
            body["continuationToken"] = continuation_token
        if priority:
            body["priority"] = priority
        if team_emails:
            body["teamEmails"] = team_emails
        return self._request("POST", "/api/query", chain="log_read", json_body=body)

    def numeric_query(
        self,
        function: str = "count",
        filter: str = "",
        start_time: Union[str, int] = "1h",
        end_time: Optional[Union[str, int]] = None,
        buckets: int = 1,
        priority: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /api/numericQuery — bucketed numeric/graph data.

        Effectively superseded by timeseriesQuery, but offers sub-30s
        buckets and is permitted for roles that cannot run
        timeseriesQuery. `function` can be 'count', 'rate', or an
        aggregation like 'mean(responseSize)'.
        """
        body: Dict[str, Any] = {
            "queryType": "numeric",
            "function": function,
            "startTime": start_time,
            "buckets": buckets,
        }
        if filter:
            body["filter"] = filter
        if end_time is not None:
            body["endTime"] = end_time
        if priority:
            body["priority"] = priority
        return self._request("POST", "/api/numericQuery", chain="log_read", json_body=body)

    def facet_query(
        self,
        field: str,
        filter: str = "",
        start_time: Union[str, int] = "1h",
        end_time: Optional[Union[str, int]] = None,
        max_count: int = 100,
        priority: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /api/facetQuery — top-N values of `field` in matching events.

        `max_count` range is 1..1000 (default 100). For very large result
        sets, returned values are sampled from at least 500K matching
        events.
        """
        body: Dict[str, Any] = {
            "queryType": "facet",
            "field": field,
            "startTime": start_time,
            "maxCount": max_count,
        }
        if filter:
            body["filter"] = filter
        if end_time is not None:
            body["endTime"] = end_time
        if priority:
            body["priority"] = priority
        return self._request("POST", "/api/facetQuery", chain="log_read", json_body=body)

    def timeseries_query(
        self,
        queries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """POST /api/timeseriesQuery — one or more numeric queries.

        Each entry in `queries` may include: filter, function, startTime,
        endTime, buckets, createSummaries, onlyUseSummaries, priority,
        teamEmails, tenant, accountIds. Creating a summary turns repeat
        matching queries into near-instant lookups after backfill (~2
        months/hour).
        """
        if not queries:
            raise ValueError("queries must be a non-empty list")
        return self._request(
            "POST", "/api/timeseriesQuery", chain="log_read", json_body={"queries": queries}
        )

    def power_query(
        self,
        query: str,
        start_time: Optional[Union[str, int]] = None,
        end_time: Optional[Union[str, int]] = None,
        priority: Optional[str] = None,
        team_emails: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """POST /api/powerQuery — full pipeline query language.

        `query` is limited to 10,000 chars; escape " in strings. Omit
        times for default 24h. Response has matchingEvents, omittedEvents,
        columns, values (array of rows).
        """
        body: Dict[str, Any] = {"query": query}
        if start_time is not None:
            body["startTime"] = start_time
        if end_time is not None:
            body["endTime"] = end_time
        if priority:
            body["priority"] = priority
        if team_emails:
            body["teamEmails"] = team_emails
        return self._request("POST", "/api/powerQuery", chain="log_read", json_body=body)

    # =========================================================================
    # Configuration files
    # =========================================================================
    def list_files(self) -> Dict[str, Any]:
        """POST /api/listFiles — list every configuration file path."""
        return self._request("POST", "/api/listFiles", chain="config_read", json_body={})

    def get_file(
        self,
        path: str,
        expected_version: Optional[int] = None,
        prettyprint: bool = False,
    ) -> Dict[str, Any]:
        """POST /api/getFile — read a configuration file.

        If `expected_version` matches the stored version, status is
        'success/unchanged' and no content is returned.
        """
        body: Dict[str, Any] = {"path": path}
        if expected_version is not None:
            body["expectedVersion"] = expected_version
        if prettyprint:
            body["prettyprint"] = True
        return self._request("POST", "/api/getFile", chain="config_read", json_body=body)

    def put_file(
        self,
        path: str,
        content: Optional[str] = None,
        expected_version: Optional[int] = None,
        prettyprint: bool = False,
        delete: bool = False,
    ) -> Dict[str, Any]:
        """POST /api/putFile — create, update, or delete a config file.

        Pass `delete=True` to delete. Otherwise `content` is required;
        content is validated per file type (e.g. dashboards expect
        '{graphs: []}' for an empty file, parsers/datatables expect "").
        """
        body: Dict[str, Any] = {"path": path}
        if expected_version is not None:
            body["expectedVersion"] = expected_version
        if delete:
            body["deleteFile"] = True
        else:
            if content is None:
                raise ValueError("content required unless delete=True")
            body["content"] = content
            if prettyprint:
                body["prettyprint"] = True
        return self._request("POST", "/api/putFile", chain="config_write", json_body=body)

    # =========================================================================
    # Helpers
    # =========================================================================
    @staticmethod
    def now_ns() -> str:
        """Current epoch nanoseconds as a string."""
        return str(time.time_ns())

    @staticmethod
    def new_session_id() -> str:
        """Generate a UUID string."""
        return str(uuid.uuid4())

    def iter_query(
        self,
        filter: str = "",
        start_time: Union[str, int] = "24h",
        end_time: Optional[Union[str, int]] = None,
        page_size: int = 1000,
        max_total: Optional[int] = None,
        **kwargs: Any,
    ) -> Iterable[Dict[str, Any]]:
        """Yield every match for a /api/query call across continuationToken pages.

        Use absolute epoch times on the first call if you want perfect
        stability across pages; relative times ('1h') still work because
        the client carries them into subsequent calls.
        """
        token: Optional[str] = None
        yielded = 0
        while True:
            resp = self.query(
                filter=filter,
                start_time=start_time,
                end_time=end_time,
                max_count=page_size,
                continuation_token=token,
                **kwargs,
            )
            matches = resp.get("matches") or []
            for m in matches:
                yield m
                yielded += 1
                if max_total and yielded >= max_total:
                    return
            token = resp.get("continuationToken")
            if not token or not matches:
                return


if __name__ == "__main__":
    # Smoke test — list configuration files.
    c = SDLClient()
    print(json.dumps(c.list_files(), indent=2)[:2000])
