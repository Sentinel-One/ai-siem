"""
SentinelOne Singularity Data Lake (SDL) API client.

Every SDL method authenticates with the management-console API token,
sent as ``Authorization: Bearer <token>``. That single credential covers
config read, config write, and log read.

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
  S1_CONSOLE_URL         -> base_url is <console>/sdl
  S1_CONSOLE_API_TOKEN   -> console_api_token (mgmt-console token; authorises
                                               every SDL query and config
                                               method. Same token used by
                                               S1Client.)
  SDL_S1_SCOPE           -> s1_scope          (required with console token when multi-site/account)
  SDL_VERIFY_TLS         -> verify_tls        (default true)

Deprecated aliases (still read but logged once):
  S1_API_TOKEN           -> S1_CONSOLE_API_TOKEN  (former canonical)
  SDL_CONSOLE_API_TOKEN  -> S1_CONSOLE_API_TOKEN  (legacy duplicate, same JWT)

Usage:
    from sdl_client import SDLClient
    c = SDLClient()

    # log read
    c.power_query("dataset='accesslog' | group count() by status", start_time="1h")
    c.query(filter="*", max_count=5, start_time="5m")

    # config files
    c.config_files()
    c.config_file(name="/alerts")
    # Parsers: use /logParsers/<name>; /parsers/ is API-accepted but invisible in the UI.
    c.put_config_file(name="/logParsers/MyParser", content="// parser body")

The client retries 429 and 5xx with exponential backoff and honours
Retry-After. All responses are returned as parsed JSON dicts. Errors
surface as SDLAPIError with .status and .body.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from urllib.parse import quote
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


class _Unset:
    """Sentinel distinguishing "argument omitted" from an explicit None.

    Needed for `scope`: omitting it inherits the client default, while passing
    None deliberately sends no S1-Scope header at all. Collapsing the two would
    make an unscoped listing unrequestable once a default is configured.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<unset>"


_UNSET = _Unset()


class SDLAPIError(RuntimeError):
    def __init__(self, status: int, message: str, body: Any = None, graphql: bool = False):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.body = body
        # True when the failure came from the GraphQL layer rather than the
        # transport. Absence detection keys off this.
        self.graphql = graphql


def _normalise_name(n: Any) -> str:
    """SDL config names are case-insensitive and tolerate stray whitespace, so
    the absence check and the duplicate guard must normalise identically."""
    return str(n or "").strip().lower()


def _matches_name(file_obj: Dict[str, Any], name: Any) -> bool:
    return _normalise_name((file_obj or {}).get("name")) == _normalise_name(name)


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

    base_url is derived from S1_CONSOLE_URL as <console>/sdl.
    (former canonical).
    """
    global _warned_legacy_token, _warned_legacy_url
    if creds.get("S1_CONSOLE_URL"):
        cfg["base_url"] = creds["S1_CONSOLE_URL"].rstrip("/") + "/sdl"
    direct_map = {
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
    if os.environ.get("S1_CONSOLE_URL"):
        cfg["base_url"] = os.environ["S1_CONSOLE_URL"].rstrip("/") + "/sdl"
    direct_env = {
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
                "SDL base_url is not set. Add S1_CONSOLE_URL to "
                "$COWORK_WORKSPACE/credentials.json (or any "
                "folder Cowork can access) or export S1_CONSOLE_URL."
            )

        self.token = cfg.get("console_api_token") or ""
        if not self.token:
            raise RuntimeError(
                "S1_CONSOLE_API_TOKEN is not set. Add it to "
                "$COWORK_WORKSPACE/credentials.json (or any "
                "folder Cowork can access) or export S1_CONSOLE_API_TOKEN."
            )
        self.s1_scope = cfg.get("s1_scope") or ""
        self.verify_tls = cfg.get("verify_tls", True) if verify_tls is None else verify_tls
        self.timeout = timeout or cfg.get("timeout_seconds", 30)

        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    # ------------------------------------------------------------------ auth
    def _auth_headers(self, content_type: str = "application/json") -> Dict[str, str]:
        h = {"Authorization": f"Bearer {self.token}", "Content-Type": content_type}
        # S1-Scope is required when the token has access to multiple sites/accounts.
        if self.s1_scope:
            h["S1-Scope"] = self.s1_scope
        return h

    # ----------------------------------------------------------------- scope
    def _scope_headers(self, scope: Any = _UNSET) -> Dict[str, str]:
        """Per-call S1-Scope override.

        SDL config reads are scope-FILTERED, not merely scope-tagged. Measured on
        usea1-purple 2026-08-17, same token: the same `configFiles` query returned
        113 files at account scope and 4 at a site scope. A dashboard created at site scope is
        invisible from account scope, so the header decides which objects appear
        to exist at all.

        `_UNSET` (the default) inherits `self.s1_scope`. Explicit `None` returns
        an override that SUPPRESSES the instance default, which is how you take a
        deliberately unscoped, token-default listing.
        """
        if scope is _UNSET:
            return {}
        if scope is None:
            # requests drops a header whose value is None.
            return {"S1-Scope": None}  # type: ignore[dict-item]
        if not isinstance(scope, str):
            raise ValueError(
                f"S1-Scope must be a string, got {type(scope).__name__}. "
                'Use "<accountId>" or "<accountId>:<siteId>".'
            )
        trimmed = scope.strip()
        if not re.fullmatch(r"\d+(:\d+)?", trimmed):
            raise ValueError(
                f"Invalid S1-Scope {trimmed!r}. Expected \"<accountId>\" or "
                '"<accountId>:<siteId>", both numeric ids. Get them from '
                "GET /web/api/v2.1/accounts and /web/api/v2.1/sites."
            )
        return {"S1-Scope": trimmed}

    # --------------------------------------------------------------- request
    def _request(
        self,
        method: str,
        path: str,
        json_body: Optional[Any] = None,
        data: Optional[Union[str, bytes]] = None,
        params: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        content_type: str = "application/json",
        retries: int = 3,
        allow_retry: Optional[bool] = None,
    ) -> Dict[str, Any]:
        # Status-based retry is restricted to idempotent methods, mirroring
        # lib/sdl.js. A 5xx received after the server committed a write would
        # otherwise be re-sent, and a re-sent addConfigFile(name:) against
        # /dashboards/ creates a duplicate. Read-only POSTs opt in explicitly.
        method_retryable = (
            allow_retry if allow_retry is not None
            else method.upper() in ("GET", "HEAD")
        )
        if not path.startswith("/"):
            path = "/" + path
        url = self.base_url + path

        headers = self._auth_headers(content_type=content_type)
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
            if retryable and method_retryable and attempt <= retries:
                wait = min(2 ** attempt, 30)
                ra = resp.headers.get("Retry-After")
                if ra and ra.isdigit():
                    # Cap the server-supplied delay: an unbounded Retry-After
                    # would park the process (observed guidance: cap at 30s).
                    wait = min(int(ra), 30)
                time.sleep(wait)
                continue
            # non-retryable, non-auth failure
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
        scope: Any = _UNSET,
    ) -> Dict[str, Any]:
        """POST /api/query: retrieve log events matching `filter`.

        `scope` sets S1-Scope. Log reads are scope-filtered exactly as config
        reads are, so a query run without the intended scope silently answers
        for the token default instead.

        `filter` uses the same syntax as the UI search bar. Escape double
        quotes with \\". `start_time`/`end_time` accept UI time strings
        ("1h", "24h", "10/27 4 PM") or epoch seconds/ms/ns. Omit both to
        default to the last 24h.

        `max_count` range is 1..5000 (default 100). Use `continuation_token`
        to page beyond max_count, reuse the same query params and pin
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
        return self._request("POST", "/api/query", json_body=body,
                             extra_headers=self._scope_headers(scope))

    def numeric_query(
        self,
        function: str = "count",
        filter: str = "",
        start_time: Union[str, int] = "1h",
        end_time: Optional[Union[str, int]] = None,
        buckets: int = 1,
        priority: Optional[str] = None,
        scope: Any = _UNSET,
    ) -> Dict[str, Any]:
        """POST /api/numericQuery: bucketed numeric/graph data.

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
        return self._request("POST", "/api/numericQuery", json_body=body,
                             extra_headers=self._scope_headers(scope))

    def facet_query(
        self,
        field: str,
        filter: str = "",
        start_time: Union[str, int] = "1h",
        end_time: Optional[Union[str, int]] = None,
        max_count: int = 100,
        priority: Optional[str] = None,
        scope: Any = _UNSET,
    ) -> Dict[str, Any]:
        """POST /api/facetQuery: top-N values of `field` in matching events.

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
        return self._request("POST", "/api/facetQuery", json_body=body,
                             extra_headers=self._scope_headers(scope))

    def timeseries_query(
        self,
        queries: List[Dict[str, Any]],
        scope: Any = _UNSET,
    ) -> Dict[str, Any]:
        """POST /api/timeseriesQuery: one or more numeric queries.

        Each entry in `queries` may include: filter, function, startTime,
        endTime, buckets, createSummaries, onlyUseSummaries, priority,
        teamEmails, tenant, accountIds. Creating a summary turns repeat
        matching queries into near-instant lookups after backfill (~2
        months/hour).
        """
        if not queries:
            raise ValueError("queries must be a non-empty list")
        return self._request(
            "POST", "/api/timeseriesQuery", json_body={"queries": queries},
            extra_headers=self._scope_headers(scope),
        )

    def power_query(
        self,
        query: str,
        start_time: Optional[Union[str, int]] = None,
        end_time: Optional[Union[str, int]] = None,
        priority: Optional[str] = None,
        team_emails: Optional[List[str]] = None,
        scope: Any = _UNSET,
    ) -> Dict[str, Any]:
        """POST /api/powerQuery: full pipeline query language.

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
        return self._request("POST", "/api/powerQuery", json_body=body,
                             extra_headers=self._scope_headers(scope))

    # =========================================================================
    # Configuration files (GraphQL, canonical)
    # =========================================================================
    #
    # POST /sdl/v2/graphql is the canonical config-file surface and a strict
    # superset of the REST /api/*File endpoints below. Measured live: REST
    # listFiles returned 1,914 paths, configFiles returned 2,264. The 350-file
    # gap is entirely udoId-addressed /dashboards/ files, and REST getFile on
    # any of them returns 'success/noSuchFile'.
    #
    # udoId is assigned by namespace: only /dashboards/ files have one.
    # /lookups/, /datatables/, /logParsers/ and /automaticLookups are
    # name-addressed with udoId None.

    _CONFIG_FIELDS = "udoId name readOnly version"

    def _graphql(
        self,
        opname: str,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        read_only: bool = False,
        scope: Any = _UNSET,
    ) -> Dict[str, Any]:
        """POST /v2/graphql. Raises SDLAPIError on the GraphQL `errors` array.

        GraphQL failures return HTTP 200 with an `errors` array, so the status
        code alone never tells you a call failed. Three shapes must all raise
        rather than fall through to an empty result, since every caller's
        "nothing here" default is indistinguishable from a real empty answer:
        a non-dict body (a proxy or SSO interstitial served as text), an
        `errors` value that is not a list, and a body carrying neither `data`
        nor `errors`.
        """
        body: Dict[str, Any] = {"query": query}
        if variables:
            body["variables"] = variables
        payload = self._request(
            "POST",
            f"/v2/graphql?opname={quote(str(opname), safe='')}",
            json_body=body,
            allow_retry=read_only,
            extra_headers=self._scope_headers(scope),
        )
        if not isinstance(payload, dict):
            raise SDLAPIError(
                200,
                f"SDL GraphQL {opname}: expected a JSON object, got "
                f"{type(payload).__name__}. This usually means a proxy or auth "
                f"interstitial answered instead of the API. "
                f"First 200 chars: {str(payload)[:200]}",
                payload,
                graphql=True,
            )
        errors = payload.get("errors")
        if errors:
            errs = errors if isinstance(errors, list) else [errors]
            first = errs[0] if errs else {}
            message = (first or {}).get("message", "unknown GraphQL error")
            correlation = (payload.get("extensions") or {}).get("correlationId") or (
                (first or {}).get("extensions") or {}
            ).get("correlationId")
            if correlation:
                message = f"{message} (correlationId={correlation})"
            raise SDLAPIError(200, f"SDL GraphQL {opname}: {message}", payload, graphql=True)
        if "data" not in payload:
            raise SDLAPIError(
                200,
                f"SDL GraphQL {opname}: response carried neither data nor errors.",
                payload,
                graphql=True,
            )
        return payload.get("data") or {}

    def config_files(self, scope: Any = _UNSET) -> List[Dict[str, Any]]:
        """Every config file VISIBLE AT `scope`, including udoId-addressed dashboards.

        Prefer this over `list_files()`, which omits them.

        This listing is scope-FILTERED. Measured on usea1-purple 2026-08-17, same
        token: 113 files at account scope, 4 at a site scope. A file absent here may
        live at another scope, so never promote "not in this listing" to
        "does not exist" without checking the scope it was created in.
        """
        data = self._graphql(
            "getConfigurationFiles",
            f"query getConfigurationFiles {{ configFiles {{ {self._CONFIG_FIELDS} }} }}",
            read_only=True,
            scope=scope,
        )
        return data.get("configFiles") or []

    def config_file(
        self,
        name: Optional[str] = None,
        udo_id: Optional[str] = None,
        scope: Any = _UNSET,
    ) -> Optional[Dict[str, Any]]:
        """Read one config file by name (plain files) or udo_id (dashboards).
        Returns None when the file does not exist.

        Absence is a normal outcome of a lookup, but the server reports it as a
        GraphQL error whose message differs by address form (verified live):

          by name  : "Config file with name /x/y not found."   -> explicit
          by udo_id: "Something went wrong. Please try again..." -> generic, and
                     the SAME text a version conflict returns, so it cannot be
                     trusted on message alone.

        The explicit form is normalised directly; the ambiguous one is
        disambiguated against the file listing. The extra listing only happens
        on the error path.
        """
        if not name and not udo_id:
            raise ValueError("config_file requires either name or udo_id")
        try:
            if udo_id:
                data = self._graphql(
                    "configFile",
                    f"query f($udoId: ID!) {{ configFile(udoId: $udoId) {{ {self._CONFIG_FIELDS} content }} }}",
                    {"udoId": str(udo_id)},
                    read_only=True,
                    scope=scope,
                )
            else:
                data = self._graphql(
                    "configFile",
                    f"query f($id: ID!) {{ configFile(id: $id) {{ {self._CONFIG_FIELDS} content }} }}",
                    {"id": name},
                    read_only=True,
                    scope=scope,
                )
        except SDLAPIError as exc:
            # Only a GraphQL-layer error can mean "absent". A transport failure
            # whose body happens to contain "not found" must never be read as
            # absence: that is how a delete gets confirmed against a file that
            # was never checked.
            if not getattr(exc, "graphql", False):
                raise
            if re.search(r"config file with (name|id) .* not found", str(exc), re.I):
                return None
            # The udo_id form returns a generic message that a version conflict
            # also returns, so settle it against the listing. If the listing
            # itself fails, keep the ORIGINAL error.
            try:
                # Same scope as the failed lookup. Disambiguating against a
                # DIFFERENT scope's listing reports a live site-scoped file as
                # absent, which is the exact false negative this branch removes.
                all_files = self.config_files(scope=scope)
            except SDLAPIError as list_exc:
                raise SDLAPIError(
                    exc.status,
                    f"{exc} (absence check failed: {list_exc})",
                    exc.body,
                ) from exc
            if udo_id:
                present = any(str(f.get("udoId")) == str(udo_id) for f in all_files)
            else:
                present = any(_matches_name(f, name) for f in all_files)
            if not present:
                return None
            raise
        return data.get("configFile")

    def put_config_file(
        self,
        name: Optional[str] = None,
        udo_id: Optional[str] = None,
        content: str = "",
        expected_version: Optional[int] = None,
        scope: Any = _UNSET,
    ) -> Optional[Dict[str, Any]]:
        """Create or update a config file.

        Pass `udo_id` to update a dashboard in place; pass `name` to create, or
        to update any name-addressed file.

        A name-addressed write UPDATES IN PLACE for plain files but CREATES A
        DUPLICATE for /dashboards/. This method refuses a name-addressed write
        to an existing dashboard for that reason; one tenant reached 152 copies
        of '/dashboards/AI Usage' that way.
        """
        if not name and not udo_id:
            raise ValueError("put_config_file requires either name or udo_id")
        if not udo_id and _normalise_name(name).startswith("/dashboards/"):
            # Scoped to match the write: an account-scoped listing cannot see a
            # same-named site-scoped dashboard, so the guard has to look where
            # the write is going, not where the token defaults.
            all_files = self.config_files(scope=scope)
            if not all_files:
                raise ValueError(
                    f'Refusing to write "{name}" by name: the configFiles listing came '
                    "back empty, so the duplicate check could not run. Retry, or pass "
                    "an explicit udo_id."
                )
            existing = [f for f in all_files if _matches_name(f, name)]
            if existing:
                ids = ", ".join(str(f.get("udoId")) for f in existing if f.get("udoId"))
                raise ValueError(
                    f'Refusing to write "{name}" by name: {len(existing)} dashboard(s) '
                    "already use that name, and a name-addressed write to /dashboards/ "
                    "creates another duplicate rather than updating. Pass one of these "
                    f"udoIds instead: {ids or '(none)'}."
                )
        if udo_id:
            data = self._graphql(
                "addConfigFile",
                "mutation f($udoId: ID, $content: String!, $expectedVersion: Long) "
                "{ addConfigFile(udoId: $udoId, content: $content, expectedVersion: $expectedVersion) "
                f"{{ {self._CONFIG_FIELDS} }} }}",
                {
                    "udoId": str(udo_id),
                    "content": content,
                    "expectedVersion": expected_version,
                },
                scope=scope,
            )
        else:
            # expectedVersion is enforced on name-addressed writes too: a stale
            # value is rejected with "There are conflicting changes in the file."
            # Omitting it silently downgrades every parser, lookup, datatable and
            # /automaticLookups update to last-write-wins.
            data = self._graphql(
                "addConfigFile",
                "mutation f($name: String, $content: String!, $expectedVersion: Long) "
                "{ addConfigFile(name: $name, content: $content, expectedVersion: $expectedVersion) "
                f"{{ {self._CONFIG_FIELDS} }} }}",
                {
                    "name": name,
                    "content": content,
                    "expectedVersion": expected_version,
                },
                scope=scope,
            )
        return data.get("addConfigFile")

    def delete_config_file(
        self,
        name: Optional[str] = None,
        udo_id: Optional[str] = None,
        expected_version: Optional[int] = None,
        scope: Any = _UNSET,
    ) -> Dict[str, Any]:
        """Delete a config file. Dashboards by udo_id, everything else by name.

        The mutation returns null on success and does not echo the deleted
        object, so its response cannot distinguish "deleted" from "matched
        nothing". Confirm by re-reading, and raise if the file survives.
        """
        if not name and not udo_id:
            raise ValueError("delete_config_file requires either name or udo_id")
        if udo_id:
            raw = self._graphql(
                "deleteConfigFile",
                "mutation f($udoId: ID, $expectedVersion: Long) "
                "{ deleteConfigFile(udoId: $udoId, expectedVersion: $expectedVersion) { udoId } }",
                {"udoId": str(udo_id), "expectedVersion": expected_version},
                scope=scope,
            )
        else:
            raw = self._graphql(
                "deleteConfigFile",
                "mutation f($id: ID, $expectedVersion: Long) "
                "{ deleteConfigFile(id: $id, expectedVersion: $expectedVersion) { udoId } }",
                {"id": name, "expectedVersion": expected_version},
                scope=scope,
            )
        still = self.config_file(name=name, udo_id=udo_id, scope=scope)
        if still:
            target = f"udoId {udo_id}" if udo_id else name
            raise SDLAPIError(
                200,
                f"delete_config_file: {target} still exists after the delete mutation "
                f"(version {still.get('version')}). The mutation reported no errors "
                "but nothing was removed.",
                still,
            )
        return {
            "status": "success",
            "deleted": {"udoId": str(udo_id)} if udo_id else {"name": name},
            "raw": (raw or {}).get("deleteConfigFile"),
        }

    # =========================================================================
    # Dashboard lifecycle (dashboardsV2, GraphQL)
    #
    # A SECOND, higher-level surface on the same POST /sdl/v2/graphql endpoint;
    # it is what the console itself drives. Captured from live console traffic
    # on usea1-purple 2026-08-17.
    #
    #   dashboardsV2   dashboard-aware: name, description, tabs, access/sharing,
    #                  authorship. Create takes the whole document as one string.
    #   configFiles    the raw file underneath, addressed by udoId. Same object,
    #                  no sharing metadata.
    #
    # The `id` here IS the `udoId` there.
    #
    # TWO VERSION FIELDS, do not cross them: getDashboardV2 returns
    # version="" (a display string), configFile returns the numeric CAS token.
    # Only the configFile value is valid as expected_version.
    # =========================================================================

    _DASHBOARD_SUMMARY_FIELDS = "id name description configType access { public users owner }"

    _VALID_SCOPE_TYPES = frozenset({"site", "account", "global"})
    _VALID_SCOPE_OPS = frozenset({"ADD", "REMOVE"})

    def list_dashboards(self, scope: Any = _UNSET) -> List[Dict[str, Any]]:
        """Dashboards visible at `scope`, with owner and sharing metadata.

        Prefer this over config_files(scope=...) filtered to /dashboards/ when you
        need `access`; prefer config_files when you need the numeric version.
        """
        data = self._graphql(
            "GetDashboardNames",
            f"query GetDashboardNames {{ dashboardsV2 {{ {self._DASHBOARD_SUMMARY_FIELDS} }} }}",
            read_only=True,
            scope=scope,
        )
        return data.get("dashboardsV2") or []

    def get_dashboard(
        self,
        dashboard_id: Optional[str] = None,
        name: Optional[str] = None,
        scope: Any = _UNSET,
    ) -> Optional[Dict[str, Any]]:
        """One dashboard including tabs. Returns None when absent at `scope`.

        `tabs[].graphs` / `.parameters` / `.filters` / `.options` come back as
        JSON STRINGS, not objects; the console parses them client-side.

        Absence handling mirrors config_file deliberately. It is not established
        whether a missing dashboard returns null data or a GraphQL error, so both
        are treated as absence and disambiguated against the listing. Assuming
        only the null form is what broke every delete in 1.3.2: the confirming
        re-read threw on exactly the success path.
        """
        if not dashboard_id and not name:
            raise ValueError("get_dashboard requires either dashboard_id or name")
        try:
            data = self._graphql(
                "GetDashboardConfigV2",
                "query GetDashboardConfigV2($id: ID, $dashboardName: String) { "
                "getDashboardV2(id: $id, dashboardName: $dashboardName, resolveParameters: true) { "
                "id name description configType duration isBuiltIn isEditable version "
                "access { public users owner } "
                "tabs { tabName parameters graphs filters options } "
                "createdAt createdBy updatedAt updatedBy } }",
                {
                    "id": str(dashboard_id) if dashboard_id else None,
                    "dashboardName": name,
                },
                read_only=True,
                scope=scope,
            )
        except SDLAPIError as exc:
            if not getattr(exc, "graphql", False):
                raise
            try:
                all_dashboards = self.list_dashboards(scope=scope)
            except SDLAPIError as list_exc:
                raise SDLAPIError(
                    exc.status,
                    f"{exc} (absence check failed: {list_exc})",
                    exc.body,
                ) from exc
            if dashboard_id:
                present = any(str(d.get("id")) == str(dashboard_id) for d in all_dashboards)
            else:
                present = any(_matches_name(d, name) for d in all_dashboards)
            if not present:
                return None
            raise
        return data.get("getDashboardV2")

    def create_dashboard(
        self,
        name: str,
        config: str,
        public: bool = True,
        scope: Any = _UNSET,
        fail_if_name_exists: bool = False,
    ) -> Dict[str, Any]:
        """Create a dashboard from a full dashboard-JSON document, at `scope`.

        This is the console's own create path and the preferred way to deploy a
        new dashboard: it takes the complete document (configType, duration,
        description, tabs[]) as ONE string.

        It also sidesteps the UI stub-append trap. Creating an empty dashboard in
        the console starts from a `{graphs: []}` stub; pasting after it instead of
        replacing it yields `{graphs: []}{...}` and the server answers
        "Content is invalid json / Additional text after JSON object", leaving an
        empty shell behind that looks like a render bug.

        `public` DEFAULTS TO TRUE here, unlike the raw API which defaults it to
        false. `access.owner` is the calling identity; with a service-account token
        that is `serviceuser-<uuid>@mgmt-<n>.sentinelone.net`, not a person, and a
        private service-user dashboard is readable through the API but INVISIBLE in
        the console to the human operator at any scope. That is indistinguishable
        from a failed deploy. Pass public=False deliberately for a private one.

        Names reject punctuation and answer only "Invalid name". Accepted: letters,
        digits, space, - _ . / . Rejected: ( ) [ ] { } : , & ' % # .

        DUPLICATE NAMES ARE ALLOWED here, unlike put_config_file: the console
        itself creates "<name> - Copy" siblings and shareResource addresses
        dashboards by id. Pass fail_if_name_exists=True to refuse instead.
        """
        if not name or not isinstance(name, str):
            raise ValueError("create_dashboard requires a name")
        if not isinstance(config, str) or not config.strip():
            raise ValueError(
                "create_dashboard requires config as a JSON string (the full dashboard document)."
            )
        try:
            json.loads(config)
        except ValueError as exc:
            raise ValueError(
                f"create_dashboard: config is not valid JSON ({exc}). If this came from the "
                "console's JSON editor, check for a leading '{graphs: []}' stub: the new "
                "document must REPLACE it, not follow it."
            ) from exc

        if fail_if_name_exists:
            existing = [d for d in self.list_dashboards(scope=scope) if _matches_name(d, name)]
            if existing:
                ids = ", ".join(str(d.get("id")) for d in existing)
                raise ValueError(
                    f'create_dashboard: {len(existing)} dashboard(s) named "{name}" already '
                    f"exist at this scope (ids: {ids}). Pass fail_if_name_exists=False to "
                    "create a sibling anyway."
                )

        data = self._graphql(
            "CreateDashboard",
            "mutation CreateDashboard($dashboardName: String!, $config: String, $public: Boolean) "
            "{ createDashboardV2(dashboardName: $dashboardName, config: $config, public: $public) "
            "{ id name } }",
            {"dashboardName": name, "config": config, "public": bool(public)},
            scope=scope,
        )
        created = data.get("createDashboardV2") or {}
        if not created.get("id"):
            raise SDLAPIError(
                200,
                "create_dashboard: mutation returned no id, so the dashboard was not created.",
                data,
                graphql=True,
            )
        return created

    def share_dashboard(
        self,
        dashboard_id: str,
        scopes: Optional[List[Dict[str, Any]]] = None,
        users: Optional[List[Dict[str, Any]]] = None,
        scope: Any = _UNSET,
    ) -> Dict[str, Any]:
        """Share (or unshare) a dashboard to scopes and/or users.

        THE ONLY SDL OPERATION THAT TAKES AN EXPLICIT SCOPE TARGET; everything
        else infers scope from the S1-Scope header. Use it to push an
        account-scoped dashboard down to a site without recreating it.

        Note the two different scope arguments: `scopes` is WHERE THE DASHBOARD
        GOES; `scope` is the header for this call, i.e. where you are standing.

        Each `scopes` entry is {scopeType, scopeId, operation}: scopeType is
        site | account | global, scopeId is the numeric id from
        /web/api/v2.1/sites or /accounts, operation is ADD | REMOVE.
        """
        if not dashboard_id:
            raise ValueError("share_dashboard requires dashboard_id")
        scopes = list(scopes or [])
        users = list(users or [])
        if not scopes and not users:
            raise ValueError(
                "share_dashboard: pass at least one scope or user, otherwise the call is a no-op."
            )
        # Validate up front: the server accepts a malformed entry and silently
        # shares nothing, which reads as success.
        normalised: List[Dict[str, str]] = []
        for i, entry in enumerate(scopes):
            scope_type = str((entry or {}).get("scopeType", "")).lower()
            operation = str((entry or {}).get("operation", "ADD")).upper()
            scope_id = str((entry or {}).get("scopeId", ""))
            if scope_type not in self._VALID_SCOPE_TYPES:
                raise ValueError(
                    f"share_dashboard: scopes[{i}].scopeType must be one of "
                    f"{sorted(self._VALID_SCOPE_TYPES)} (got {(entry or {}).get('scopeType')!r})."
                )
            if operation not in self._VALID_SCOPE_OPS:
                raise ValueError(
                    f"share_dashboard: scopes[{i}].operation must be ADD or REMOVE "
                    f"(got {(entry or {}).get('operation')!r})."
                )
            if scope_type != "global" and not re.fullmatch(r"\d+", scope_id):
                raise ValueError(
                    f"share_dashboard: scopes[{i}].scopeId must be a numeric id for "
                    f'scopeType "{scope_type}" (got {(entry or {}).get("scopeId")!r}).'
                )
            normalised.append(
                {"scopeType": scope_type, "scopeId": scope_id, "operation": operation}
            )

        data = self._graphql(
            "ShareDashboard",
            "mutation ShareDashboard($id: ID!, $users: [UserSharingCommand], "
            "$scopes: [ScopeSharingCommand]) "
            "{ shareResource(id: $id, users: $users, scopes: $scopes) { id name } }",
            {"id": str(dashboard_id), "users": users, "scopes": normalised},
            scope=scope,
        )
        shared = data.get("shareResource") or {}
        if not shared.get("id"):
            raise SDLAPIError(
                200,
                "share_dashboard: shareResource returned no id, so nothing was shared.",
                data,
                graphql=True,
            )
        return {
            "status": "success",
            "dashboard": {"id": str(shared.get("id")), "name": shared.get("name")},
            "scopes": normalised,
            "users": users,
        }

    def save_dashboard_layout(
        self,
        graphs: str,
        tab_name: str,
        dashboard_id: Optional[str] = None,
        name: Optional[str] = None,
        options: Optional[str] = None,
        scope: Any = _UNSET,
    ) -> Optional[Dict[str, Any]]:
        """Replace the panel layout of ONE tab.

        `graphs` is a JSON string shaped {"graphs": [...]}, INCLUDING the wrapper
        key, even though the response echoes a bare array. Use create_dashboard
        for a whole document, or put_config_file with expected_version to rewrite
        an existing dashboard's full config.
        """
        if not dashboard_id and not name:
            raise ValueError("save_dashboard_layout requires either dashboard_id or name")
        if not isinstance(graphs, str) or not graphs.strip():
            raise ValueError(
                'save_dashboard_layout requires graphs as a JSON string shaped {"graphs":[...]}.'
            )
        try:
            parsed = json.loads(graphs)
            if not isinstance(parsed, dict) or not isinstance(parsed.get("graphs"), list):
                raise ValueError('missing the top-level "graphs" array')
        except ValueError as exc:
            raise ValueError(
                f'save_dashboard_layout: graphs is not a valid {{"graphs":[...]}} JSON string ({exc}).'
            ) from exc

        data = self._graphql(
            "SaveDashboardLayout",
            "mutation SaveDashboardLayout($id: ID, $dashboardName: String, $graphs: String, "
            "$options: String, $tabName: String) "
            "{ saveDashboardLayout(id: $id, dashboardName: $dashboardName, graphs: $graphs, "
            "options: $options, tabName: $tabName) { graphs options } }",
            {
                "id": str(dashboard_id) if dashboard_id else None,
                "dashboardName": name,
                "graphs": graphs,
                "options": options,
                "tabName": tab_name,
            },
            scope=scope,
        )
        return data.get("saveDashboardLayout")

    def delete_dashboard(
        self,
        dashboard_id: Optional[str] = None,
        name: Optional[str] = None,
        scope: Any = _UNSET,
    ) -> Dict[str, Any]:
        """Delete a dashboard by id or name.

        `deleteDashboard` returns a bare boolean, so per the house rule removal is
        confirmed by re-reading rather than trusted from the mutation response.
        """
        if not dashboard_id and not name:
            raise ValueError("delete_dashboard requires either dashboard_id or name")
        data = self._graphql(
            "DeleteDashboard",
            "mutation DeleteDashboard($id: ID, $dashboardName: String) "
            "{ deleteDashboard(id: $id, dashboardName: $dashboardName) }",
            {
                "id": str(dashboard_id) if dashboard_id else None,
                "dashboardName": name,
            },
            scope=scope,
        )
        reported = (data or {}).get("deleteDashboard")
        still = self.get_dashboard(dashboard_id=dashboard_id, name=name, scope=scope)
        if still:
            target = f"id {dashboard_id}" if dashboard_id else str(name)
            raise SDLAPIError(
                200,
                f"delete_dashboard: {target} still exists after the delete mutation "
                f"(mutation returned {reported!r}). Nothing was removed.",
                still,
            )
        return {
            "status": "success",
            "deleted": {"id": str(dashboard_id)} if dashboard_id else {"name": name},
            "raw": reported,
        }

    # =========================================================================
    # Configuration files (legacy REST)
    # =========================================================================
    def list_files(self) -> Dict[str, Any]:
        """POST /api/listFiles. INCOMPLETE: omits udoId-addressed dashboards.

        Prefer `config_files()`. Never use this listing to decide whether a
        file exists.
        """
        return self._request("POST", "/api/listFiles", json_body={})

    def get_file(
        self,
        path: str,
        expected_version: Optional[int] = None,
        prettyprint: bool = False,
    ) -> Dict[str, Any]:
        """POST /api/getFile: read a configuration file.

        If `expected_version` matches the stored version, status is
        'success/unchanged' and no content is returned.
        """
        body: Dict[str, Any] = {"path": path}
        if expected_version is not None:
            body["expectedVersion"] = expected_version
        if prettyprint:
            body["prettyprint"] = True
        return self._request("POST", "/api/getFile", json_body=body)

    def put_file(
        self,
        path: str,
        content: Optional[str] = None,
        expected_version: Optional[int] = None,
        prettyprint: bool = False,
        delete: bool = False,
    ) -> Dict[str, Any]:
        """POST /api/putFile: create, update, or delete a config file.

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
        return self._request("POST", "/api/putFile", json_body=body)

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
    # Smoke test: list configuration files.
    c = SDLClient()
    print(json.dumps(c.config_files(), indent=2)[:2000])
