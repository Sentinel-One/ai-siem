"""
UAM (Unified Alert Management) Alert Interface helper.

Write-side API that pushes OCSF-formatted indicators and alerts INTO
UAM so they surface in the console as real alerts with attached
indicators. Separate host + wire contract from the Mgmt Console REST
and the UAM GraphQL query layer (both of which are READ/mutate on
pre-existing state).

Host (region-specific, e.g. US1 shown — see https://community.sentinelone.com/s/article/000004961 for your region):
    https://ingest.us1.sentinelone.net


Wire contract
-------------
  * Content-Encoding: gzip (mandatory; zstd also accepted by the server)
  * Authorization:    Bearer <JWT>          -- NOT "ApiToken ..."
  * S1-Scope:         <accountId>[:<siteId>[:<groupId>]]
  * Body:             concatenated JSON (one or more objects back-to-back,
                      optionally newline-separated), then gzip-compressed.
                      Used for both the single-object and the batch case.
  * Response:         202 Accepted with {"details":"Success","status":202}
                      on success; 4xx JSON {"details":"...", "status":<n>}
                      on rejection.

Auth token
----------
The interface accepts the same service-user JWT used for the Mgmt
Console API (loaded from credentials.json via S1Client.api_token —
canonical key `S1_CONSOLE_API_TOKEN`).
`ApiToken <token>` is rejected with HTTP 401
`{"details":"Unsupported auth type: ApiToken"}`, so callers MUST switch
to the `Bearer` scheme when talking to this endpoint family.

Indicator <-> alert linkage
---------------------------
Indicators live at /v1/indicators and must carry:
    metadata.profiles = ["s1/security_indicator"]
    metadata.uid      = "<uuid>"   # the linkage key
Alerts live at /v1/alerts and reference indicators by UID:
    finding_info.related_events[].uid = "<indicator metadata.uid>"
The server stitches them once both sides land. A single alert MAY
reference many indicators by including multiple related_events entries
(one per indicator uid).

Batching
--------
POST /v1/indicators accepts N indicators per call (concatenated JSON,
gzip-compressed); batching indicators is the idiomatic path.

POST /v1/alerts is DIFFERENT. Empirically (usea1-acme 2026-04-22) the
gateway accepts multi-alert bodies and returns HTTP 202, but the
stitcher silently drops all but one of the alerts. Call /v1/alerts with
ONE alert per invocation; loop if you have many. `post_alerts` emits a
RuntimeWarning when called with more than one alert to flag the issue.

Race condition between /v1/indicators and /v1/alerts
----------------------------------------------------
The stitcher resolves `finding_info.related_events[].uid` against the
set of indicators already registered for the scope. Posting the alert
immediately after the indicators can fire those lookups before the
indicator's `metadata.uid` lands, which silently drops the alert
(HTTP 202 still returned). A ~3s sleep between the two POSTs avoids
this; the `post_alert_with_indicators` helper builds the sleep in.

Usage
-----
    from s1_client import S1Client
    from uam_alert_interface import (
        UAMAlertInterfaceClient,
        build_file_indicator, build_process_indicator,
        build_network_indicator, build_alert_referencing,
    )

    mgmt = S1Client()
    uam  = UAMAlertInterfaceClient(bearer_token=mgmt.api_token)

    # Preferred safe path: one helper call per alert. It POSTs the
    # indicators, sleeps 3s, then POSTs the single alert.
    uam.post_alert_with_indicators(alert, [ind1, ind2, ind3],
                                   scope=f"{acct}:{site}")

    # Low-level path (only if you need custom ordering). Remember: ONE
    # alert per /v1/alerts call, and sleep between the two POSTs.
    uam.post_indicators([ind1, ind2, ind3], scope=f"{acct}:{site}")
    time.sleep(3)
    uam.post_alerts([alert_linking_all_three], scope=f"{acct}:{site}")
"""
from __future__ import annotations

import gzip
import json
import os
import time
import urllib.error
import urllib.request
import warnings
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


_DEFAULT_PROD_HOST = "https://ingest.us1.sentinelone.net"

# Optional override key in credentials.json or config.json.
# If not present the helper falls back to _DEFAULT_PROD_HOST.
# Canonical key is S1_HEC_INGEST_URL: the host serves both log ingest
# and OCSF alert/indicator ingest, so the variable name reflects that.
# Aliases are read for backward compatibility.
_CONFIG_KEY = "S1_HEC_INGEST_URL"
_LEGACY_CONFIG_KEYS = (
    "S1_UAM_ALERT_INTERFACE_URL",  # former canonical
    "uam_alert_interface_url",     # legacy snake_case
)


# ---- OCSF observable.type_id values (from OCSF Observable Type ID enum)
# Used by the build_* helpers so callers don't have to memorise them.
OBS_HOSTNAME       = 1
OBS_IP_ADDRESS     = 2
OBS_MAC_ADDRESS    = 3
OBS_USER_NAME      = 4
OBS_EMAIL_ADDRESS  = 5
OBS_URL_STRING     = 6
OBS_FILE_NAME      = 7
OBS_HASH           = 8
OBS_PROCESS_NAME   = 9
OBS_RESOURCE_UID   = 10

# Mapping from OCSF observable.type_id to the UI-friendly (type, typeName)
# pair carried on related_events[].observables[]. Per the UAM "Alert and
# Indicator Ingestion" doc, populating these lets the Indicators tab
# render without a secondary lookup against SDL.
_OBS_TYPE_META: Dict[int, tuple] = {
    OBS_HOSTNAME:      ("string",  "Hostname"),
    OBS_IP_ADDRESS:    ("ip",      "IP Address"),
    OBS_MAC_ADDRESS:   ("string",  "MAC Address"),
    OBS_USER_NAME:     ("string",  "User Name"),
    OBS_EMAIL_ADDRESS: ("string",  "Email Address"),
    OBS_URL_STRING:    ("string",  "URL String"),
    OBS_FILE_NAME:     ("string",  "File Name"),
    OBS_HASH:          ("string",  "Hash"),
    OBS_PROCESS_NAME:  ("string",  "Process Name"),
    OBS_RESOURCE_UID:  ("integer", "Resource UID"),
}


def _enrich_observable_for_alert(obs: Dict[str, Any]) -> Dict[str, Any]:
    """Copy an observable onto an alert's related_events[] entry,
    adding the `type` + `typeName` fields the UAM UI reads for rendering.
    """
    type_id = obs.get("type_id")
    t, tn = _OBS_TYPE_META.get(type_id, ("string", "Other"))
    out = {
        "name": obs.get("name"),
        "type_id": type_id,
        "type": t,
        "typeName": tn,
        "value": obs.get("value"),
    }
    return out


def _walk_up_for_workspace_creds() -> Optional[Path]:
    """Find a workspace-scoped .claude/sentinelone/credentials.json.

    Two-pass search: cwd walk-up first, then scan $HOME/mnt/ * for
    Cowork-mounted workspace folders (skips system mounts).
    """
    try:
        cwd = Path.cwd().resolve()
    except (OSError, RuntimeError):
        cwd = None
    if cwd is not None:
        for i, parent in enumerate([cwd, *cwd.parents]):
            if i >= 20:
                break
            candidate = parent / ".claude" / "sentinelone" / "credentials.json"
            if candidate.is_file():
                return candidate
    home_mnt = Path.home() / "mnt"
    if home_mnt.is_dir():
        skip = {".claude", ".auto-memory", ".remote-plugins", "outputs", "uploads"}
        try:
            entries = sorted(home_mnt.iterdir())
        except OSError:
            entries = []
        for entry in entries:
            if not entry.is_dir() or entry.name in skip:
                continue
            candidate = entry / ".claude" / "sentinelone" / "credentials.json"
            if candidate.is_file():
                return candidate
    return None


def _load_config_url() -> Optional[str]:
    """Resolve the UAM Alert Interface URL across all credential layers.

    Priority (highest wins): workspace .claude > $CLAUDE_CONFIG_DIR
    > ~/.claude > ~/.config > skill config.json. The first non-empty
    value wins; iteration is highest-to-lowest so we can short-circuit.
    """
    _claude_config_dir = os.environ.get("CLAUDE_CONFIG_DIR", "")
    _plugin_creds = (Path(_claude_config_dir) / "sentinelone" / "credentials.json"
                     if _claude_config_dir else None)
    _dotclaude_creds = Path.home() / ".claude" / "sentinelone" / "credentials.json"
    _home_creds = Path.home() / ".config" / "sentinelone" / "credentials.json"
    _local_config = Path(__file__).resolve().parent.parent / "config.json"
    _workspace_creds = _walk_up_for_workspace_creds()
    # Highest priority first.
    candidates = [p for p in [_workspace_creds, _plugin_creds, _dotclaude_creds, _home_creds, _local_config] if p]
    for cfg_path in candidates:
        if not cfg_path.is_file():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception:
            continue
        for key in (_CONFIG_KEY, *_LEGACY_CONFIG_KEYS):
            url = cfg.get(key)
            if isinstance(url, str) and url.strip():
                return url.rstrip("/")
    return None


class UAMAlertInterfaceError(RuntimeError):
    def __init__(self, status: int, body: str, *, method: str, url: str):
        self.status = status
        self.body = body
        self.method = method
        self.url = url
        super().__init__(f"HTTP {status} on {method} {url}: {body}")


class UAMAlertInterfaceClient:
    """Thin wrapper over POST /v1/indicators and POST /v1/alerts against
    the UAM Alert Interface (Unified Alert Management ingestion surface).

    Intentionally stdlib-only (urllib + gzip) so it has no coupling to
    the `requests`-based S1Client and can run in a fresh Python without
    extra deps.
    """

    def __init__(
        self,
        *,
        bearer_token: str,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
    ):
        if not bearer_token or bearer_token.startswith("REPLACE"):
            raise RuntimeError(
                "UAMAlertInterfaceClient requires a non-empty bearer_token "
                "(typically the same JWT as S1Client.api_token)."
            )
        self.bearer_token = bearer_token
        # Resolution priority: explicit base_url arg > S1_HEC_INGEST_URL env >
        # legacy S1_UAM_ALERT_INTERFACE_URL env > credentials.json > default.
        self.base_url = (
            (base_url
             or os.environ.get("S1_HEC_INGEST_URL")
             or os.environ.get("S1_UAM_ALERT_INTERFACE_URL")
             or _load_config_url()
             or _DEFAULT_PROD_HOST)
            .rstrip("/")
        )
        self.timeout = timeout

    # ------------------------------------------------------------------ core
    @staticmethod
    def _encode_batch(objs: Iterable[Dict[str, Any]]) -> bytes:
        """Concatenated JSON (newline-separated) + gzip compression.

        Both the single-object case and the batch case go through this
        path, so the wire format is always identical.
        """
        items = list(objs)
        if not items:
            raise ValueError("batch is empty")
        raw = ("\n".join(json.dumps(o, separators=(",", ":")) for o in items)
               ).encode("utf-8")
        return gzip.compress(raw)

    def _post(self, path: str, objs: Iterable[Dict[str, Any]], *, scope: str,
              trace_id: Optional[str] = None) -> Dict[str, Any]:
        if not scope:
            raise ValueError(
                "S1-Scope is mandatory. Pass scope='<accountId>' or "
                "'<accountId>:<siteId>'."
            )
        url = f"{self.base_url}{path}"
        body_gz = self._encode_batch(objs)
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
            "S1-Scope": scope,
        }
        if trace_id:
            headers["S1-Trace-Id"] = trace_id
        req = urllib.request.Request(url, data=body_gz, method="POST",
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                try:
                    return json.loads(raw.decode("utf-8"))
                except Exception:
                    return {"status": resp.status, "raw": raw[:500].decode(
                        "utf-8", errors="replace")}
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = "<unreadable body>"
            raise UAMAlertInterfaceError(e.code, body, method="POST", url=url)

    # ------------------------------------------------------------------ API
    def post_indicators(self, indicators: List[Dict[str, Any]], *, scope: str,
                        trace_id: Optional[str] = None) -> Dict[str, Any]:
        """POST /v1/indicators. One or many per call.

        Each indicator MUST carry:
            metadata.profiles >= ["s1/security_indicator"]
            metadata.uid       = <uuid>          # linkage key
            class_uid / type_uid / activity_id   # OCSF required
            observables[]                        # surfaces in UAM Indicators tab
        """
        return self._post("/v1/indicators", indicators, scope=scope,
                          trace_id=trace_id)

    def post_alerts(self, alerts: List[Dict[str, Any]], *, scope: str,
                    trace_id: Optional[str] = None) -> Dict[str, Any]:
        """POST /v1/alerts. Call with ONE alert per invocation.

        Each alert MUST reference its indicator(s) via:
            finding_info.related_events[].uid == indicator.metadata.uid

        A single alert may reference MANY indicators by including multiple
        related_events entries, one per uid. The server stitches them into
        the alert's Indicators tab once both sides land on the tenant.

        Multi-alert bodies: the wire format accepts concatenated JSON for
        N alerts in one POST, and the gateway returns HTTP 202, but the
        stitcher has been observed to silently drop all but one of the
        alerts (usea1-acme 2026-04-22). Loop callers over this method
        one alert at a time, or use `post_alert_with_indicators`, which
        enforces the safe pattern. A RuntimeWarning is emitted when
        `alerts` has more than one entry so callers notice the hazard.
        """
        if len(alerts) > 1:
            warnings.warn(
                "UAM Alert Interface: posting multiple alerts in a single "
                "POST /v1/alerts call silently drops all but one alert "
                "(HTTP 202 still returned). Loop callers one alert at a "
                "time, or use UAMAlertInterfaceClient."
                "post_alert_with_indicators().",
                RuntimeWarning,
                stacklevel=2,
            )
        return self._post("/v1/alerts", alerts, scope=scope, trace_id=trace_id)

    def post_alert_with_indicators(
        self,
        alert: Dict[str, Any],
        indicators: List[Dict[str, Any]],
        *,
        scope: str,
        sleep_between_s: float = 3.0,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Safely ingest one alert with its supporting indicators.

        This wraps the canonical two-step sequence proven to get alerts
        to surface in UAM without silent stitcher drops:

          1. POST all `indicators` to /v1/indicators (batched is fine;
             N indicators per call is the idiomatic path).
          2. Sleep `sleep_between_s` (default 3s) so each indicator's
             `metadata.uid` is registered before the alert's
             `finding_info.related_events[].uid` lookups fire.
          3. POST `alert` BY ITSELF to /v1/alerts.

        Two empirical failure modes this helper prevents (confirmed on
        `usea1-acme` 2026-04-22):

          * Back-to-back POSTs with no sleep: the stitcher can resolve
            `related_events[].uid` before the indicator lands on the
            scope, silently dropping the alert. HTTP 202 is still
            returned. `test_uam_alert_interface_batch.py` uses a 3s
            sleep for this reason; reducing it below ~2s has been
            observed to regress on loaded tenants.
          * Multiple alerts in one POST: the wire format accepts it,
            HTTP 202 is returned, but the stitcher silently drops all
            but one. Callers with many alerts should loop this helper
            once per alert.

        Arguments
        ---------
        alert: a single alert dict (as built by `build_alert_referencing`).
        indicators: list of indicator dicts referenced by the alert via
            `finding_info.related_events[].uid`. May include indicators
            not referenced by this alert -- extras are harmless.
        scope: `S1-Scope` header value. Mandatory.
        sleep_between_s: seconds to sleep between the indicator POST and
            the alert POST. Defaults to 3.0; do not reduce unless you
            are certain the target tenant is unloaded.
        trace_id: optional `S1-Trace-Id` header value. Applied to both
            POSTs so they can be correlated in server-side traces.

        Returns
        -------
        `{"indicators": <indicator_resp>, "alert": <alert_resp>}`.
        """
        if not indicators:
            raise ValueError(
                "post_alert_with_indicators requires >=1 indicator; "
                "the alert's related_events[].uid must match an indicator "
                "metadata.uid for the stitcher to surface it.")
        indicator_resp = self.post_indicators(
            indicators, scope=scope, trace_id=trace_id)
        time.sleep(sleep_between_s)
        alert_resp = self.post_alerts(
            [alert], scope=scope, trace_id=trace_id)
        return {"indicators": indicator_resp, "alert": alert_resp}


# -------------------------------------------------------------------- helpers

def _observable(name: str, type_id: int, value: str) -> Dict[str, Any]:
    """Build one OCSF observable dict. Kept as a helper so callers don't
    hand-mix field orders."""
    return {"name": name, "type_id": type_id, "value": value}


def _base_indicator(
    *,
    indicator_uid: str,
    now_ms: int,
    class_uid: int,
    activity_id: int,
    category_uid: int,
    device_uid: str,
    device_hostname: str,
    user_uid: str,
    user_name: str,
    message: str,
    observables: List[Dict[str, Any]],
    severity_id: int = 2,
    extra_top_level: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Common skeleton for every OCSF indicator this module builds. The
    class/activity-specific fields (file / process / network) come in
    via `extra_top_level`."""
    body: Dict[str, Any] = {
        "message": message,
        "time": now_ms,
        "device": {
            "uid": device_uid,
            "name": device_hostname,
            "type_id": 1,
            "hostname": device_hostname,
        },
        "metadata": {
            "version": "1.6.0-dev",
            "product": {"name": "smoke-product"},
            "extensions": [{"name": "s1", "uid": "998", "version": "0.1.0"}],
            "profiles": ["s1/security_indicator"],
            "uid": indicator_uid,
        },
        "type_uid": class_uid * 100 + activity_id,
        "activity_id": activity_id,
        "class_uid": class_uid,
        "category_uid": category_uid,
        "observables": observables,
        "actor": {
            "user": {
                "name": user_name,
                "type": "System",
                "uid": user_uid,
                "type_id": 3,
            }
        },
        "severity_id": severity_id,
        "attack_surface_id": 1,
    }
    if extra_top_level:
        body.update(extra_top_level)
    return body


def build_file_indicator(
    *,
    indicator_uid: str,
    file_name: str,
    device_uid: str,
    device_hostname: str,
    user_uid: str,
    user_name: str = "smoke-user",
    now_ms: int,
    message: Optional[str] = None,
    severity_id: int = 2,
    # Optional enrichments -- any observable the caller adds is both
    # attached to the observables[] array AND the corresponding top-level
    # OCSF field, so the record is schema-valid.
    file_path: Optional[str] = None,
    file_sha256: Optional[str] = None,
    file_md5: Optional[str] = None,
    device_ip: Optional[str] = None,
    activity_id: int = 1,   # 1=Create, 2=Read, 3=Update, 4=Delete, ...
) -> Dict[str, Any]:
    """OCSF FileSystem Activity indicator (class_uid=1001).

    Observables populated:
        * file.name                     (always)
        * file.path                     (if file_path)
        * file.hashes.sha256            (if file_sha256)
        * file.hashes.md5               (if file_md5)
        * device.ip                     (if device_ip)
        * device.hostname               (always)
    """
    observables = [
        _observable("file.name", OBS_FILE_NAME, file_name),
        _observable("device.hostname", OBS_HOSTNAME, device_hostname),
    ]
    file_obj: Dict[str, Any] = {"name": file_name, "type_id": 1}
    if file_path:
        file_obj["path"] = file_path
        observables.append(_observable("file.path", OBS_FILE_NAME, file_path))
    # OCSF 1.6.0 file.hashes is Array of Fingerprint objects, NOT a dict.
    # Empirically (diag2 on usea1-acme 2026-04-22): posting hashes as a
    # dict ({"sha256": "..."}) causes the UAM indicator stitcher to silently
    # drop the indicator (POST still returns 202). The correct Fingerprint
    # shape is {"algorithm_id": <int>, "algorithm": "<name>", "value": "<hex>"}.
    # OCSF algorithm_id enum: 1=unknown, 2=MD5, 3=SHA-1 (v1.5) / SHA-256 in
    # newer profiles; we follow S1's 'security_indicator' profile where
    # sha256 uses id=3 and md5 uses id=2.
    hashes_arr: List[Dict[str, Any]] = []
    if file_sha256:
        hashes_arr.append({"algorithm_id": 3, "algorithm": "SHA-256",
                           "value": file_sha256})
        observables.append(_observable(
            "file.hashes.sha256", OBS_HASH, file_sha256))
    if file_md5:
        hashes_arr.append({"algorithm_id": 2, "algorithm": "MD5",
                           "value": file_md5})
        observables.append(_observable(
            "file.hashes.md5", OBS_HASH, file_md5))
    if hashes_arr:
        file_obj["hashes"] = hashes_arr
    extra: Dict[str, Any] = {"file": file_obj}
    if device_ip:
        observables.append(_observable("device.ip", OBS_IP_ADDRESS, device_ip))
    return _base_indicator(
        indicator_uid=indicator_uid,
        now_ms=now_ms,
        class_uid=1001,
        activity_id=activity_id,
        category_uid=1,
        device_uid=device_uid,
        device_hostname=device_hostname,
        user_uid=user_uid,
        user_name=user_name,
        message=message or f"File {file_name} {('action_' + str(activity_id))}",
        observables=observables,
        severity_id=severity_id,
        extra_top_level=extra,
    )


def build_process_indicator(
    *,
    indicator_uid: str,
    process_name: str,
    process_pid: int,
    process_cmd_line: Optional[str],
    device_uid: str,
    device_hostname: str,
    user_uid: str,
    user_name: str = "smoke-user",
    now_ms: int,
    message: Optional[str] = None,
    severity_id: int = 2,
    parent_process_name: Optional[str] = None,
) -> Dict[str, Any]:
    """OCSF Process Activity indicator (class_uid=1007, activity=Launch).

    Observables populated:
        * process.name                  (always)
        * process.pid                   (always)
        * process.cmd_line              (if cmd_line)
        * process.parent_process.name   (if parent_process_name)
        * device.hostname               (always)
    """
    observables = [
        _observable("process.name", OBS_PROCESS_NAME, process_name),
        _observable("process.pid", OBS_RESOURCE_UID, str(process_pid)),
        _observable("device.hostname", OBS_HOSTNAME, device_hostname),
    ]
    process: Dict[str, Any] = {
        "name": process_name,
        "pid": process_pid,
    }
    if process_cmd_line:
        process["cmd_line"] = process_cmd_line
        observables.append(_observable(
            "process.cmd_line", OBS_PROCESS_NAME, process_cmd_line))
    if parent_process_name:
        process["parent_process"] = {"name": parent_process_name, "pid": 1}
        observables.append(_observable(
            "process.parent_process.name", OBS_PROCESS_NAME,
            parent_process_name))
    return _base_indicator(
        indicator_uid=indicator_uid,
        now_ms=now_ms,
        class_uid=1007,
        activity_id=1,   # Launch
        category_uid=1,
        device_uid=device_uid,
        device_hostname=device_hostname,
        user_uid=user_uid,
        user_name=user_name,
        message=message or f"Process {process_name} launched (pid={process_pid})",
        observables=observables,
        severity_id=severity_id,
        extra_top_level={"process": process},
    )


def build_network_indicator(
    *,
    indicator_uid: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    url: Optional[str],
    device_uid: str,
    device_hostname: str,
    user_uid: str,
    user_name: str = "smoke-user",
    now_ms: int,
    message: Optional[str] = None,
    severity_id: int = 2,
) -> Dict[str, Any]:
    """OCSF Network Activity indicator (class_uid=4001, activity=Open).

    Observables populated:
        * src_endpoint.ip       (always)
        * dst_endpoint.ip       (always)
        * dst_endpoint.port     (always)
        * url.full              (if url)
        * device.hostname       (always)
    """
    observables = [
        _observable("src_endpoint.ip", OBS_IP_ADDRESS, src_ip),
        _observable("dst_endpoint.ip", OBS_IP_ADDRESS, dst_ip),
        _observable("dst_endpoint.port", OBS_RESOURCE_UID, str(dst_port)),
        _observable("device.hostname", OBS_HOSTNAME, device_hostname),
    ]
    extra: Dict[str, Any] = {
        "src_endpoint": {"ip": src_ip},
        "dst_endpoint": {"ip": dst_ip, "port": dst_port},
    }
    if url:
        extra["url"] = {"url_string": url}
        observables.append(_observable("url.full", OBS_URL_STRING, url))
    return _base_indicator(
        indicator_uid=indicator_uid,
        now_ms=now_ms,
        class_uid=4001,
        activity_id=1,    # Open
        category_uid=4,   # Network Activity
        device_uid=device_uid,
        device_hostname=device_hostname,
        user_uid=user_uid,
        user_name=user_name,
        message=message or f"Network {src_ip} -> {dst_ip}:{dst_port}",
        observables=observables,
        severity_id=severity_id,
        extra_top_level=extra,
    )


def build_alert_referencing(
    *,
    alert_uid: str,
    indicators: List[Dict[str, Any]],
    now_ms: int,
    title: str,
    description: str,
    severity_id: int = 2,
    detection_product: str = "smoke-product",
    detection_vendor: str = "smoke-vendor",
) -> Dict[str, Any]:
    """S1 SecurityAlert that references one OR many indicators.

    `indicators` is a list of indicator dicts (as returned by any
    build_*_indicator helper above). The returned alert embeds one
    `finding_info.related_events[]` entry per indicator, linked by
    metadata.uid. Observables are carried through on each related_events
    entry so the UAM Indicators tab surfaces the right data.

    `detection_product` / `detection_vendor` populate `metadata.product`
    on the posted alert. These drive how UAM classifies the synthetic
    asset created for the alert (visible in `assets[].category` /
    `subcategory` on the GraphQL side). Empirical findings:
      * "smoke-product" / "smoke-vendor" (default)  -> category "Device", subcategory "Other Device"
      * "SentinelOne" / "SentinelOne"               -> category "Server", subcategory "Virtual Machine"
    Neither path populates `assets[].agentUuid` (that linkage is only
    established when the alert originates from an installed S1 agent on
    the tenant). See references/ASSET_LINKAGE.md for the full matrix.
    """
    if not indicators:
        raise ValueError("alert must reference at least one indicator")

    # Per SentinelOne UAM "Alert and Indicator Ingestion" docs: carry the
    # class/type/category/activity fields and enriched observables forward
    # onto each related_events entry so the UI can render the Indicators
    # tab without a secondary lookup against SDL. Observables get extra
    # `type` + `typeName` fields for rendering.
    related_events = []
    for ind in indicators:
        enriched_obs = [_enrich_observable_for_alert(o)
                        for o in ind.get("observables", [])]
        related_events.append({
            "message": ind.get("message", ""),
            "time": ind["time"],
            "uid": ind["metadata"]["uid"],
            "severity_id": ind.get("severity_id", severity_id),
            "observables": enriched_obs,
            "class_uid": ind.get("class_uid"),
            "type_uid": ind.get("type_uid"),
            "category_uid": ind.get("category_uid"),
            "activity_id": ind.get("activity_id"),
        })

    # resources[] on an S1 Security Alert is the affected ASSET. Per the
    # UAM "Alert and Indicator Ingestion" worked example, a single alert
    # targets a single asset even when referencing multiple indicators.
    # We take the first indicator's device as the authoritative resource;
    # callers who truly need per-indicator assets should emit separate
    # alerts. (The stitcher silently drops alerts whose related_events
    # span multiple devices but declare multiple resources, so keeping
    # this to one resource is the robust pattern.)
    first_dev = indicators[0].get("device", {}) or {}
    resources = [{
        "uid": first_dev.get("uid", "unknown"),
        "name": first_dev.get("hostname", "unknown"),
        "type_id": 1,
        "type": "host",
    }]

    return {
        "finding_info": {
            "uid": alert_uid,
            "title": title,
            "desc": description,
            "related_events": related_events,
        },
        "resources": resources,
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 99602001,
        "class_name": "S1 Security Alert",
        "type_uid": 9960200101,
        "type_name": "S1 Security Alert: Create",
        "activity_id": 1,
        "metadata": {
            "version": "1.6.0-dev",
            "extension": {"name": "s1", "uid": "998", "version": "0.1.0"},
            "product": {"name": detection_product, "vendor_name": detection_vendor},
            "logged_time": now_ms,
            "modified_time": now_ms,
        },
        "time": now_ms,
        "attack_surface_ids": [1],
        "severity_id": severity_id,
        "state_id": 1,
        "s1_classification_id": 1,
    }
