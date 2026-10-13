"""
UAM (Unified Alert Management) Alert Interface helper.

Write-side API that pushes OCSF-formatted alerts INTO UAM so they
surface in the console as real alerts with attached indicators. Separate
host + wire contract from the Mgmt Console REST and the UAM GraphQL
query layer (both of which are READ/mutate on pre-existing state).

Host (region-specific, e.g. US1 shown; see https://community.sentinelone.com/s/article/000004961 for your region):
    https://ingest.us1.sentinelone.net


Wire contract
-------------
  * Content-Encoding: gzip (mandatory; zstd also accepted by the server)
  * Authorization:    Bearer <JWT>          -- NOT "ApiToken ..."
  * S1-Scope:         <accountId>[:<siteId>[:<groupId>]]  (mandatory on
                      /v1/alerts)
  * Body:             concatenated JSON (one or more objects back-to-back,
                      optionally newline-separated), then gzip-compressed.
  * Response:         202 Accepted with {"details":"Success","status":202}
                      on success; 4xx JSON {"details":"...", "status":<n>}
                      on rejection.

Auth token
----------
/v1/alerts takes the same service-user JWT used for the Mgmt Console API
(S1Client.api_token, resolved from the environment or the OS keychain
under the name `S1_CONSOLE_API_TOKEN`). `ApiToken <token>` is rejected with HTTP 401
`{"details":"Unsupported auth type: ApiToken"}`, so callers MUST switch
to the `Bearer` scheme when talking to this endpoint family.

This is NOT the credential used by the raw log event collector
(`/services/collector/raw` and `/services/collector/event`), which
requires an SDL Log Write Key (`S1_HEC_TOKEN`) and sends no `S1-Scope`
header. The two surfaces share a host and nothing else; do not swap the
credentials between them.

Indicators ride inline in the alert
-----------------------------------
Indicators are NOT posted separately. `POST /v1/indicators` refuses both
the console API token and the SDL Log Write Key, so no credential can
reach it. Every indicator travels inside the alert body at
`finding_info.related_events[]` in a single `POST /v1/alerts`, carrying
its full OCSF context (device, actor, file / process / endpoints,
metadata, observables). That inline copy is what populates
`alert.indicators`, which the console Indicators tab renders.

An alert MAY carry many indicators: one `related_events[]` entry per
indicator, each keyed by its own `metadata.uid`.
`build_alert_referencing` builds these entries for you.

Because ingest is a single POST, there is no ordering to get right and
no window in which one half of the pair is visible without the other.

Batching
--------
POST /v1/alerts accepts concatenated JSON for N alerts and the gateway
returns HTTP 202, but the ingest pipeline has been observed to silently
drop all but one of the alerts (usea1-acme 2026-04-22). Call /v1/alerts
with ONE alert per invocation; loop if you have many. `post_alerts`
emits a RuntimeWarning when called with more than one alert.

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

    alert = build_alert_referencing(
        alert_uid=alert_uid, indicators=[ind1, ind2, ind3],
        now_ms=now_ms, title="...", description="...")

    # ONE POST carries the alert and all three indicators inline.
    uam.post_alerts([alert], scope=f"{acct}:{site}")
"""
from __future__ import annotations

import gzip
import json
import os
import sys
import urllib.error
import urllib.request
import warnings
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


_DEFAULT_PROD_HOST = "https://ingest.us1.sentinelone.net"

# Optional ingest host override, read from the environment and then the OS
# keychain (never from a file). If not present the helper falls back to
# _DEFAULT_PROD_HOST. Canonical name is S1_HEC_INGEST_URL: the host serves
# both log ingest and OCSF alert/indicator ingest, so the name reflects that.
# The former canonical environment variable is still read.
_CONFIG_KEY = "S1_HEC_INGEST_URL"
_LEGACY_CONFIG_KEYS = (
    "S1_UAM_ALERT_INTERFACE_URL",  # former canonical
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


def _configured_url() -> Optional[str]:
    """The HEC ingest URL from the environment, then the OS keychain.

    Environment: S1_HEC_INGEST_URL, then S1_UAM_ALERT_INTERFACE_URL.
    Keychain: item "<profile>:S1_HEC_INGEST_URL" (see s1_keystore.py).
    No file is read. Returns None when neither has a value; a keychain
    error is never raised from here.
    """
    for key in (_CONFIG_KEY, *_LEGACY_CONFIG_KEYS):
        v = os.environ.get(key)
        if v and v.strip():
            return v.strip().rstrip("/")
    try:
        try:
            import s1_keystore as ks  # type: ignore
        except ImportError:
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "s1_keystore", Path(__file__).resolve().parent / "s1_keystore.py")
            ks = importlib.util.module_from_spec(spec)
            sys.modules["s1_keystore"] = ks
            spec.loader.exec_module(ks)  # type: ignore[union-attr]
        v = ks.get(_CONFIG_KEY)
    except Exception:  # keychain problems fall through to the default host
        v = None
    return v.strip().rstrip("/") if v and v.strip() else None


class UAMAlertInterfaceError(RuntimeError):
    def __init__(self, status: int, body: str, *, method: str, url: str):
        self.status = status
        self.body = body
        self.method = method
        self.url = url
        super().__init__(f"HTTP {status} on {method} {url}: {body}")


# REMOVED: UAMAlertInterfaceClient.post_indicators().
# It POSTed to /v1/indicators, which refuses both the console API token
# and the SDL Log Write Key, so no credential can drive it. There is no
# separate indicator ingest. Put the indicator inline in the alert at
# finding_info.related_events[] (build_alert_referencing does this) and
# send it with post_alerts().

# REMOVED: UAMAlertInterfaceClient.post_alert_with_indicators().
# It sequenced post_indicators() -> sleep -> post_alerts() to dodge a
# race between two POSTs. With indicators inline there is only one POST,
# so the sequencing, the sleep, and the helper all have nothing left to
# do. Call post_alerts([alert], scope=...) directly.


class UAMAlertInterfaceClient:
    """Thin wrapper over POST /v1/alerts against the UAM Alert Interface
    (Unified Alert Management ingestion surface).

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
        # legacy S1_UAM_ALERT_INTERFACE_URL env > OS keychain > default.
        resolved = base_url or _configured_url()
        if not resolved:
            resolved = _DEFAULT_PROD_HOST
            print(
                "WARNING: no S1_HEC_INGEST_URL configured (environment or OS "
                "keychain); falling back to the default US1 ingest "
                f"host {_DEFAULT_PROD_HOST}. If your tenant is not in US1, "
                "store S1_HEC_INGEST_URL with `s1-secops-mcp setup` or export it "
                "(see https://community.sentinelone.com/s/article/000004961).",
                file=sys.stderr,
            )
        self.base_url = resolved.rstrip("/")
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
    def post_alerts(self, alerts: List[Dict[str, Any]], *, scope: str,
                    trace_id: Optional[str] = None) -> Dict[str, Any]:
        """POST /v1/alerts. Call with ONE alert per invocation.

        This is the only ingest call. Each alert carries its indicators
        inline at `finding_info.related_events[]`, one entry per
        indicator, each holding that indicator's full OCSF context
        (`metadata.uid`, device, actor, file / process / endpoints,
        observables). Build the alert with `build_alert_referencing` and
        the inline entries are produced for you. The inline copy is what
        populates `alert.indicators` for the console Indicators tab.

        Multi-alert bodies: the wire format accepts concatenated JSON for
        N alerts in one POST, and the gateway returns HTTP 202, but the
        ingest pipeline has been observed to silently drop all but one of
        the alerts (usea1-acme 2026-04-22). Loop callers over this method
        one alert at a time. A RuntimeWarning is emitted when `alerts`
        has more than one entry so callers notice the hazard.
        """
        if len(alerts) > 1:
            warnings.warn(
                "UAM Alert Interface: posting multiple alerts in a single "
                "POST /v1/alerts call silently drops all but one alert "
                "(HTTP 202 still returned). Loop callers one alert at a "
                "time.",
                RuntimeWarning,
                stacklevel=2,
            )
        return self._post("/v1/alerts", alerts, scope=scope, trace_id=trace_id)


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
    """S1 SecurityAlert carrying one OR many indicators inline.

    `indicators` is a list of indicator dicts (as returned by any
    build_*_indicator helper above). The returned alert embeds one
    `finding_info.related_events[]` entry per indicator, and each entry
    holds that indicator's FULL context, not just a uid reference:
    `metadata` (including the `metadata.uid` key), `device`, `actor`,
    the class-specific object (`file` / `process` / `src_endpoint` +
    `dst_endpoint` + `url`), the OCSF class/type/category/activity ids,
    and the enriched `observables[]`. This inline copy is the only way
    indicator data reaches the tenant, since /v1/indicators is not
    reachable with any credential, and it is what populates
    `alert.indicators` for the console Indicators tab.

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
        raise ValueError("alert must carry at least one inline indicator")

    # Copy each indicator WHOLE onto its related_events entry. There is
    # no second POST that could supply the rest of the record later, so a
    # reference-only entry (uid + a few scalars) would land an indicator
    # with no context attached. Carrying the full body forward keeps
    # device / actor / file / process / endpoint context, and the OCSF
    # class/type/category/activity ids, on the alert itself, which is
    # what the Indicators tab renders from. Observables additionally get
    # `type` + `typeName` for rendering.
    related_events = []
    for ind in indicators:
        entry = dict(ind)
        entry["uid"] = ind["metadata"]["uid"]
        entry["message"] = ind.get("message", "")
        entry["time"] = ind["time"]
        entry["severity_id"] = ind.get("severity_id", severity_id)
        entry["observables"] = [_enrich_observable_for_alert(o)
                                for o in ind.get("observables", [])]
        related_events.append(entry)

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
