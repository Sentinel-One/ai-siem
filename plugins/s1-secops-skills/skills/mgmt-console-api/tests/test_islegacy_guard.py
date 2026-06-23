"""
Unit test for the isLegacy=false safety net in s1_client.py.

Why this exists
---------------
GET /web/api/v2.1/cloud-detection/rules silently omits queryType="scheduled"
PowerQuery rules from the response unless isLegacy=false is passed on the
query string. There is no error, no warning — the response just lies by
omission. This has bitten us multiple times: "list my scheduled detections"
returns an empty list even though scheduled rules exist and are visible in
the console UI.

To prevent the same mistake recurring, s1_client.S1Client.request() auto-
injects isLegacy=false on every GET to /cloud-detection/rules (including
the single-rule /{id} variant and trailing-slash forms). This test pins
that behavior so regressions surface immediately.

The corresponding JS guard lives in
  s1-secops-mcp/tools/mgmt-console.js  (normalizeS1ApiGetParams)
Keep the two in sync.

Run
---
    python3 tests/test_islegacy_guard.py

No network, no credentials required.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make scripts/ importable when running this file directly.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))

from s1_client import _maybe_inject_islegacy  # noqa: E402


def _assert(condition: bool, label: str) -> None:
    if not condition:
        print(f"FAIL: {label}")
        sys.exit(1)
    print(f"  ok   {label}")


def main() -> None:
    # GET on the listing endpoint injects.
    out = _maybe_inject_islegacy("GET", "/web/api/v2.1/cloud-detection/rules", None)
    _assert(out == {"isLegacy": "false"}, "GET /cloud-detection/rules → isLegacy injected")

    # Trailing slash variant injects.
    out = _maybe_inject_islegacy("GET", "/web/api/v2.1/cloud-detection/rules/", None)
    _assert(out == {"isLegacy": "false"}, "GET /cloud-detection/rules/ → isLegacy injected")

    # Single-rule lookup (/{id}) also injects — getting one rule by ID should
    # see the same scheduled/legacy fork.
    rule_id = "2487612380083288142"
    out = _maybe_inject_islegacy("GET", f"/web/api/v2.1/cloud-detection/rules/{rule_id}", None)
    _assert(out == {"isLegacy": "false"}, "GET /cloud-detection/rules/<id> → isLegacy injected")

    # Callers that inline query params in the path string (instead of passing
    # them via the params dict) must still trigger injection. An end-anchored
    # regex used to skip these, silently dropping scheduled rules.
    out = _maybe_inject_islegacy("GET", "/web/api/v2.1/cloud-detection/rules?limit=200", None)
    _assert(out == {"isLegacy": "false"}, "GET /cloud-detection/rules?limit=200 → isLegacy injected")

    out = _maybe_inject_islegacy("GET", f"/web/api/v2.1/cloud-detection/rules/{rule_id}?expanded=true", None)
    _assert(out == {"isLegacy": "false"}, "GET /cloud-detection/rules/<id>?query → isLegacy injected")

    # Adjacent names that merely start with "rules" must NOT match — the guard
    # requires `/`, `?`, or end-of-string immediately after "rules".
    out = _maybe_inject_islegacy("GET", "/web/api/v2.1/cloud-detection/rules-export", None)
    _assert(out == {}, "GET /cloud-detection/rules-export → no injection")

    # Existing params are preserved, not clobbered.
    out = _maybe_inject_islegacy(
        "GET",
        "/web/api/v2.1/cloud-detection/rules",
        {"limit": 200, "siteIds": "abc"},
    )
    _assert(
        out == {"limit": 200, "siteIds": "abc", "isLegacy": "false"},
        "existing params preserved alongside injection",
    )

    # Explicit override is honored — caller may pass isLegacy=true if they
    # actually want the legacy-only view for some reason.
    out = _maybe_inject_islegacy(
        "GET",
        "/web/api/v2.1/cloud-detection/rules",
        {"isLegacy": "true"},
    )
    _assert(out == {"isLegacy": "true"}, "explicit isLegacy=true override honored")

    # snake_case alias is also honored as an override (defensive).
    out = _maybe_inject_islegacy(
        "GET",
        "/web/api/v2.1/cloud-detection/rules",
        {"is_legacy": "true"},
    )
    _assert(
        out == {"is_legacy": "true"},
        "is_legacy snake_case override honored (no double-injection)",
    )

    # POST to the same path does NOT inject — guard is GET-only.
    out = _maybe_inject_islegacy("POST", "/web/api/v2.1/cloud-detection/rules", None)
    _assert(out == {}, "POST /cloud-detection/rules → no injection")

    # Unrelated GET path does NOT inject.
    out = _maybe_inject_islegacy("GET", "/web/api/v2.1/agents", None)
    _assert(out == {}, "GET /agents → no injection")

    # Adjacent endpoint /cloud-detection/alerts does NOT inject — only the
    # /rules surface has the legacy/scheduled fork.
    out = _maybe_inject_islegacy("GET", "/web/api/v2.1/cloud-detection/alerts", None)
    _assert(out == {}, "GET /cloud-detection/alerts → no injection")

    # Original caller dict is not mutated.
    caller = {"limit": 50}
    _ = _maybe_inject_islegacy("GET", "/web/api/v2.1/cloud-detection/rules", caller)
    _assert(caller == {"limit": 50}, "caller's params dict not mutated")

    # Method casing is normalized.
    out = _maybe_inject_islegacy("get", "/web/api/v2.1/cloud-detection/rules", None)
    _assert(out == {"isLegacy": "false"}, "lowercase 'get' method handled")

    print("\nOK: all isLegacy guard cases passed")


if __name__ == "__main__":
    main()
