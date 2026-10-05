#!/usr/bin/env python3
"""Render the "custom detection with MITRE mapping" Hyperautomation watchdog.

Solution for custom detections to carry MITRE mapping. A Custom Detection (STAR) rule
cannot carry MITRE ATT&CK: POST /cloud-detection/rules rejects `mitre` and
`mitreTechniques` with HTTP 400 "Unknown field", and STAR alerts reach UAM with
`mitreTactics` / `mitreTechniques` empty. The supported path is to run the same
detection query from a Hyperautomation watchdog and post the alert to UAM
`/v1/alerts` with `attacks[]` on each `finding_info.related_events[]` entry.
`finding_info.attacks` is ignored by UAM; only the per-indicator copy is read.

Input is a rule spec (JSON). Either write one by hand (see
assets/mitre_rule_specs/*.json) or derive it from an existing scheduled STAR rule
with --from-rule (the `data[0]` object of GET /cloud-detection/rules?ids=<id>).

    python3 render_mitre_watchdog.py --spec ../assets/mitre_rule_specs/encoded_powershell.json \
        --prefix ACME --account-id 123 --site-id 456 \
        --hec-url https://ingest.us1.sentinelone.net \
        --sdl-integration-id ea6018b7-2a2f-44ca-b9b6-27a0434b0503 \
        --out rendered.workflow.json

Zero dependencies. Exit code 2 on a spec error.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE.parent / "assets" / "mitre_watchdog.workflow.template.json"

# Tactic names as UAM renders them for library rules on S-26.3.x. TA0005 is
# "Stealth" (ATT&CK v18), not "Defense Evasion". Match on the id, never the name.
TACTICS = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Stealth", "TA0006": "Credential Access", "TA0007": "Discovery",
    "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0011": "Command and Control",
    "TA0010": "Exfiltration", "TA0040": "Impact",
}
SEVERITY = {"info": 1, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
ATTACK_VERSION = "18"


def fail(msg):
    print(f"spec error: {msg}", file=sys.stderr)
    sys.exit(2)


def attacks_from_spec(mitre):
    """mitre: list of {tactic: "TA0002", technique: "T1059.001", technique_name?: "PowerShell"}."""
    if not isinstance(mitre, list) or not mitre:
        fail("`mitre` must be a non-empty list")
    out = []
    for m in mitre:
        tac = str(m.get("tactic", "")).upper()
        tech = str(m.get("technique", "")).upper()
        if tac not in TACTICS:
            fail(f"unknown tactic id {tac!r}; use a TA00xx id")
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", tech):
            fail(f"bad technique id {tech!r}; use T1234 or T1234.001")
        out.append({"tactic": {"uid": tac, "name": m.get("tactic_name") or TACTICS[tac]},
                    "technique": {"uid": tech, "name": m.get("technique_name") or tech},
                    "version": ATTACK_VERSION})
    return out


def spec_from_rule(rule, mitre):
    """Build a spec from an existing scheduled STAR rule (GET response data object)."""
    sp = rule.get("scheduledParams") or {}
    if rule.get("queryType") != "scheduled" or not sp.get("query"):
        fail("--from-rule needs a scheduled (PowerQuery) rule with scheduledParams.query")
    return {
        "name": rule["name"], "description": rule.get("description") or rule["name"],
        "severity": rule.get("severity", "Medium"), "query": sp["query"],
        "lookback_minutes": int(sp.get("lookbackWindowMinutes", 60)),
        "interval_minutes": int(sp.get("runIntervalMinutes", 60)), "mitre": mitre,
    }


def esc_in_json_string(text):
    """Escape for a value that sits inside a JSON string in the template file."""
    return json.dumps(text)[1:-1]


def render(spec, prefix, account_id, site_id, hec_url, sdl_integration_id):
    for k in ("name", "description", "query", "mitre"):
        if not spec.get(k):
            fail(f"missing `{k}`")
    sev = spec.get("severity", "Medium")
    sev_id = SEVERITY.get(str(sev).lower()) if not isinstance(sev, int) else sev
    if sev_id not in (1, 2, 3, 4, 5):
        fail(f"bad severity {sev!r}")
    lookback_h = max(1, -(-int(spec.get("lookback_minutes", 60)) // 60))  # ceil to hours
    interval = int(spec.get("interval_minutes", 60))
    attacks = attacks_from_spec(spec["mitre"])
    query = spec["query"].strip()

    t = TEMPLATE.read_text()
    # PQ sits in the LRQ payload (a JSON document) which is itself a JSON string in
    # the workflow file: escape twice.
    t = t.replace("{{PQ_QUERY}}", esc_in_json_string(json.dumps(query)[1:-1]))
    # attacks[] sits as raw JSON inside the alert variable, which is a JSON string.
    t = t.replace("{{MITRE_ATTACKS_JSON}}", esc_in_json_string(json.dumps(attacks, separators=(",", ":"))))
    for tok, val in {
        "{{RULE_NAME}}": spec["name"], "{{RULE_DESCRIPTION}}": spec["description"],
        "{{PRODUCT_NAME}}": spec.get("product_name") or f"{prefix} Custom Detection (MITRE)",
    }.items():
        # These sit both inside the alert JSON string (two escaping levels) and in plain
        # fields such as the workflow name (one level). Rejecting the characters that need
        # escaping keeps one substitution correct in both places.
        if re.search(r'["\\\n\r\t]', val):
            fail(f"{tok} must not contain quotes, backslashes or newlines: {val!r}")
        t = t.replace(tok, val)
    t = (t.replace("{{PREFIX}}", prefix).replace("{{ACCOUNT_ID}}", str(account_id))
          .replace("{{SITE_ID}}", str(site_id)).replace("{{HEC_URL}}", hec_url.rstrip("/"))
          .replace("{{SDL_INTEGRATION_ID}}", sdl_integration_id)
          .replace("{{SEVERITY_ID}}", str(sev_id)).replace("{{LOOKBACK_HOURS}}", str(lookback_h))
          .replace("{{INTERVAL_MINUTES}}", str(interval)))
    left = re.findall(r"\{\{[A-Z_]+\}\}", t)
    if left:
        fail(f"unrendered tokens: {sorted(set(left))}")
    wf = json.loads(t)  # must stay valid JSON
    # The alert body must also parse once the HA expressions are stubbed.
    alert = next(v["value"] for a in wf["actions"]
                 for v in a["action"]["data"].get("variables", []) if v["name"] == "MitreAlert")
    stub = re.sub(r"\{\{Function\.DATETIME_TO_MS\(Function\.DATETIME_NOW\(\)\)\}\}", "0", alert)
    parsed = json.loads(stub)
    assert parsed["finding_info"]["related_events"][0]["attacks"] == attacks
    return wf


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--spec", help="rule spec JSON")
    src.add_argument("--from-rule", help="scheduled STAR rule JSON (GET data object); needs --mitre")
    ap.add_argument("--mitre", help='with --from-rule: JSON list, e.g. [{"tactic":"TA0002","technique":"T1059.001"}]')
    ap.add_argument("--prefix", required=True)
    ap.add_argument("--account-id", required=True)
    ap.add_argument("--site-id", required=True)
    ap.add_argument("--hec-url", required=True, help="ingest host, e.g. https://ingest.us1.sentinelone.net")
    ap.add_argument("--sdl-integration-id", required=True,
                    help="the built-in SentinelOne SDL integration id the flow binds to")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.spec:
        spec = json.loads(Path(a.spec).read_text())
    else:
        if not a.mitre:
            fail("--from-rule needs --mitre")
        spec = spec_from_rule(json.loads(Path(a.from_rule).read_text()), json.loads(a.mitre))
    wf = render(spec, a.prefix, a.account_id, a.site_id, a.hec_url, a.sdl_integration_id)
    Path(a.out).write_text(json.dumps(wf, indent=2) + "\n")
    print(f"rendered {len(wf['actions'])} actions -> {a.out}")


if __name__ == "__main__":
    main()
