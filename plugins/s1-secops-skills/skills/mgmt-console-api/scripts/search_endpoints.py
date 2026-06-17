"""
Search the endpoint index for matching operations.

Ranks results by a simple relevance score: exact path segment hits and
verb detection weighted higher than substring matches on the summary.

Usage:
    python scripts/search_endpoints.py "threats"
    python scripts/search_endpoints.py --tag "Agents" --method GET
    python scripts/search_endpoints.py --path "/web/api/v2.1/threats"
    python scripts/search_endpoints.py "isolate endpoint"
    python scripts/search_endpoints.py "count threats"
    python scripts/search_endpoints.py --only-works       # only on this tenant
    python scripts/search_endpoints.py --json "isolate"   # structured output

Prints a compact table so Claude can pick the right endpoint without
loading the full spec.

Options:
  --only-works   Restrict output to endpoints that returned 200 in the
                 most recent smoke test (references/tenant_capabilities.json).
  --json         Emit JSON instead of the human-readable table.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

SKILL_DIR = Path(__file__).resolve().parent.parent
INDEX = SKILL_DIR / "references" / "endpoint_index.json"
CAPS = SKILL_DIR / "references" / "tenant_capabilities.json"

# Verb synonyms -> canonical method expectation. Used to boost results
# when the user's phrasing matches HTTP method intent.
VERB_MAP = {
    "list": "GET", "get": "GET", "show": "GET", "fetch": "GET",
    "read": "GET", "view": "GET", "find": "GET", "search": "GET",
    "count": "GET",
    "create": "POST", "make": "POST", "add": "POST", "new": "POST",
    "post": "POST", "run": "POST", "start": "POST", "execute": "POST",
    "update": "PUT", "edit": "PUT", "modify": "PUT", "change": "PUT",
    "put": "PUT", "set": "PUT",
    "delete": "DELETE", "remove": "DELETE", "destroy": "DELETE",
    # S1-specific action verbs (all POSTs under /actions/)
    "isolate": "POST", "disconnect": "POST", "reconnect": "POST",
    "shutdown": "POST", "uninstall": "POST", "decommission": "POST",
    "fetch-logs": "POST", "initiate": "POST", "trigger": "POST",
    "scan": "POST", "move": "POST",
}


# S1-specific synonym expansion: users say "isolate" but S1 calls it
# "disconnect"; "endpoint" and "agent" are used interchangeably; etc.
# These are additive — both original and synonym become search tokens.
SYNONYMS = {
    "isolate":    ["disconnect", "quarantine"],
    "deisolate":  ["reconnect"],
    "unisolate":  ["reconnect"],
    "endpoint":   ["agent"],
    "endpoints":  ["agents"],
    "machine":    ["agent"],
    "host":       ["agent"],
    "device":     ["agent"],
    "hunt":       ["dv", "powerquery", "deep-visibility"],
    "query":      ["dv", "powerquery"],
    "policy":     ["policies"],
    "mitigate":   ["mitigation"],
    "pq":         ["powerquery"],
}


def _tokenize(s: str) -> List[str]:
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    toks = [t for t in s.split() if t]
    out: List[str] = list(toks)
    for t in toks:
        for syn in SYNONYMS.get(t, []):
            if syn not in out:
                out.append(syn)
    return out


def _score(entry: Dict[str, Any], tokens: List[str]) -> float:
    if not tokens:
        return 0.0
    hay_path = entry["path"].lower()
    hay_sum = (entry.get("summary") or "").lower()
    hay_op = (entry.get("operationId") or "").lower()
    hay_tag = entry["tag"].lower()
    score = 0.0

    for t in tokens:
        # path segment match (exact) — most valuable
        path_segs = re.split(r"[/{}]", hay_path)
        if t in path_segs:
            score += 10.0
        elif t in hay_path:
            score += 4.0
        if t in hay_sum.split():
            score += 3.0
        elif t in hay_sum:
            score += 1.5
        if t in hay_op:
            score += 2.5
        if t in hay_tag:
            score += 4.0
        # verb/method intent — boost endpoints matching the implied method
        expected = VERB_MAP.get(t)
        if expected and entry["method"] == expected:
            score += 5.0
    # tie-breaker: shorter paths win (less deeply nested = usually the
    # primary endpoint for a resource)
    score -= len(entry["path"]) / 1000.0
    return score


def _load_works_only() -> Optional[Set[str]]:
    if not CAPS.exists():
        return None
    try:
        data = json.loads(CAPS.read_text())
    except Exception:
        return None
    ok: Set[str] = set()
    for row in data.get("rows", []):
        if row.get("ok"):
            ok.add(f"{row['method']} {row['path_template']}")
    return ok or None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="?", default="",
                    help="free-text match against summary/path/operationId; tokenized")
    ap.add_argument("--tag", help="exact tag filter (e.g. Threats)")
    ap.add_argument("--method", help="GET/POST/PUT/DELETE")
    ap.add_argument("--path", help="substring match on path")
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--only-works", action="store_true",
                    help="only show endpoints that returned 200 in the last smoke test")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of a table")
    args = ap.parse_args()

    data: List[Dict[str, Any]] = json.loads(INDEX.read_text())
    tokens = _tokenize(args.query)
    method = (args.method or "").upper()
    works = _load_works_only() if args.only_works else None

    def matches(e):
        if args.tag and e["tag"] != args.tag:
            return False
        if method and e["method"] != method:
            return False
        if args.path and args.path.lower() not in e["path"].lower():
            return False
        if works is not None and f"{e['method']} {e['path']}" not in works:
            return False
        if tokens:
            return _score(e, tokens) > 0
        return True

    hits = [e for e in data if matches(e)]
    if tokens:
        hits.sort(key=lambda e: -_score(e, tokens))
    else:
        hits.sort(key=lambda e: (e["tag"], e["path"]))

    if args.json:
        print(json.dumps(hits[: args.limit], indent=2))
        return

    total = len(hits)
    shown = hits[: args.limit]
    print(f"{total} match(es)" + (f" — showing top {len(shown)}" if total > len(shown) else ""))
    if works is not None:
        print("(filtered to endpoints confirmed working on this tenant)")
    for e in shown:
        sc = f"{_score(e, tokens):5.1f}" if tokens else "     "
        print(f"  {sc}  {e['method']:6} {e['path']:60} [{e['tag']}] — {e['summary']}")


if __name__ == "__main__":
    main()
