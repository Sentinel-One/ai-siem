#!/usr/bin/env python3
"""Search the Hyperautomation action library and marketplace templates shipped with this skill.

Runs locally (standard library only, no network). The library is too large to read whole, so
search it with this script and copy the `public_action_id` and `integration_id` of the action
you need into the workflow JSON.

Usage:
  python3 scripts/find_action.py slack post message          # every term must match
  python3 scripts/find_action.py --integration jira create issue
  python3 scripts/find_action.py --id <uuid>                 # exact public_action_id, or an
                                                              # older id an entry derives from
  python3 scripts/find_action.py --list-integrations [terms]
  python3 scripts/find_action.py --templates phishing        # marketplace templates
  add --json for machine-readable output, --limit N (default 20, 0 = no limit)

Exit status: 0 when something matched, 1 when nothing did, 2 on a usage or data error.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
ACTIONS = os.path.join(SKILL, "assets", "action-library.json")
TEMPLATES = os.path.join(SKILL, "assets", "marketplace-templates.json")


def _load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)


def _matches(haystack, terms):
    h = haystack.lower()
    return all(t in h for t in terms)


def search_actions(lib, terms, integration=None, action_id=None):
    out = []
    for g in lib["integrations"]:
        gtext = " ".join(str(x) for x in (g["label"], g.get("product_key") or "", g["integration_id"]))
        if integration and integration.lower() not in gtext.lower():
            continue
        for a in g["actions"]:
            if action_id:
                if action_id != a["public_action_id"] and action_id not in a.get("derived_from", []):
                    continue
            else:
                text = " ".join(str(x) for x in (gtext, a["name"], a.get("method") or "",
                                                  a.get("url_path") or "", a.get("description") or ""))
                if not _matches(text, terms):
                    continue
            name = a["name"].lower()
            score = sum(3 for t in terms if t in name) + sum(1 for t in terms if t in (a.get("url_path") or "").lower())
            out.append({"integration": g["label"], "integration_id": g["integration_id"],
                        "product_key": g.get("product_key"), "_score": score, **a})
    out.sort(key=lambda r: (-r["_score"], len(r["name"]), r["integration"].lower(), r["name"].lower()))
    for r in out:
        del r["_score"]
    return out


def search_templates(lib, terms):
    out = []
    for t in lib["templates"]:
        text = " ".join([t["name"], t["description"], " ".join(t["steps"]), " ".join(t["integrations"])])
        if _matches(text, terms):
            out.append(t)
    return out


def main():
    ap = argparse.ArgumentParser(description="Search the Hyperautomation action library.")
    ap.add_argument("terms", nargs="*", help="words that must all appear (case-insensitive)")
    ap.add_argument("--integration", help="limit to integrations whose name, product_key or id contains this")
    ap.add_argument("--id", dest="action_id", help="look up one action by public_action_id or by an id it derives from")
    ap.add_argument("--list-integrations", action="store_true")
    ap.add_argument("--templates", action="store_true", help="search marketplace templates instead of actions")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()
    terms = [t.lower() for t in args.terms]

    if args.templates:
        rows = search_templates(_load(TEMPLATES), terms)
    elif args.list_integrations:
        lib = _load(ACTIONS)
        rows = [{"integration": g["label"], "product_key": g.get("product_key"), "integration_id": g["integration_id"],
                 "actions": len(g["actions"])} for g in lib["integrations"]
                if _matches(" ".join([g["label"], g.get("product_key") or "", g["integration_id"]]), terms)]
    else:
        if not terms and not args.action_id and not args.integration:
            ap.error("give search terms, --id, --integration, --list-integrations or --templates")
        rows = search_actions(_load(ACTIONS), terms, args.integration, args.action_id)

    total = len(rows)
    if args.limit > 0:
        rows = rows[:args.limit]
    if args.json:
        print(json.dumps({"total": total, "shown": len(rows), "results": rows}, indent=1))
    elif args.templates:
        for t in rows:
            print(f"{t['name']}  [{', '.join(t['integrations']) or 'core actions only'}]")
            print(f"    {t['description'][:300]}")
            for s in t["steps"][:6]:
                print(f"    - {s}")
    elif args.list_integrations:
        for r in rows:
            print(f"{r['integration']:<45} {str(r['product_key']):<28} {r['actions']:>4}  {r['integration_id']}")
    else:
        for r in rows:
            print(f"{r['integration']} | {r['name']}")
            print(f"    {r.get('method') or '-'} {r.get('url_path') or '-'}")
            print(f"    public_action_id {r['public_action_id']}   integration_id {r['integration_id']}")
            if r.get("url"):
                print(f"    url {r['url']}")
            if r.get("payload"):
                print(f"    payload {' '.join(r['payload'].split())[:240]}")
            if r.get("status"):
                print(f"    status {r['status']}")
            if r.get("description"):
                print(f"    {r['description'][:240]}")
    if total > len(rows):
        print(f"... {total - len(rows)} more; narrow the terms or raise --limit", file=sys.stderr)
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())
