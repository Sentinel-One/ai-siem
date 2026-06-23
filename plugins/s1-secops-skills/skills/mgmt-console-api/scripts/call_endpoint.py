"""
One-shot CLI for hitting any SentinelOne API endpoint.

Examples:
    python scripts/call_endpoint.py GET /web/api/v2.1/accounts --param limit=5
    python scripts/call_endpoint.py GET /web/api/v2.1/threats --param limit=100 --paginate
    python scripts/call_endpoint.py POST /web/api/v2.1/agents/actions/disconnect --body '{"filter":{"ids":["123"]}}'

Reads credentials from $CLAUDE_CONFIG_DIR/sentinelone/credentials.json or env vars via s1_client.
"""

from __future__ import annotations

import argparse
import json
import sys

from s1_client import S1Client, S1APIError


def parse_param(kv: str):
    if "=" not in kv:
        raise argparse.ArgumentTypeError(f"expected key=value, got {kv!r}")
    k, v = kv.split("=", 1)
    return k, v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("method", choices=["GET", "POST", "PUT", "DELETE"])
    ap.add_argument("path", help="API path, e.g. /web/api/v2.1/agents")
    ap.add_argument("--param", action="append", default=[], type=parse_param, help="query param key=value (repeatable)")
    ap.add_argument("--body", help="JSON string for request body")
    ap.add_argument("--body-file", help="path to JSON file for request body")
    ap.add_argument("--paginate", action="store_true", help="iterate via cursor until done (GET only)")
    ap.add_argument("--max-items", type=int, help="limit items when --paginate is used")
    ap.add_argument("--max-pages", type=int, help="limit pages when --paginate is used")
    args = ap.parse_args()

    params = dict(args.param) if args.param else None

    body = None
    if args.body:
        body = json.loads(args.body)
    elif args.body_file:
        with open(args.body_file) as f:
            body = json.load(f)

    client = S1Client()

    try:
        if args.paginate and args.method == "GET":
            items = []
            for page in client.paginate(args.path, params=params, max_pages=args.max_pages):
                items.extend(page.get("data", []) or [])
                if args.max_items and len(items) >= args.max_items:
                    items = items[: args.max_items]
                    break
            print(json.dumps({"count": len(items), "data": items}, indent=2, default=str))
        else:
            resp = client.request(args.method, args.path, params=params, json_body=body)
            print(json.dumps(resp, indent=2, default=str))
    except S1APIError as e:
        print(f"ERROR {e.status}: {e}", file=sys.stderr)
        if e.body:
            print(json.dumps(e.body, indent=2, default=str)[:4000], file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
