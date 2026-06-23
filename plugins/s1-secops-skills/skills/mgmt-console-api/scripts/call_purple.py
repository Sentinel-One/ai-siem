#!/usr/bin/env python3
"""CLI wrapper for Purple AI natural-language queries.

Usage:
    python scripts/call_purple.py "Show powershell.exe outbound connections, top 10"
    python scripts/call_purple.py --selector CLOUD --hours 48 "Show S3 object downloads by user"
    python scripts/call_purple.py --raw "..."          # dump full GraphQL response
    python scripts/call_purple.py --json "..."         # machine-readable normalized dict
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make the sibling modules importable when called as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from s1_client import S1Client, S1APIError
from purple_ai import VIEW_SELECTORS, PurpleAIError, purple_query


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ask Purple AI a natural-language question via the S1 GraphQL endpoint.",
    )
    parser.add_argument("question", help="The natural-language question")
    parser.add_argument(
        "--selector",
        choices=VIEW_SELECTORS,
        default="EDR",
        help="Purple AI viewSelector (data domain hint). Default: EDR.",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Look-back window in hours from now. Default: 24.",
    )
    parser.add_argument(
        "--async-mode",
        action="store_true",
        help="Use Purple AI's async mode (returns a continuation token).",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print the full GraphQL response as JSON and exit.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the normalized result dict as JSON and exit.",
    )
    args = parser.parse_args()

    try:
        c = S1Client()
    except RuntimeError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    try:
        r = purple_query(
            c,
            args.question,
            view_selector=args.selector,
            hours=args.hours,
            is_async=args.async_mode,
        )
    except PurpleAIError as e:
        # Entitlement/permission/GraphQL — 200-response errors.
        print(f"Purple AI error: {e}", file=sys.stderr)
        if e.error_type:
            print(f"  errorType: {e.error_type}", file=sys.stderr)
        if e.error_type in ("ENTITLEMENT", "ENTITLEMENT_ERROR"):
            print(
                "  hint: the tenant isn't entitled to Purple AI, "
                "or the token's role lacks Purple AI permission.",
                file=sys.stderr,
            )
        return 1
    except S1APIError as e:
        print(f"HTTP error: {e}", file=sys.stderr)
        return 1

    if args.raw:
        print(json.dumps(r["raw"], indent=2))
        return 0
    if args.json:
        # Strip the raw response for a tighter dump.
        out = {k: v for k, v in r.items() if k != "raw"}
        print(json.dumps(out, indent=2))
        return 0

    # Human-readable default output.
    print(f"state:       {r['state']}")
    print(f"result_type: {r['result_type']}")
    print(f"selector:    {r['view_selector']}")
    print("-" * 60)
    if r["message"]:
        print("MESSAGE:")
        print(r["message"])
        print("-" * 60)
    if r["power_query"]:
        print("POWERQUERY:")
        print(r["power_query"])
        print("-" * 60)
    if r["suggested_questions"]:
        print("SUGGESTED FOLLOW-UPS:")
        for q in r["suggested_questions"]:
            print(f"  - {q}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
