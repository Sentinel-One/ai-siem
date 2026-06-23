"""
Command-line runner for the SDL API. Wraps sdl_client.SDLClient so that
every method is reachable from the shell without writing Python.

Examples
--------

    # List every configuration file
    python scripts/sdl_cli.py list-files

    # Read one
    python scripts/sdl_cli.py get-file /logParsers/MyParser

    # Power query
    python scripts/sdl_cli.py power-query "dataset='accesslog' | group count() by status" --start 1h

    # Raw query with filter
    python scripts/sdl_cli.py query "error" --start 15m --max 50

    # Facet (top N values of a field)
    python scripts/sdl_cli.py facet-query srcIp --filter "status >= 400" --start 1h

    # Timeseries
    python scripts/sdl_cli.py timeseries-query --filter "*" --function count --buckets 60 --start 1h

    # Numeric
    python scripts/sdl_cli.py numeric-query --function count --filter "status >= 500" --start 1h --buckets 30

    # Put file (create/update)
    # Parsers: use /logParsers/<name> — /parsers/ is API-accepted but invisible in the UI.
    python scripts/sdl_cli.py put-file /logParsers/MyParser --content-file ./parser.txt

    # Delete file
    python scripts/sdl_cli.py put-file /logParsers/Stale --delete

Every output is pretty-printed JSON on stdout. Errors exit non-zero with
the parsed error body.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make sibling import work when invoked directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sdl_client import SDLClient, SDLAPIError  # noqa: E402


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _parse_kv(pairs):
    out = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit(f"invalid --attr '{p}': expected key=value")
        k, v = p.split("=", 1)
        # try to coerce numbers/bools
        vs = v.strip()
        if vs.lower() in ("true", "false"):
            out[k] = vs.lower() == "true"
        else:
            try:
                out[k] = int(vs)
            except ValueError:
                try:
                    out[k] = float(vs)
                except ValueError:
                    out[k] = v
    return out


def cmd_list_files(c, args):
    _print(c.list_files())


def cmd_get_file(c, args):
    _print(c.get_file(args.path, expected_version=args.expected_version, prettyprint=args.prettyprint))


def cmd_put_file(c, args):
    content = None
    if not args.delete:
        if args.content is not None:
            content = args.content
        elif args.content_file:
            content = Path(args.content_file).read_text()
        else:
            raise SystemExit("put-file requires --content, --content-file, or --delete")
    _print(
        c.put_file(
            args.path,
            content=content,
            expected_version=args.expected_version,
            delete=args.delete,
        )
    )


def cmd_query(c, args):
    res = c.query(
        filter=args.filter or "",
        start_time=args.start,
        end_time=args.end,
        max_count=args.max,
        page_mode=args.page_mode,
        columns=args.columns,
        priority=args.priority,
    )
    _print(res)


def cmd_power_query(c, args):
    _print(c.power_query(query=args.query, start_time=args.start, end_time=args.end, priority=args.priority))


def cmd_facet_query(c, args):
    _print(
        c.facet_query(
            field=args.field,
            filter=args.filter or "",
            start_time=args.start,
            end_time=args.end,
            max_count=args.max,
            priority=args.priority,
        )
    )


def cmd_numeric_query(c, args):
    _print(
        c.numeric_query(
            function=args.function,
            filter=args.filter or "",
            start_time=args.start,
            end_time=args.end,
            buckets=args.buckets,
            priority=args.priority,
        )
    )


def cmd_timeseries_query(c, args):
    q = {
        "function": args.function,
        "startTime": args.start,
        "buckets": args.buckets,
    }
    if args.filter:
        q["filter"] = args.filter
    if args.end is not None:
        q["endTime"] = args.end
    if args.create_summaries is not None:
        q["createSummaries"] = args.create_summaries
    if args.only_use_summaries is not None:
        q["onlyUseSummaries"] = args.only_use_summaries
    _print(c.timeseries_query(queries=[q]))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sdl_cli", description="SentinelOne SDL API CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # list-files
    sp = sub.add_parser("list-files", help="List configuration file paths")
    sp.set_defaults(func=cmd_list_files)

    # get-file
    sp = sub.add_parser("get-file", help="Read a configuration file")
    sp.add_argument("path")
    sp.add_argument("--expected-version", type=int, default=None)
    sp.add_argument("--prettyprint", action="store_true")
    sp.set_defaults(func=cmd_get_file)

    # put-file
    sp = sub.add_parser("put-file", help="Create, update, or delete a configuration file")
    sp.add_argument("path")
    sp.add_argument("--content", help="Content string (or use --content-file)")
    sp.add_argument("--content-file", help="Path to a file whose text becomes the content")
    sp.add_argument("--expected-version", type=int, default=None)
    sp.add_argument("--delete", action="store_true")
    sp.set_defaults(func=cmd_put_file)

    # query
    sp = sub.add_parser("query", help="Get raw log events matching a filter")
    sp.add_argument("filter", nargs="?", default="")
    sp.add_argument("--start", default=None)
    sp.add_argument("--end", default=None)
    sp.add_argument("--max", type=int, default=100, help="1..5000 (default 100)")
    sp.add_argument("--page-mode", choices=("head", "tail"), default=None)
    sp.add_argument("--columns", default=None)
    sp.add_argument("--priority", choices=("low", "high"), default=None)
    sp.set_defaults(func=cmd_query)

    # power-query
    sp = sub.add_parser("power-query", help="Run a PowerQuery")
    sp.add_argument("query")
    sp.add_argument("--start", default=None)
    sp.add_argument("--end", default=None)
    sp.add_argument("--priority", choices=("low", "high"), default=None)
    sp.set_defaults(func=cmd_power_query)

    # facet-query
    sp = sub.add_parser("facet-query", help="Top-N values of a field")
    sp.add_argument("field")
    sp.add_argument("--filter", default="")
    sp.add_argument("--start", default="1h")
    sp.add_argument("--end", default=None)
    sp.add_argument("--max", type=int, default=100, help="1..1000 (default 100)")
    sp.add_argument("--priority", choices=("low", "high"), default=None)
    sp.set_defaults(func=cmd_facet_query)

    # numeric-query
    sp = sub.add_parser("numeric-query", help="Bucketed numeric data")
    sp.add_argument("--function", default="count", help="count | rate | mean(field) | ...")
    sp.add_argument("--filter", default="")
    sp.add_argument("--start", default="1h")
    sp.add_argument("--end", default=None)
    sp.add_argument("--buckets", type=int, default=1, help="1..5000")
    sp.add_argument("--priority", choices=("low", "high"), default=None)
    sp.set_defaults(func=cmd_numeric_query)

    # timeseries-query
    sp = sub.add_parser("timeseries-query", help="Timeseries query (single query wrapper)")
    sp.add_argument("--function", default="count")
    sp.add_argument("--filter", default="")
    sp.add_argument("--start", default="1h")
    sp.add_argument("--end", default=None)
    sp.add_argument("--buckets", type=int, default=1)
    sp.add_argument("--create-summaries", type=lambda s: s.lower() == "true", default=None)
    sp.add_argument("--only-use-summaries", type=lambda s: s.lower() == "true", default=None)
    sp.set_defaults(func=cmd_timeseries_query)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        client = SDLClient()
    except Exception as e:
        print(f"Failed to initialise client: {e}", file=sys.stderr)
        return 2
    try:
        args.func(client, args)
        return 0
    except SDLAPIError as e:
        sys.stderr.write(f"API error (HTTP {e.status}): {e}\n")
        if e.body:
            try:
                sys.stderr.write(json.dumps(e.body, indent=2) + "\n")
            except Exception:
                sys.stderr.write(str(e.body) + "\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
