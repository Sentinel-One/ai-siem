#!/usr/bin/env python3
"""Lint SDL log parser files offline, before deploying them.

    python3 scripts/lint_parser.py myparser.json            # one file
    python3 scripts/lint_parser.py parsers/                 # every .conf / .json under a dir
    python3 scripts/lint_parser.py --new myparser.json      # authoring: hard rules are ERRORs
    python3 scripts/lint_parser.py --json parsers/ > out.json
    python3 scripts/lint_parser.py --csv parsers/ > out.csv
    python3 scripts/lint_parser.py --rules                  # list the rules

Exit code: 1 if any ERROR finding (at or above --min-severity), else 0.
Standard library only. Rules live in scripts/parser_rules.py.

A clean lint means none of the KNOWN traps are present. It does not prove the
parser parses; the SDL parser engine is server-side. Deploy and validate live.
"""
from __future__ import annotations

import argparse
import csv
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from parser_rules import (OFFLINE_DISCLAIMER, RULES, SEV_RANK,  # noqa: E402
                          ParseError, lint_text, load_augmented_json)

EXTS = {".conf", ".json", ".json5", ".parser"}


PARSER_KEYS = {"formats", "aliasTo", "patterns", "lineGroupers", "mappings"}


def _looks_like_parser(f: pathlib.Path) -> bool:
    """In a directory walk, skip JSON that is clearly not a parser (query
    results, metadata). Unparseable files are kept so they get reported."""
    try:
        obj, _ = load_augmented_json(f.read_text(encoding="utf-8", errors="replace"))
    except ParseError:
        return True
    return not isinstance(obj, dict) or bool(PARSER_KEYS & obj.keys())


def _targets(paths: list[str]) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for p in paths:
        q = pathlib.Path(p)
        if q.is_dir():
            out.extend(sorted(f for f in q.rglob("*")
                              if f.is_file() and f.suffix in EXTS and _looks_like_parser(f)))
        elif q.is_file():
            out.append(q)
        else:
            print(f"lint_parser: no such file or directory: {p}", file=sys.stderr)
            sys.exit(2)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--new", action="store_true",
                    help="authoring a new parser: mandatory attributes, the security "
                         "category and a semver metadata.version become ERRORs")
    ap.add_argument("--min-severity", choices=["ERROR", "WARN", "INFO"], default="INFO")
    ap.add_argument("--only", help="comma-separated rule ids, e.g. R01,R02")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true")
    fmt.add_argument("--csv", action="store_true")
    ap.add_argument("--rules", action="store_true", help="list the rules and exit")
    a = ap.parse_args(argv)

    if a.rules:
        for r in RULES:
            print(f"{r.id}  {r.severity:5}  {r.title}  [{r.ref}]")
        return 0
    if not a.paths:
        ap.error("give at least one file or directory")

    only = [x.strip() for x in a.only.split(",")] if a.only else None
    floor = SEV_RANK[a.min_severity]
    results = []
    for f in _targets(a.paths):
        text = f.read_text(encoding="utf-8", errors="replace")
        findings = [x for x in lint_text(text, new=a.new, only=only)
                    if SEV_RANK[x.severity] <= floor]
        results.append((f, findings))

    errors = sum(1 for _, fs in results for x in fs if x.severity == "ERROR")

    if a.json:
        json.dump({"disclaimer": OFFLINE_DISCLAIMER,
                   "files": [{"file": str(f), "findings": [x.as_dict() for x in fs]}
                             for f, fs in results]}, sys.stdout, indent=2)
        print()
    elif a.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["file", "rule", "severity", "line", "path", "message", "ref"])
        for f, fs in results:
            for x in fs:
                w.writerow([f, x.rule, x.severity, x.line or "", x.path, x.message, x.ref])
    else:
        for f, fs in results:
            for x in fs:
                loc = f"{f}:{x.line}" if x.line else str(f)
                print(f"{loc}: {x.severity} {x.rule} {x.message}"
                      + (f" ({x.path})" if x.path else ""))
        clean = sum(1 for _, fs in results if not fs)
        print(f"\n{len(results)} file(s), {clean} clean, {errors} error(s), "
              f"{sum(len(fs) for _, fs in results) - errors} other finding(s)")
        print(OFFLINE_DISCLAIMER)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
