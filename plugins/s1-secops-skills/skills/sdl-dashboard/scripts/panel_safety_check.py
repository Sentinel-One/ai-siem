#!/usr/bin/env python3
"""panel_safety_check.py: scan an SDL dashboard JSON for known-bad panel
patterns before deploy.

Run this before every put_file. It catches issues the SDL API will accept and
the renderer will silently fail on (or which produce HTTP 500 from PowerQuery).
Each rule traces back to a row in SKILL.md / references/lessons-learned.md.

Usage:
    python panel_safety_check.py path/to/dashboard.json
    python panel_safety_check.py dashboard.json --warn-only

Exit status:
    0  no issues
    1  one or more rule violations found
    2  could not parse the dashboard JSON

Rules implemented (each rule has an ID; --ignore lets you suppress one):

    L01  Every panel must have explicit x, y, w, h in `layout`.
    Q01  graphStyle: "area" with a `query:` field (use stacked_bar/line, or use plots:).
    M01  Markdown panel uses `content:` instead of `markdown:`.
    P01  Anything after `| transpose` (transpose must be terminal).
    P02  Hyphenated arithmetic: `total-min`, `max-min` without spaces.
    P03  Aggregate function `count_if(...)` or `countif(...)`.
    P04  `sum(if(predicate, value, 0))` or other `sum(if(...))` aggregate.
    P05  `| union (subquery)` to merge pipelines.
    P06  Named subquery `let totals = (... | group ...)` before main pipeline.
    P07  `\\s` or `\\d` regex escapes inside `matches '...'`.
    P08  Full-text predicate combined with `timebucket` + `transpose` (timeline timeout).
    N01  Number panel without terminal `| limit 1`.
    N02  Table panel without any `| limit N`.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------- helpers ----------------------------------------------------------

def _parse_dashboard(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import json5  # type: ignore
            return json5.loads(text)
        except Exception as e:
            raise SystemExit(f"ERROR: dashboard JSON is not parseable as JSON or JSON5: {e}")


def _flatten_panels(dash: Dict[str, Any]) -> List[Tuple[str, int, Dict[str, Any]]]:
    out: List[Tuple[str, int, Dict[str, Any]]] = []
    if dash.get("configType") == "TABBED" and isinstance(dash.get("tabs"), list):
        for tab in dash["tabs"]:
            tab_name = tab.get("tabName") or "(unnamed tab)"
            for i, g in enumerate(tab.get("graphs") or []):
                out.append((tab_name, i, g))
    else:
        for i, g in enumerate(dash.get("graphs") or []):
            out.append(("(single-tab)", i, g))
    return out


def _label(tab: str, idx: int, panel: Dict[str, Any]) -> str:
    return f"{tab} :: panel#{idx} '{panel.get('title','(untitled)')}'"


# ---------- rules ------------------------------------------------------------

def rule_L01(tab: str, idx: int, panel: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    layout = panel.get("layout") or {}
    missing = [k for k in ("x", "y", "w", "h") if k not in layout]
    if missing:
        return ("L01", f"layout missing keys: {missing}. Every panel must specify explicit x, y, w, h.")
    return None


def rule_Q01(tab: str, idx: int, panel: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    if (panel.get("graphStyle") or "").lower() == "area" and "query" in panel:
        return ("Q01", "graphStyle 'area' with a `query:` field renders an indefinite spinner. "
                       "Switch to graphStyle 'stacked_bar' or 'line', or restructure to use `plots:` instead of `query:`.")
    return None


def rule_M01(tab: str, idx: int, panel: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    if (panel.get("graphStyle") or "").lower() == "markdown":
        if "content" in panel and "markdown" not in panel:
            return ("M01", "Markdown panel uses `content:` instead of `markdown:`. "
                           "The renderer will display a blank tile with no error. Rename to `markdown:`.")
    return None


def rule_P01_transpose_not_terminal(query: str) -> Optional[Tuple[str, str]]:
    # If the query contains `| transpose ...` and there is a subsequent `|` after it,
    # then transpose is not the last command.
    m = re.search(r"\|\s*transpose\b", query, flags=re.IGNORECASE)
    if not m:
        return None
    tail = query[m.end():]
    if re.search(r"\|\s*\w", tail):
        return ("P01", "Pipeline contains commands AFTER `| transpose`. transpose must be the terminal command.")
    return None


def rule_P02_hyphen_arith(query: str) -> Optional[Tuple[str, str]]:
    # Detect `let foo = bar-baz` or `... = a-b ...` where both sides are bare identifiers
    # (not surrounded by spaces). Only flag inside `| let ...` lines to reduce noise.
    for m in re.finditer(r"\|\s*let\s+\w+\s*=\s*(.+?)(?:\||$)", query, flags=re.IGNORECASE | re.DOTALL):
        expr = m.group(1)
        if re.search(r"[A-Za-z_][A-Za-z0-9_.]*-[A-Za-z_][A-Za-z0-9_.]*", expr):
            return ("P02", "Hyphenated arithmetic without spaces (e.g. `total-min`). "
                           "Add spaces: `total - min`. The PQ parser otherwise reads it as one identifier.")
    return None


def rule_P03_count_if(query: str) -> Optional[Tuple[str, str]]:
    if re.search(r"\bcount_if\s*\(", query, flags=re.IGNORECASE) or re.search(r"\bcountif\s*\(", query, flags=re.IGNORECASE):
        return ("P03", "`count_if(...)` / `countif(...)` aggregates produce HTTP 500 in dashboards. "
                       "Replace with `| filter <pred> | group hits=count()` or a side-by-side breakdown panel.")
    return None


def rule_P04_sum_if(query: str) -> Optional[Tuple[str, str]]:
    if re.search(r"\bsum\s*\(\s*if\s*\(", query, flags=re.IGNORECASE):
        return ("P04", "`sum(if(predicate, value, 0))` aggregates produce HTTP 500 inside `| group`. "
                       "Replace with two adjacent panels (totals + breakdown) or a `| filter` before group.")
    return None


def rule_P05_union(query: str) -> Optional[Tuple[str, str]]:
    if re.search(r"\|\s*union\s*\(", query, flags=re.IGNORECASE):
        return ("P05", "`| union (subquery)` produces HTTP 500. Use two adjacent panels instead.")
    return None


def rule_P06_named_subquery(query: str) -> Optional[Tuple[str, str]]:
    # `let <name> = (... | group ...)` pre-pipeline, with parens.
    if re.search(r"\blet\s+\w+\s*=\s*\([^)]*\|\s*group\b", query, flags=re.IGNORECASE | re.DOTALL):
        return ("P06", "Named subquery (`let name = (... | group ...)`) produces HTTP 500. "
                       "Inline the values or split into two adjacent panels.")
    return None


def rule_P07_regex_escapes(query: str) -> Optional[Tuple[str, str]]:
    # Detect `matches '...\\s...'` / `\\d` literally inside the regex literal.
    if re.search(r"matches\s+'[^']*\\\\[sd][^']*'", query, flags=re.IGNORECASE):
        return ("P07", "Regex escapes `\\s` / `\\d` inside `matches '...'` produce HTTP 500. "
                       "Use simple character classes ([0-9], [ \\t]) or `field in (...)` for fixed lists.")
    return None


def _has_fulltext(query: str) -> bool:
    """Heuristic: a bare-quoted string token in the index-level filter.

    Full-text predicates appear in the index-level filter before the first pipe
    (`dataSource.name='x' '<token>' | group ...`). The engine treats any quoted
    string that is NOT a structured-field RHS or a function argument as a
    substring search across raw_data.

    We strip the obvious structured constructs first, then any leftover quoted
    content in the head fragment is a full-text predicate.
    """
    # Only the head fragment (before the first `|`) carries the index-level filter.
    head = query.split("|", 1)[0]

    # Strip `<field>=`/`!=`/`contains`/`matches`/`in` followed by a quoted RHS.
    cleaned = re.sub(
        r"\b[\w.]+\s*(?:=|!=|contains|matches|in)\s*'[^']*'",
        " ",
        head,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r'\b[\w.]+\s*(?:=|!=|contains|matches|in)\s*"[^"]*"',
        " ",
        cleaned,
        flags=re.IGNORECASE,
    )
    # Strip `name(...)` function calls (single-line, balanced parens).
    cleaned = re.sub(r"\b\w+\s*\([^)]*\)", " ", cleaned)

    # Anything left that contains a quoted token is treated as full-text.
    return bool(re.search(r"'[^']+'", cleaned) or re.search(r'"[^"]+"', cleaned))


def rule_P08_fulltext_timeline(query: str) -> Optional[Tuple[str, str]]:
    if not _has_fulltext(query):
        return None
    has_bucket = bool(re.search(r"\btimebucket\s*\(", query, flags=re.IGNORECASE))
    has_transpose = bool(re.search(r"\|\s*transpose\b", query, flags=re.IGNORECASE))
    if has_bucket and has_transpose:
        return ("P08", "Full-text predicate combined with `timebucket` + `transpose` reliably times out. "
                       "Use a structured-field equivalent for timelines, or restrict the timeline to a "
                       "narrower co-filter.")
    return None


def rule_N01_number_no_limit(panel: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    if (panel.get("graphStyle") or "").lower() != "number":
        return None
    q = (panel.get("query") or "").strip()
    if not q:
        return None
    # Must end with a `| limit 1` (allow trailing whitespace / comments).
    if not re.search(r"\|\s*limit\s+1\s*$", q, flags=re.IGNORECASE):
        return ("N01", "Number panel must terminate with `| limit 1`. "
                       "Without it the engine keeps scanning after the answer is computed.")
    return None


def rule_N02_table_no_limit(panel: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    style = (panel.get("graphStyle") or "table").lower()
    if style not in ("table", ""):  # default panel style for PQ is table
        return None
    q = (panel.get("query") or "").strip()
    if not q:
        return None
    if not re.search(r"\|\s*limit\s+\d+", q, flags=re.IGNORECASE):
        return ("N02", "Table panel must include an explicit `| limit N` somewhere in the pipeline. "
                       "Unbounded tables force a full scan.")
    return None


# ---------- runner -----------------------------------------------------------

QUERY_RULES = (
    rule_P01_transpose_not_terminal,
    rule_P02_hyphen_arith,
    rule_P03_count_if,
    rule_P04_sum_if,
    rule_P05_union,
    rule_P06_named_subquery,
    rule_P07_regex_escapes,
    rule_P08_fulltext_timeline,
)

PANEL_RULES = (rule_L01, rule_Q01, rule_M01)
PANEL_QUERY_RULES = (rule_N01_number_no_limit, rule_N02_table_no_limit)


def check(dashboard: Dict[str, Any], ignore: List[str]) -> List[Tuple[str, str, str]]:
    """Return list of (rule_id, panel_label, message) tuples."""
    violations: List[Tuple[str, str, str]] = []
    for tab, idx, panel in _flatten_panels(dashboard):
        label = _label(tab, idx, panel)

        for r in PANEL_RULES:
            v = r(tab, idx, panel)
            if v and v[0] not in ignore:
                violations.append((v[0], label, v[1]))

        for r in PANEL_QUERY_RULES:
            v = r(panel)
            if v and v[0] not in ignore:
                violations.append((v[0], label, v[1]))

        q = panel.get("query") or ""
        if q:
            for r in QUERY_RULES:
                v = r(q)
                if v and v[0] not in ignore:
                    violations.append((v[0], label, v[1]))
    return violations


def main() -> int:
    ap = argparse.ArgumentParser(description="Pre-deploy safety check for an SDL dashboard JSON.")
    ap.add_argument("dashboard", help="Path to dashboard JSON.")
    ap.add_argument("--ignore", default="", help="Comma-separated rule IDs to skip (e.g. 'L01,N02').")
    ap.add_argument("--warn-only", action="store_true", help="Always exit 0; print findings only.")
    args = ap.parse_args()

    path = Path(args.dashboard).resolve()
    if not path.exists():
        print(f"ERROR: dashboard not found: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8")
    try:
        dash = _parse_dashboard(text)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 2

    ignore = [s.strip() for s in args.ignore.split(",") if s.strip()]
    issues = check(dash, ignore)

    if not issues:
        print(f"OK: panel_safety_check passed for {path.name} (no issues).")
        return 0

    print(f"FOUND {len(issues)} issue(s) in {path.name}:")
    print()
    for rule_id, label, msg in issues:
        print(f"  [{rule_id}] {label}")
        print(f"          {msg}")
        print()
    return 0 if args.warn_only else 1


if __name__ == "__main__":
    raise SystemExit(main())
