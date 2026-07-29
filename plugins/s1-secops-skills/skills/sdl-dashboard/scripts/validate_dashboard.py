#!/usr/bin/env python3
"""validate_dashboard.py: replay every panel in a deployed SDL dashboard JSON and
capture log evidence (sample rows, row count, matchCount, elapsed, errors) for
each one.

This is the post-deploy validation step from the dashboard skill workflow. It
is mandatory: every dashboard delivered ships with the JSON + markdown evidence
files this script produces, plus the PDF rendered by render_validation_pdf.py.

Usage:
    python validate_dashboard.py path/to/dashboard.json
    python validate_dashboard.py dashboard.json --start 7d --end now --out ./evidence
    python validate_dashboard.py dashboard.json --resume          # skip panels already in results JSON

Output:
    <out>/<basename>.evidence.json         per-panel evidence (keyed on "tab::title")
    <out>/<basename>.evidence.md           human-readable markdown report

Notes:
    Auth falls through to the console JWT by default (the scoped log_read /
    config_read keys are force-cleared so a `console_api_token` in
    credentials.json is used instead). The console JWT has both query and
    config-read permission, which is what dashboard validation needs.

    The script is idempotent. If the evidence JSON already contains a key for a
    panel, that panel is skipped. Persistence happens after every panel so
    re-running picks up where it left off.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _import_sdl_client():
    """Locate sdl_client.py from the sibling sentinelone-sdl-api skill.

    Walks up from this script's location to find a sentinelone-sdl-api/scripts
    directory. Falls back to PYTHONPATH if the script is run outside the repo.
    """
    here = Path(__file__).resolve()
    candidates: List[Path] = []
    for ancestor in [here.parent, *here.parents]:
        candidates.append(ancestor / "sentinelone-sdl-api" / "scripts")
        candidates.append(ancestor.parent / "sentinelone-sdl-api" / "scripts")
    for c in candidates:
        if (c / "sdl_client.py").exists():
            sys.path.insert(0, str(c))
            break
    try:
        from sdl_client import SDLClient  # type: ignore
        return SDLClient
    except Exception as e:
        print(
            "ERROR: could not import sdl_client. Add sentinelone-sdl-api/scripts "
            "to PYTHONPATH or run this script from inside the claude-skills repo.",
            file=sys.stderr,
        )
        print(f"underlying error: {e}", file=sys.stderr)
        sys.exit(2)


def _parse_dashboard(dash: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten a dashboard JSON into a list of panel dicts with tab name attached."""
    panels: List[Dict[str, Any]] = []
    if dash.get("configType") == "TABBED" and isinstance(dash.get("tabs"), list):
        for tab in dash["tabs"]:
            tab_name = tab.get("tabName") or "(unnamed tab)"
            for g in tab.get("graphs") or []:
                panels.append({**g, "_tab": tab_name})
    else:
        for g in dash.get("graphs") or []:
            panels.append({**g, "_tab": "(single-tab)"})
    return panels


def _panel_key(panel: Dict[str, Any], idx: int) -> str:
    tab = panel.get("_tab") or "tab"
    title = panel.get("title") or f"panel-{idx}"
    return f"{tab}::{title}"


def _is_runnable(panel: Dict[str, Any]) -> bool:
    """A panel is runnable if it has a `query` (PowerQuery) and is not a markdown tile."""
    if panel.get("graphStyle") == "markdown":
        return False
    if "query" in panel and isinstance(panel["query"], str) and panel["query"].strip():
        return True
    # filter+facet panels (line/area/distribution) are not validated by this script;
    # they would need the timeseries / facet APIs, not power_query. They are skipped
    # explicitly so the report shows them as "not_validated".
    return False


def _verdict(panel: Dict[str, Any], result: Dict[str, Any]) -> str:
    if not result.get("ok"):
        return "FAIL"
    style = (panel.get("graphStyle") or "table").lower()
    rows = result.get("row_count") or 0
    cols = len(result.get("columns") or [])
    if rows == 0:
        # Empty result is valid evidence; flag it for the appendix but don't fail.
        return "EMPTY"
    if style == "number":
        return "PASS" if rows == 1 and cols == 1 else "WARN"
    if style in ("donut", "pie"):
        return "PASS" if cols >= 2 else "WARN"
    if style in ("stacked_bar", "bar", "line", "area", "stacked", "honeycomb"):
        return "PASS" if cols >= 2 else "WARN"
    return "PASS"  # table, distribution, anything else: presence of rows is enough


def _replay(client, panel: Dict[str, Any], start_time: str, end_time: Optional[str]) -> Dict[str, Any]:
    t0 = time.time()
    style = panel.get("graphStyle") or "table"
    q = panel.get("query") or ""
    try:
        kwargs = {"query": q, "start_time": start_time}
        if end_time:
            kwargs["end_time"] = end_time
        r = client.power_query(**kwargs)
        elapsed = round(time.time() - t0, 2)
        values = r.get("values") or []
        columns = [c.get("name") for c in (r.get("columns") or []) if isinstance(c, dict)]
        match_count = (
            (r.get("data") or {}).get("matchCount")
            if isinstance(r.get("data"), dict)
            else None
        )
        if match_count is None:
            match_count = r.get("matchingEvents")
        return {
            "ok": True,
            "style": style,
            "query": q,
            "elapsed_s": elapsed,
            "row_count": len(values),
            "columns": columns,
            "sample_rows": values[:3],
            "matchCount": match_count,
            "omittedEvents": r.get("omittedEvents"),
        }
    except Exception as e:
        elapsed = round(time.time() - t0, 2)
        return {"ok": False, "style": style, "query": q, "elapsed_s": elapsed, "error": str(e)[:300]}


def _render_markdown(dash_path: Path, results: Dict[str, Dict[str, Any]], panels: List[Dict[str, Any]],
                     start_time: str, end_time: Optional[str]) -> str:
    lines: List[str] = []
    lines.append(f"# Dashboard validation evidence: `{dash_path.name}`")
    lines.append("")
    lines.append(f"- Source dashboard JSON: `{dash_path}`")
    lines.append(f"- Time window: `start_time={start_time}`, `end_time={end_time or 'now'}`")
    lines.append(f"- Generated: `{time.strftime('%Y-%m-%d %H:%M:%S %Z')}`")
    lines.append("")

    # Summary
    total = len(panels)
    runnable = sum(1 for p in panels if _is_runnable(p))
    pass_n = sum(1 for k in results if results[k].get("verdict") == "PASS")
    warn_n = sum(1 for k in results if results[k].get("verdict") == "WARN")
    empty_n = sum(1 for k in results if results[k].get("verdict") == "EMPTY")
    fail_n = sum(1 for k in results if results[k].get("verdict") == "FAIL")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total panels: **{total}** (runnable: {runnable}, markdown/skipped: {total - runnable})")
    lines.append(f"- PASS: **{pass_n}**, WARN: **{warn_n}**, EMPTY: **{empty_n}**, FAIL: **{fail_n}**")
    lines.append("")

    # Per-tab sections
    by_tab: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {}
    for idx, p in enumerate(panels):
        if not _is_runnable(p):
            continue
        key = _panel_key(p, idx)
        by_tab.setdefault(p["_tab"], []).append((p, results.get(key, {})))

    for tab, items in by_tab.items():
        lines.append(f"## Tab: {tab}")
        lines.append("")
        for p, r in items:
            verdict = r.get("verdict", "?")
            style = p.get("graphStyle") or "table"
            elapsed = r.get("elapsed_s")
            lines.append(f"### {p.get('title','(untitled)')}  ·  `{style}`  ·  **{verdict}**")
            lines.append("")
            lines.append(f"- elapsed: `{elapsed}s`")
            lines.append(f"- row_count: `{r.get('row_count')}`  ·  matchCount: `{r.get('matchCount')}`")
            lines.append(f"- columns: `{r.get('columns')}`")
            if r.get("error"):
                lines.append(f"- **error**: `{r['error']}`")
            lines.append("")
            lines.append("```text")
            lines.append((p.get("query") or "").strip())
            lines.append("```")
            lines.append("")
            sample = r.get("sample_rows") or []
            if sample:
                lines.append("Sample rows (first 3):")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(sample, indent=2, default=str))
                lines.append("```")
            else:
                if verdict == "EMPTY":
                    lines.append("> NO LOG EVIDENCE in the queried window. ")
                    lines.append("> This panel ran successfully but returned 0 rows. ")
                    lines.append("> Provide a SOC-meaningful interpretation in the markdown header next to this panel.")
            lines.append("")

    # Empty-result appendix
    empties = [(k, r) for k, r in results.items() if r.get("verdict") == "EMPTY"]
    if empties:
        lines.append("## Appendix: empty-result panels")
        lines.append("")
        lines.append("Each panel below ran successfully but returned 0 rows. Document the SOC-meaningful")
        lines.append("interpretation in the dashboard's markdown header for that section so analysts read")
        lines.append("the empty panel as evidence of posture, not as a broken dashboard.")
        lines.append("")
        for k, r in empties:
            mc = r.get("matchCount")
            mc_label = f"matchCount={mc}" if mc is not None else "matchCount unavailable"
            lines.append(f"- `{k}`: 0 rows, {mc_label}, elapsed {r.get('elapsed_s')}s.")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay every panel in a deployed SDL dashboard and capture log evidence.")
    ap.add_argument("dashboard", help="Path to dashboard JSON file (single-tab or multi-tab).")
    ap.add_argument("--start", default="7d", help="start_time for power_query (default: 7d).")
    ap.add_argument("--end", default=None, help="end_time for power_query (default: now).")
    ap.add_argument("--out", default=None, help="Output directory (default: alongside the dashboard JSON).")
    ap.add_argument("--resume", action="store_true",
                    help="Skip panels already present in the existing evidence JSON.")
    args = ap.parse_args()

    dash_path = Path(args.dashboard).resolve()
    if not dash_path.exists():
        print(f"ERROR: dashboard not found: {dash_path}", file=sys.stderr)
        return 2

    out_dir = Path(args.out).resolve() if args.out else dash_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    base = dash_path.stem
    json_out = out_dir / f"{base}.evidence.json"
    md_out = out_dir / f"{base}.evidence.md"

    # Tolerate the JavaScript-literal form SDL accepts (unquoted keys, trailing commas).
    raw = dash_path.read_text(encoding="utf-8")
    try:
        dash = json.loads(raw)
    except json.JSONDecodeError:
        try:
            import json5  # type: ignore
            dash = json5.loads(raw)
        except Exception as e:
            print(f"ERROR: dashboard JSON is not parseable as JSON or JSON5: {e}", file=sys.stderr)
            return 2

    panels = _parse_dashboard(dash)
    if not panels:
        print("ERROR: no panels found in dashboard JSON.", file=sys.stderr)
        return 2

    SDLClient = _import_sdl_client()
    client = SDLClient()
    # Force-clear scoped keys so auth falls through to the console JWT, which has the
    # broadest read scope and is the most reliable for replaying mixed-source panels.
    for k in ("log_read_key", "config_read_key", "config_write_key"):
        if k in client.keys:
            client.keys[k] = ""

    # Resume support
    results: Dict[str, Dict[str, Any]] = {}
    if args.resume and json_out.exists():
        try:
            results = json.loads(json_out.read_text(encoding="utf-8"))
            print(f"resume: loaded {len(results)} prior result(s) from {json_out}")
        except Exception:
            results = {}

    # Replay
    for idx, p in enumerate(panels):
        key = _panel_key(p, idx)
        if not _is_runnable(p):
            results[key] = {"ok": True, "verdict": "SKIP", "reason": "markdown or filter+facet panel"}
            continue
        if key in results and results[key].get("verdict") not in (None, "FAIL"):
            continue  # resume: skip already-validated runnable panels
        print(f"[{idx+1}/{len(panels)}] {key}")
        r = _replay(client, p, args.start, args.end)
        r["verdict"] = _verdict(p, r)
        results[key] = r
        # Persist after every panel so re-running picks up where it left off.
        json_out.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")

    # Markdown report
    md = _render_markdown(dash_path, results, panels, args.start, args.end)
    md_out.write_text(md, encoding="utf-8")

    fail_n = sum(1 for r in results.values() if r.get("verdict") == "FAIL")
    print(f"done. evidence JSON: {json_out}")
    print(f"      evidence MD:   {md_out}")
    print(f"      FAIL panels:   {fail_n}")
    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
