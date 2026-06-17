#!/usr/bin/env python3
"""render_validation_pdf.py: render a per-panel evidence JSON (produced by
validate_dashboard.py) into a PDF report suitable for leadership distribution.

The PDF contains:
- Cover page (dashboard name, time window, summary counts).
- Per-tab sections with one block per panel: title, style, verdict, elapsed,
  rowCount, matchCount, the exact PowerQuery body, sample-row table.
- Appendix listing every empty-result panel with its SOC-meaningful
  interpretation (read from a sidecar interpretations.json if present, or
  printed as a TODO line for the operator to fill in).

Usage:
    python render_validation_pdf.py path/to/dashboard.evidence.json
    python render_validation_pdf.py evidence.json --out report.pdf --title "SOC Overview"
    python render_validation_pdf.py evidence.json --interpretations interpretations.json

`interpretations.json` is a flat object keyed on the same `tab::title` keys the
evidence JSON uses, with a string value containing the SOC interpretation
("0 here is the desired posture; non-zero indicates a regression worth
investigating", etc.). Any empty-result panel without an entry is rendered
with a clear "TODO interpretation" placeholder so the operator can see what is
missing.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
        Preformatted,
    )
except Exception as e:
    print(
        "ERROR: reportlab is required. Install with: "
        "pip install --break-system-packages reportlab",
        file=sys.stderr,
    )
    print(f"underlying error: {e}", file=sys.stderr)
    sys.exit(2)


# Verdict colour palette (no em-dashes, business-direct)
VERDICT_COLOR = {
    "PASS":  colors.HexColor("#2e7d32"),
    "WARN":  colors.HexColor("#ef6c00"),
    "EMPTY": colors.HexColor("#b08800"),
    "FAIL":  colors.HexColor("#c62828"),
    "SKIP":  colors.HexColor("#546e7a"),
}


def _styles():
    """Return a dict of named ParagraphStyles. We use unique `EV*` names to avoid
    collisions with reportlab's default getSampleStyleSheet entries (Normal,
    BodyText, Heading1-6, Code, etc.)."""
    return {
        "H1":      ParagraphStyle(name="EVH1", fontSize=20, leading=24, spaceAfter=12, fontName="Helvetica-Bold"),
        "H2":      ParagraphStyle(name="EVH2", fontSize=14, leading=18, spaceBefore=14, spaceAfter=8, fontName="Helvetica-Bold"),
        "H3":      ParagraphStyle(name="EVH3", fontSize=11, leading=14, spaceBefore=10, spaceAfter=4, fontName="Helvetica-Bold"),
        "Meta":    ParagraphStyle(name="EVMeta", fontSize=9, leading=11, textColor=colors.grey),
        "Body":    ParagraphStyle(name="EVBody", fontSize=10, leading=13),
        "Verdict": ParagraphStyle(name="EVVerdict", fontSize=11, leading=13, fontName="Helvetica-Bold"),
        "Code":    ParagraphStyle(name="EVCode", fontSize=8, leading=10, fontName="Courier", textColor=colors.HexColor("#1a1a1a")),
    }


def _safe(s: Any) -> str:
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _truncate(s: str, n: int = 80) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _row_to_strings(row: Any, max_cells: int = 8) -> List[str]:
    """Normalise a sample-row to a list of short strings for table display.

    The SDL power_query response represents rows as lists. Some entries can be
    nested dicts/lists; flatten with json.dumps for those.
    """
    if isinstance(row, list):
        cells = row[:max_cells]
    elif isinstance(row, dict):
        cells = list(row.values())[:max_cells]
    else:
        cells = [row]
    out: List[str] = []
    for c in cells:
        if isinstance(c, (dict, list)):
            out.append(_truncate(json.dumps(c, default=str), 80))
        elif c is None:
            out.append("")
        else:
            out.append(_truncate(str(c), 80))
    return out


def _summary_counts(results: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    counts = {"PASS": 0, "WARN": 0, "EMPTY": 0, "FAIL": 0, "SKIP": 0, "TOTAL": 0}
    for v in results.values():
        counts["TOTAL"] += 1
        verdict = v.get("verdict", "?")
        if verdict in counts:
            counts[verdict] += 1
    return counts


def _group_by_tab(results: Dict[str, Dict[str, Any]]) -> Dict[str, List[tuple]]:
    """Group panel results by tab. Key is "tab::title"."""
    tabs: Dict[str, List[tuple]] = {}
    for key, r in results.items():
        if "::" in key:
            tab, title = key.split("::", 1)
        else:
            tab, title = "(default)", key
        tabs.setdefault(tab, []).append((title, r))
    return tabs


def render(evidence_path: Path, out_path: Path, title: Optional[str],
           interpretations: Dict[str, str]) -> None:
    results: Dict[str, Dict[str, Any]] = json.loads(evidence_path.read_text(encoding="utf-8"))
    counts = _summary_counts(results)
    tabs = _group_by_tab(results)

    title_text = title or evidence_path.stem.replace(".evidence", "")
    styles = _styles()

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=LETTER,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
        title=f"Dashboard validation evidence: {title_text}",
    )

    story: List[Any] = []

    # Cover
    story.append(Paragraph(f"Dashboard validation evidence", styles["H1"]))
    story.append(Paragraph(f"<b>{_safe(title_text)}</b>", styles["H2"]))
    story.append(Paragraph(
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        styles["Meta"],
    ))
    story.append(Paragraph(f"Source: <font face='Courier'>{_safe(evidence_path.name)}</font>", styles["Meta"]))
    story.append(Spacer(1, 0.25 * inch))

    summary = [
        ["Total panels", str(counts["TOTAL"])],
        ["PASS", str(counts["PASS"])],
        ["WARN", str(counts["WARN"])],
        ["EMPTY (0 rows)", str(counts["EMPTY"])],
        ["FAIL", str(counts["FAIL"])],
        ["Skipped (markdown / filter+facet)", str(counts["SKIP"])],
    ]
    t = Table(summary, colWidths=[3.2 * inch, 1.0 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff1")),
        ("FONT", (0, 0), (-1, -1), "Helvetica", 10),
        ("FONT", (1, 1), (1, 1), "Helvetica-Bold", 10),
        ("FONT", (1, 4), (1, 4), "Helvetica-Bold", 10),
        ("TEXTCOLOR", (1, 1), (1, 1), VERDICT_COLOR["PASS"]),
        ("TEXTCOLOR", (1, 2), (1, 2), VERDICT_COLOR["WARN"]),
        ("TEXTCOLOR", (1, 3), (1, 3), VERDICT_COLOR["EMPTY"]),
        ("TEXTCOLOR", (1, 4), (1, 4), VERDICT_COLOR["FAIL"]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cfd8dc")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cfd8dc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.18 * inch))
    story.append(Paragraph(
        "This report is the live-data evidence base for the dashboard. Each "
        "section below replays one panel's PowerQuery against the tenant and "
        "captures the actual response. EMPTY panels are valid evidence when "
        "documented; the Appendix lists each one alongside its SOC-meaningful "
        "interpretation.",
        styles["Body"],
    ))
    story.append(PageBreak())

    # Per-tab sections
    for tab_name, items in tabs.items():
        # Skip tabs that contain only SKIP entries (markdown-only tabs).
        if all(r.get("verdict") == "SKIP" for _, r in items):
            continue
        story.append(Paragraph(f"Tab: {_safe(tab_name)}", styles["H1"]))
        for title_, r in items:
            verdict = r.get("verdict", "?")
            if verdict == "SKIP":
                continue
            color = VERDICT_COLOR.get(verdict, colors.black)
            style_panel = r.get("style") or "table"
            elapsed = r.get("elapsed_s")
            row_count = r.get("row_count")
            match_count = r.get("matchCount")
            cols = r.get("columns")

            story.append(Paragraph(_safe(title_), styles["H2"]))
            story.append(Paragraph(
                f"<font color='{color.hexval()}'><b>{verdict}</b></font> "
                f"&nbsp;&nbsp; style: <font face='Courier'>{_safe(style_panel)}</font> "
                f"&nbsp;&nbsp; elapsed: {_safe(elapsed)}s "
                f"&nbsp;&nbsp; rows: {_safe(row_count)} "
                f"&nbsp;&nbsp; matchCount: {_safe(match_count)}",
                styles["Verdict"],
            ))
            if r.get("error"):
                story.append(Paragraph(
                    f"<font color='{VERDICT_COLOR['FAIL'].hexval()}'><b>error:</b></font> "
                    f"<font face='Courier'>{_safe(r['error'])}</font>",
                    styles["Body"],
                ))
            if cols:
                story.append(Paragraph(
                    f"columns: <font face='Courier'>{_safe(cols)}</font>",
                    styles["Meta"],
                ))

            # Query body (if we have it on the evidence record; otherwise the operator
            # can map back via the source JSON). We do NOT require it; we display if
            # present.
            if r.get("query"):
                story.append(Spacer(1, 0.05 * inch))
                story.append(Preformatted(r["query"].rstrip(), styles["Code"]))

            # Sample rows
            sample = r.get("sample_rows") or []
            if sample:
                # Use response columns as header if available; else generic n0..n7.
                if isinstance(cols, list) and cols:
                    header = [_truncate(str(c or ""), 40) for c in cols[:8]]
                else:
                    header = [f"col{i}" for i in range(min(8, len(_row_to_strings(sample[0]))))]
                rows = [header] + [_row_to_strings(row) for row in sample]
                # Pad short rows so the table is rectangular.
                width = max(len(r) for r in rows)
                rows = [r + [""] * (width - len(r)) for r in rows]
                col_w = [(7.2 / max(width, 1)) * inch] * width
                tbl = Table(rows, colWidths=col_w, repeatRows=1)
                tbl.setStyle(TableStyle([
                    ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
                    ("FONT", (0, 1), (-1, -1), "Courier", 7.5),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cfd8dc")),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8dc")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 3),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ]))
                story.append(Spacer(1, 0.06 * inch))
                story.append(tbl)
            elif verdict == "EMPTY":
                story.append(Spacer(1, 0.06 * inch))
                story.append(Paragraph(
                    f"<para backColor='#fff3e0' borderColor='#ef6c00' borderWidth='0.5' "
                    f"borderPadding='6'><b>NO LOG EVIDENCE</b> in the queried window. "
                    f"matchCount = {_safe(match_count)}. Verify whether 0 reflects "
                    f"posture or coverage; document interpretation in the Appendix.</para>",
                    styles["Body"],
                ))
            story.append(Spacer(1, 0.18 * inch))
        story.append(PageBreak())

    # Appendix: empty-result panels
    empties = []
    for key, r in results.items():
        if r.get("verdict") == "EMPTY":
            empties.append((key, r))

    if empties:
        story.append(Paragraph("Appendix: empty-result panels", styles["H1"]))
        story.append(Paragraph(
            "Each panel below ran successfully but returned 0 rows. Distinguish "
            "<b>posture</b> (0 is desired; non-zero is a regression) from <b>coverage</b> "
            "(0 because no data is flowing). The interpretation column is sourced from "
            "the dashboard's per-panel markdown header; missing entries are flagged "
            "<b>TODO</b> for the operator to fill in.",
            styles["Body"],
        ))
        story.append(Spacer(1, 0.12 * inch))

        rows = [["Panel (tab :: title)", "matchCount", "Interpretation"]]
        for key, r in empties:
            mc = r.get("matchCount")
            interp = interpretations.get(key, "TODO: document SOC-meaningful interpretation for this empty panel.")
            rows.append([_truncate(key, 70), str(mc) if mc is not None else "", interp])
        col_w = [3.2 * inch, 0.9 * inch, 3.1 * inch]
        tbl = Table(rows, colWidths=col_w, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
            ("FONT", (0, 1), (-1, -1), "Helvetica", 8.5),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cfd8dc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cfd8dc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(tbl)

    doc.build(story)


def main() -> int:
    ap = argparse.ArgumentParser(description="Render an SDL dashboard validation JSON into a PDF report.")
    ap.add_argument("evidence", help="Path to the *.evidence.json produced by validate_dashboard.py.")
    ap.add_argument("--out", default=None, help="Output PDF path (default: alongside the evidence JSON).")
    ap.add_argument("--title", default=None, help="Dashboard display title for the cover page.")
    ap.add_argument("--interpretations", default=None,
                    help="Optional JSON file mapping `tab::title` to SOC-meaningful interpretation text "
                         "for empty-result panels.")
    args = ap.parse_args()

    ev_path = Path(args.evidence).resolve()
    if not ev_path.exists():
        print(f"ERROR: evidence JSON not found: {ev_path}", file=sys.stderr)
        return 2

    out_path = Path(args.out).resolve() if args.out else ev_path.with_suffix(".pdf")
    interp: Dict[str, str] = {}
    if args.interpretations:
        ip = Path(args.interpretations).resolve()
        if ip.exists():
            try:
                interp = json.loads(ip.read_text(encoding="utf-8"))
                if not isinstance(interp, dict):
                    print("WARN: interpretations file is not a JSON object; ignoring.", file=sys.stderr)
                    interp = {}
            except Exception as e:
                print(f"WARN: could not parse interpretations file: {e}", file=sys.stderr)

    render(ev_path, out_path, args.title, interp)
    print(f"wrote PDF: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
