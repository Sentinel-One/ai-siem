"""
Render all charts for a data-source CTO report as PNG images.

Input : reports/<slug>_<window>/data.json  (or path via --data)
Output: reports/<slug>_<window>/charts/*.png

Source-agnostic. Reads `source`, `window_label`, `summary` and the query
rows from the JSON; does not assume the source is Example Source.

Derives `by_user`, `by_user_blocks`, `by_user_bypass` views from
`per_user_mix_top10` so the collector only asked the tenant once.

Palette is constrained and maps semantic meaning onto colour:
  NAVY   dominant colour (#0B1F3A)
  CORAL  block / risk (#E8434F)
  AMBER  modify (#F2A950)
  TEAL   bypass (#4FB89E)
  SLATE  log / other (#8899A6)
  CREAM  backgrounds (#F5F1E8)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import numpy as np

NAVY = "#0B1F3A"
CORAL = "#E8434F"
AMBER = "#F2A950"
TEAL = "#4FB89E"
SLATE = "#8899A6"
CREAM = "#F5F1E8"
INK = "#1A1F2E"

ACTION_COLORS = {
    "log": SLATE,
    "block": CORAL,
    "modify": AMBER,
    "bypass": TEAL,
    "None": "#CBD1D6",
    "null": "#CBD1D6",
}
ACTION_ORDER = ["log", "block", "modify", "bypass", "None"]

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
    "axes.edgecolor": INK,
    "axes.labelcolor": INK,
    "axes.titlecolor": INK,
    "xtick.color": INK,
    "ytick.color": INK,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.color": "#E3E5E8",
    "grid.linewidth": 0.6,
    "savefig.facecolor": "white",
    "figure.facecolor": "white",
})


def shorten(u: Any, maxlen: int = 28) -> str:
    if u is None or u in ("None", "null", ""):
        return "(unattributed)"
    s = str(u)
    if len(s) > maxlen:
        return s[: maxlen - 1] + "..."
    return s


# ---------------------------------------------------------- derived views

def _principal_key(mix_rows: List[Dict[str, Any]]) -> Optional[str]:
    """Detect which principal column per_user_mix_top10 grouped by."""
    for r in mix_rows:
        for k in ("user", "src.hostname", "src.ip.address"):
            if k in r:
                return k
    return None


def derive_by_user(mix_rows: List[Dict[str, Any]],
                   p_key: str) -> List[Dict[str, Any]]:
    """Sum per-user across actions to get a per-user total ranking."""
    acc: Dict[Any, int] = defaultdict(int)
    for r in mix_rows:
        acc[r.get(p_key)] += int(r.get("n") or 0)
    ranked = sorted(acc.items(), key=lambda kv: -kv[1])
    return [{p_key: k, "n": v} for k, v in ranked]


def derive_action_rows(mix_rows: List[Dict[str, Any]],
                       p_key: str,
                       action: str) -> List[Dict[str, Any]]:
    """Filter per_user_mix_top10 to one action and rank by count."""
    filt = [r for r in mix_rows if str(r.get("action")) == action]
    filt.sort(key=lambda r: -int(r.get("n") or 0))
    return [{p_key: r.get(p_key), "n": int(r.get("n") or 0)}
            for r in filt]


# ---------------------------------------------------------- chart builders

def save(fig, charts_dir: Path, name: str) -> None:
    out = charts_dir / f"{name}.png"
    fig.savefig(out, dpi=180, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  wrote {out.name}")


def chart_action_mix(d: Dict[str, Any], charts_dir: Path,
                     source: str, window: str) -> None:
    rows = d["queries"].get("by_action", {}).get("rows", []) or []
    if not rows:
        return
    action_key = "action" if any("action" in r for r in rows) else (
        "event.type" if any("event.type" in r for r in rows) else None)
    if action_key is None:
        return
    actions = [str(r.get(action_key)) for r in rows]
    counts = [int(r.get("n") or 0) for r in rows]
    total = sum(counts) or 1
    pct = [100 * c / total for c in counts]
    colors = [ACTION_COLORS.get(a, NAVY) for a in actions]

    fig, ax = plt.subplots(figsize=(8, 4.2))
    y = np.arange(len(actions))
    bars = ax.barh(y, counts, color=colors, edgecolor="white")
    ax.set_yticks(y, [a.upper() if a not in ("None", "null") else "(no action)"
                      for a in actions])
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(mtick.FuncFormatter(
        lambda x, _: f"{int(x):,}"))
    ax.set_xlabel(f"Events ({window})")
    ax.set_title(f"{source}: {action_key} mix",
                 loc="left", fontsize=14, fontweight="bold", pad=12)
    for bar, c, p in zip(bars, counts, pct):
        ax.text(bar.get_width() + total * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{c:,}  ({p:.1f}%)",
                va="center", ha="left", fontsize=10, color=INK)
    ax.set_xlim(0, max(counts) * 1.25)
    save(fig, charts_dir, "01_action_mix")


def chart_timeline(d: Dict[str, Any], charts_dir: Path,
                   source: str, window: str) -> None:
    tl = d["queries"].get("daily_by_action", {})
    rows = tl.get("rows", []) or []
    if not rows:
        return
    kind = tl.get("slice_kind", "day")
    dates = [r["date"] for r in rows]
    totals = np.array([int(r.get("matchCount") or 0) for r in rows])
    # collect all action keys seen across slices for consistent stacking
    all_actions = set()
    for r in rows:
        all_actions.update(r.get("by_action", {}).keys())
    # prefer canonical order then any extras
    order = [a for a in ACTION_ORDER if a in all_actions] + \
            [a for a in sorted(all_actions) if a not in ACTION_ORDER]

    # wider figure if many slices so labels don't collide
    fig_w = max(9, min(16, 0.55 * len(dates) + 5))
    fig, ax = plt.subplots(figsize=(fig_w, 4.5))
    bottom = np.zeros(len(dates))
    n_series = 0
    for action in order:
        vals = np.array([int(r["by_action"].get(action, 0)) for r in rows])
        if vals.sum() == 0:
            continue
        label = action if action not in ("None", "null") else "(no action)"
        color = ACTION_COLORS.get(action, NAVY)
        ax.bar(dates, vals, bottom=bottom, color=color, label=label,
               edgecolor="white", linewidth=0.8)
        bottom += vals
        n_series += 1
    # data labels on top: skip when density would cause overlap
    if totals.max() > 0 and len(dates) <= 12:
        for i, t in enumerate(totals):
            ax.text(i, t + totals.max() * 0.015, f"{t:,}",
                    ha="center", va="bottom", fontsize=9, color=INK)
        ax.set_ylim(0, totals.max() * 1.15)
    elif totals.max() > 0:
        ax.set_ylim(0, totals.max() * 1.05)
    ax.yaxis.set_major_formatter(mtick.FuncFormatter(
        lambda x, _: f"{int(x):,}"))
    # human-friendly name for the slice: day -> "daily", hour -> "hourly"
    kind_adj = {"day": "daily", "hour": "hourly",
                "week": "weekly", "month": "monthly"}.get(kind, kind)
    ax.set_ylabel(f"Events per {kind}")
    # title adapts to whether the action field is real
    has_action = bool(d.get("dims", {}).get("action"))
    title_suffix = "volume by action" if has_action else "volume"
    ax.set_title(f"{source}: {kind_adj} {title_suffix}",
                 loc="left", fontsize=14, fontweight="bold", pad=12)
    # legend only when >1 series; a one-bucket stack is noise
    if n_series > 1:
        ax.legend(loc="upper right", frameon=False, ncol=5, fontsize=9)
    # thin x-tick labels for dense hourly timelines (must hide before
    # autofmt_xdate to stick)
    if len(dates) > 14:
        step = max(1, int(len(dates) / 10))
        ticks = list(range(len(dates)))
        ax.set_xticks(ticks[::step])
        ax.set_xticklabels([dates[i] for i in ticks[::step]])
    fig.autofmt_xdate()
    save(fig, charts_dir, "02_daily_timeline")


def chart_top_principals(d: Dict[str, Any], charts_dir: Path,
                         source: str, window: str,
                         p_key: str,
                         by_user: List[Dict[str, Any]]) -> None:
    if not by_user:
        return
    rows = [r for r in by_user
            if r.get(p_key) not in (None, "", "null")][:12]
    if not rows:
        return
    users = [shorten(r.get(p_key)) for r in rows]
    counts = [int(r["n"]) for r in rows]

    fig, ax = plt.subplots(figsize=(9, 5.2))
    y = np.arange(len(users))
    bars = ax.barh(y, counts, color=NAVY, edgecolor="white")
    ax.set_yticks(y, users)
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(mtick.FuncFormatter(
        lambda x, _: f"{int(x):,}"))
    ax.set_xlabel(f"Events ({window})")
    pretty = p_key.replace("src.", "").replace(".", " ")
    ax.set_title(f"{source}: top {len(users)} by {pretty} activity",
                 loc="left", fontsize=14, fontweight="bold", pad=12)
    max_v = max(counts) or 1
    for bar, c in zip(bars, counts):
        ax.text(bar.get_width() + max_v * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{c:,}",
                va="center", ha="left", fontsize=9, color=INK)
    if max_v >= 10:
        ax.set_xscale("log")
        ax.set_xlim(1, max_v * 3)
    save(fig, charts_dir, "03_top_users_log")


def chart_by_action(d: Dict[str, Any], charts_dir: Path,
                    source: str, window: str, p_key: str,
                    action_rows: List[Dict[str, Any]],
                    name: str, title: str, color: str,
                    xlabel: str, use_log: bool = True) -> None:
    rows = [r for r in action_rows
            if r.get(p_key) not in (None, "", "null")][:12]
    if not rows:
        return
    users = [shorten(r.get(p_key)) for r in rows]
    counts = [int(r["n"]) for r in rows]

    fig, ax = plt.subplots(figsize=(9, 5.2))
    y = np.arange(len(users))
    bars = ax.barh(y, counts, color=color, edgecolor="white")
    ax.set_yticks(y, users)
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(mtick.FuncFormatter(
        lambda x, _: f"{int(x):,}"))
    ax.set_xlabel(xlabel)
    ax.set_title(f"{source}: {title}",
                 loc="left", fontsize=14, fontweight="bold", pad=12)
    max_v = max(counts) or 1
    for bar, c in zip(bars, counts):
        ax.text(bar.get_width() + max_v * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{c:,}", va="center", ha="left",
                fontsize=9, color=INK)
    if use_log and max_v >= 10:
        ax.set_xscale("log")
        ax.set_xlim(1, max_v * 3)
    else:
        ax.set_xlim(0, max_v * 1.3)
    save(fig, charts_dir, name)


def chart_user_action_mix(d: Dict[str, Any], charts_dir: Path,
                          source: str, window: str,
                          p_key: str,
                          mix_rows: List[Dict[str, Any]]) -> None:
    if not mix_rows:
        return
    per_user: Dict[str, Dict[str, int]] = {}
    for r in mix_rows:
        u = r.get(p_key)
        if u in (None, "", "null"):
            continue
        per_user.setdefault(str(u), {})[str(r.get("action"))] = int(
            r.get("n") or 0)
    if not per_user:
        return
    ranked = sorted(per_user.items(), key=lambda kv: -sum(kv[1].values()))[:8]
    users = [shorten(u) for u, _ in ranked]

    fig, ax = plt.subplots(figsize=(9, 4.8))
    y = np.arange(len(users))
    left = np.zeros(len(users))
    for action in ACTION_ORDER:
        vals = np.array([kv[1].get(action, 0) for kv in ranked])
        if vals.sum() == 0:
            continue
        label = action if action not in ("None", "null") else "(no action)"
        ax.barh(y, vals, left=left,
                color=ACTION_COLORS.get(action, NAVY),
                label=label, edgecolor="white", linewidth=0.8)
        left += vals
    ax.set_yticks(y, users)
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(mtick.FuncFormatter(
        lambda x, _: f"{int(x):,}"))
    ax.set_xlabel(f"Events ({window})")
    ax.set_title(f"{source}: action mix per top user",
                 loc="left", fontsize=14, fontweight="bold", pad=12)
    if left.max() >= 10:
        ax.set_xscale("log")
        ax.set_xlim(1, left.max() * 3)
    ax.legend(loc="lower right", frameon=False, ncol=4, fontsize=9)
    save(fig, charts_dir, "06_user_action_mix")


def chart_tenant_context(d: Dict[str, Any], charts_dir: Path,
                         source: str) -> None:
    ctx = d["queries"].get("tenant_sources_24h", {}).get("rows", []) or []
    if not ctx:
        return
    top = ctx[:12]
    idx = next((i for i, r in enumerate(ctx)
                if r.get("dataSource.name") == source), None)
    if idx is not None and idx >= len(top):
        top = top + [ctx[idx]]
    names = [str(r["dataSource.name"]) for r in top]
    counts = [int(r["ct"]) for r in top]
    rank = None
    for i, r in enumerate(ctx):
        if r.get("dataSource.name") == source:
            rank = i + 1
            break
    labels = [f"{n}  (#{rank})" if n == source else n for n in names]
    colors = [CORAL if n == source else NAVY for n in names]

    fig, ax = plt.subplots(figsize=(9, 5.2))
    y = np.arange(len(names))
    bars = ax.barh(y, counts, color=colors, edgecolor="white")
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(mtick.FuncFormatter(
        lambda x, _: f"{int(x):,}"))
    ax.set_xlabel("Events in last 24h (log scale)")
    ax.set_title(f"Tenant data-source ranking (where {source} sits)",
                 loc="left", fontsize=14, fontweight="bold", pad=12)
    for bar, c in zip(bars, counts):
        ax.text(bar.get_width() * 1.05,
                bar.get_y() + bar.get_height() / 2,
                f"{c:,}", va="center", ha="left",
                fontsize=9, color=INK)
    ax.set_xscale("log")
    save(fig, charts_dir, "07_tenant_context")


# ---------------------------------------------------------- orchestrator

def render_all(data_path: Path) -> Path:
    d = json.loads(data_path.read_text())
    source = d.get("source", "source")
    window = d.get("window_label", "window")
    dims = d.get("dims", {}) or {}

    charts_dir = data_path.parent / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)
    print(f"Rendering charts for '{source}' ({window}) -> {charts_dir}/")

    mix_rows = (d["queries"].get("per_user_mix_top10", {})
                .get("rows", []) or [])
    p_key = _principal_key(mix_rows)

    chart_action_mix(d, charts_dir, source, window)
    chart_timeline(d, charts_dir, source, window)

    if p_key:
        by_user = derive_by_user(mix_rows, p_key)
        chart_top_principals(d, charts_dir, source, window, p_key, by_user)

        if dims.get("action"):
            blocks = derive_action_rows(mix_rows, p_key, "block")
            bypasses = derive_action_rows(mix_rows, p_key, "bypass")
            if blocks:
                chart_by_action(
                    d, charts_dir, source, window, p_key, blocks,
                    "04_blocks_by_user",
                    "top users by BLOCK (highest-risk senders)",
                    CORAL, f"Block events ({window})")
            if bypasses:
                chart_by_action(
                    d, charts_dir, source, window, p_key, bypasses,
                    "05_bypass_by_user",
                    "top users by BYPASS (guardrail overriders)",
                    TEAL, f"Bypass events ({window})", use_log=False)
            chart_user_action_mix(d, charts_dir, source, window,
                                  p_key, mix_rows)

    chart_tenant_context(d, charts_dir, source)
    print(f"done, charts in {charts_dir}/")
    return charts_dir


def main():
    ap = argparse.ArgumentParser(description=(
        "Render CTO-report charts from a data.json produced by "
        "build_source_report.py. Source-agnostic: picks up source/"
        "window/dims/summary from the JSON."))
    ap.add_argument("--data", required=True,
                    help="Path to reports/<slug>_<window>/data.json")
    args = ap.parse_args()
    render_all(Path(args.data))


if __name__ == "__main__":
    main()
