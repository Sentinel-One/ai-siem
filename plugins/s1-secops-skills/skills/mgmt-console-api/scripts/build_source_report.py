"""
Parameterised "data-source activity" data collector.

Takes a `dataSource.name` and a window length, picks the right slicing
strategy based on the window, and writes a single JSON artefact with:

  - every aggregation needed for the 7 canonical charts
  - a client-side-sliced timeline (the PQ engine has no timebucket)
  - a tenant-context query (24h)
  - a data-driven `summary` block the rendering scripts consume
    (top principal, intervention rate, block/bypass %, tenant rank,
    etc.) so downstream commentary is derived from numbers, not
    hard-coded per source.

Rendering is deliberately kept OUT of this file. Charts, DOCX, and
PPTX each have their own entry points that read the JSON artefact
and produce their specific format. That separation makes iterating
on rendering cheap (re-use `--skip-collect` or just re-read the JSON).

Usage
-----
    python scripts/build_source_report.py --source "Example Source" --days 7
    python scripts/build_source_report.py --source "Zscaler Internet Access" --days 1
    python scripts/build_source_report.py --source "FortiGate" --days 30

Output
------
    ./reports/<slug>_<window>/data.json

Slicing strategy (see SKILL.md Step 3a/3b)
------------------------------------------
- <=1h    : 1 call; timeline is the single-call result
- 1h-24h  : single call for aggregates, hourly slicing for timeline
- 24h-7d  : single call for aggregates, daily slicing for timeline
- 7d-30d  : single call (longer deadline) for aggregates, daily slicing
- >30d    : reject and point at the two-JWT runner in the powerquery skill

All parallelism is capped at 3 workers to respect the per-user 3 rps
LRQ rate limit.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from s1_client import S1Client       # noqa: E402
from pq import run_pq, list_data_sources, PQError  # noqa: E402


SKILL_ROOT = _THIS_DIR.parent
REPORTS_DIR = SKILL_ROOT / "reports"
MAX_WORKERS = 3  # per-user 3 rps cap


def slugify(name: str) -> str:
    s = re.sub(r"[^0-9A-Za-z]+", "_", name.strip())
    return re.sub(r"_+", "_", s).strip("_") or "source"


# ----------------------------------------------------------------- strategy

def pick_strategy(hours: float) -> Dict[str, Any]:
    if hours <= 1:
        return {"window_label": f"{int(hours*60)}m" if hours < 1 else "1h",
                "slice_kind": "hour", "n_slices": max(1, int(hours)),
                "poll_deadline": 90}
    if hours <= 24:
        return {"window_label": "24h" if hours == 24 else f"{int(hours)}h",
                "slice_kind": "hour", "n_slices": int(hours),
                "poll_deadline": 150}
    days = hours / 24
    if days <= 7:
        return {"window_label": f"{int(days)}d",
                "slice_kind": "day", "n_slices": int(days),
                "poll_deadline": 240}
    if days <= 30:
        return {"window_label": f"{int(days)}d",
                "slice_kind": "day", "n_slices": int(days),
                "poll_deadline": 420}
    raise SystemExit(
        f"window > 30d ({days:.1f}d) requires the two-JWT runner. "
        "See `references/lrq-api.md` in the powerquery skill.")


# --------------------------------------------------------------- discovery

def verify_source_exists(client: S1Client, source: str) -> Dict[str, Any]:
    print(f"  Verifying source '{source}' exists on tenant...")
    sources = list_data_sources(client, hours=24, limit=200)
    match = next((s for s in sources
                  if s.get("dataSource.name") == source), None)
    if match is None:
        close = [s.get("dataSource.name") for s in sources
                 if source.lower() in str(s.get("dataSource.name", "")).lower()
                 or str(s.get("dataSource.name", "")).lower() in source.lower()]
        msg = (f"dataSource.name='{source}' not visible in the last 24h on "
               f"{client.base_url}.")
        if close:
            msg += f" Did you mean one of: {close}?"
        else:
            msg += (f" Top 10 present: "
                    f"{[s['dataSource.name'] for s in sources[:10]]}")
        raise SystemExit(msg)
    print(f"  OK: 24h rank implies {int(match.get('ct', 0)):,} events, "
          f"category={match.get('dataSource.category', '?')}")
    return match


def probe_dimensions(client: S1Client, source: str,
                     hours: float) -> Dict[str, bool]:
    """Decide which optional dimensions the source carries with useful
    cardinality. `user`, `action`, `src.ip.address`, `src.hostname`,
    `event.type`. Absent dimensions get skipped in the aggregation
    plan so the renderers know which charts to omit.

    Probes run in parallel (3-wide) over a 1h window. 1h is enough to
    decide presence, and a short window keeps the probe phase cheap.
    """
    BASE = f"dataSource.name = '{source}' (tag != 'logVolume' OR !(tag = *))"
    probes = {
        "user":  BASE + " | group n=count() by user | sort -n | limit 3",
        "action": BASE + " | group n=count() by action | sort -n | limit 6",
        "src_ip":  BASE + " | group n=count() by src.ip.address | sort -n | limit 3",
        "src_host": BASE + " | group n=count() by src.hostname | sort -n | limit 3",
        "event_type": BASE + " | group n=count() by event.type | sort -n | limit 6",
    }
    probe_hours = min(hours, 1)   # 1h plenty for presence detection
    probe_deadline = 60
    dims: Dict[str, bool] = {}

    def _probe(name: str, q: str):
        try:
            r = run_pq(client, q, hours=probe_hours,
                       poll_deadline_s=probe_deadline, poll_interval_s=1.5)
        except PQError as e:
            return name, False, f"error ({e})"
        useful = any(
            (row.get(list(row.keys())[0]) not in (None, "", "null"))
            for row in r["rows"]
        )
        return name, useful, f"{r['row_count']} rows"

    with cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(_probe, n, q): n for n, q in probes.items()}
        for fut in cf.as_completed(futs):
            name, useful, detail = fut.result()
            dims[name] = useful
            print(f"    dim probe {name}: "
                  f"{'present' if useful else 'empty'} ({detail})")
    return dims


# --------------------------------------------------------------- aggregation

def _run_q(client: S1Client, name: str, query: str, *,
           hours: Optional[float] = None,
           start_time: Optional[str] = None,
           end_time: Optional[str] = None,
           poll_deadline_s: float = 120) -> Dict[str, Any]:
    t0 = time.time()
    try:
        res = run_pq(
            client, query, hours=hours,
            start_time=start_time, end_time=end_time,
            poll_deadline_s=poll_deadline_s, poll_interval_s=1.5,
        )
        print(f"    [{name}] {res['row_count']} rows, "
              f"matchCount={res['matchCount']}, {time.time()-t0:.1f}s")
        return {
            "name": name, "query": query,
            "matchCount": res["matchCount"],
            "row_count": res["row_count"],
            "columns": res["columns"],
            "rows": res["rows"],
            "elapsed_s": res["elapsed_s"],
        }
    except PQError as e:
        print(f"    [{name}] FAILED: {e}")
        return {"name": name, "query": query, "error": str(e),
                "rows": [], "row_count": 0, "matchCount": 0}


def build_jobs(source: str, dims: Dict[str, bool]) -> List[Tuple[str, str]]:
    """Aggregate plan based on the dimensions the source carries.

    Deliberately minimal: we only ask the tenant for what can't be
    derived. `per_user_mix_top10` with a generous row cap subsumes
    by_user / by_user_blocks / by_user_bypass -- the renderer
    derives those by filtering and summing.
    """
    BASE = f"dataSource.name = '{source}' (tag != 'logVolume' OR !(tag = *))"
    jobs: List[Tuple[str, str]] = []

    if dims.get("action"):
        jobs.append(("by_action",
                     BASE + " | group n=count() by action | sort -n"))
    elif dims.get("event_type"):
        jobs.append(("by_action",
                     BASE + " | group n=count() by event.type | sort -n "
                            "| limit 12"))
    else:
        jobs.append(("by_action",
                     BASE + " | group n=count() | sort -n"))

    if dims.get("user") and dims.get("action"):
        jobs.append(("per_user_mix_top10",
                     BASE + " | group n=count() by user, action "
                            "| sort -n | limit 200"))
    elif dims.get("user"):
        jobs.append(("per_user_mix_top10",
                     BASE + " | group n=count() by user "
                            "| sort -n | limit 25"))
    elif dims.get("src_host"):
        jobs.append(("per_user_mix_top10",
                     BASE + " | group n=count() by src.hostname "
                            "| sort -n | limit 25"))
    elif dims.get("src_ip"):
        jobs.append(("per_user_mix_top10",
                     BASE + " | group n=count() by src.ip.address "
                            "| sort -n | limit 25"))

    return jobs


def _timeline_slices(strategy: Dict[str, Any], end: datetime
                     ) -> List[Tuple[str, datetime, datetime]]:
    """Build the list of (label, start, end) slices for the timeline."""
    kind = strategy["slice_kind"]
    n = strategy["n_slices"]
    if kind == "day":
        boundary = end.replace(hour=0, minute=0, second=0, microsecond=0)
        raw = [(boundary - timedelta(days=i + 1),
                boundary - timedelta(days=i)) for i in range(n)]
    else:
        boundary = end.replace(minute=0, second=0, microsecond=0)
        raw = [(boundary - timedelta(hours=i + 1),
                boundary - timedelta(hours=i)) for i in range(n)]
    raw = list(reversed(raw))
    fmt = "%Y-%m-%d" if kind == "day" else "%Y-%m-%d %H:00"
    return [(s.strftime(fmt), s, e) for s, e in raw]


def _run_slice(client: S1Client, base: str, sec_dim: Optional[str],
               label: str, s: datetime, e: datetime,
               poll_deadline_s: float) -> Dict[str, Any]:
    iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
    q_sec = (base + f" | group n=count() by {sec_dim} | sort -n"
             if sec_dim else base + " | group n=count()")
    try:
        res = run_pq(client, q_sec,
                     start_time=iso(s), end_time=iso(e),
                     poll_deadline_s=poll_deadline_s,
                     poll_interval_s=1.5)
    except PQError as exc:
        return {"date": label, "start": iso(s), "end": iso(e),
                "matchCount": 0, "by_action": {}, "error": str(exc)}
    by_action: Dict[str, int] = {}
    for row in res["rows"]:
        key = row.get(sec_dim) if sec_dim else "total"
        by_action[str(key)] = int(row.get("n") or 0)
    if not sec_dim:
        by_action["total"] = int(res.get("matchCount") or 0)
    return {"date": label, "start": iso(s), "end": iso(e),
            "matchCount": res["matchCount"], "by_action": by_action}


# ----------------------------------------------------------- data-driven summary

def summarise(d: Dict[str, Any]) -> Dict[str, Any]:
    """Derive the numbers downstream commentary uses. Pure function
    over the JSON artefact so renderers don't re-compute."""
    rows = d["queries"].get("by_action", {}).get("rows", []) or []
    prim_key: Optional[str] = None
    for r in rows:
        for k in ("action", "event.type"):
            if k in r:
                prim_key = k
                break
        if prim_key:
            break

    total = sum(int(r.get("n") or 0) for r in rows)
    by: Dict[str, int] = {}
    if prim_key:
        for r in rows:
            by[str(r.get(prim_key))] = int(r.get("n") or 0)

    block_n = int(by.get("block", 0))
    modify_n = int(by.get("modify", 0))
    bypass_n = int(by.get("bypass", 0))
    log_n = int(by.get("log", 0))

    # Derive per-principal totals from per_user_mix_top10. The main
    # collector now runs a single `| group by user, action` (or by
    # hostname / src.ip if user is absent) and the renderer rolls it up.
    mix_rows = d["queries"].get("per_user_mix_top10", {}).get("rows", []) or []
    p_key: Optional[str] = None
    for r in mix_rows:
        for k in ("user", "src.hostname", "src.ip.address"):
            if k in r:
                p_key = k
                break
        if p_key:
            break
    principal_totals: Dict[str, int] = {}
    if p_key:
        for r in mix_rows:
            who = r.get(p_key)
            if who in (None, "", "null"):
                continue
            principal_totals[str(who)] = (
                principal_totals.get(str(who), 0) + int(r.get("n") or 0))
    users_ranked = sorted(principal_totals.items(), key=lambda kv: -kv[1])
    top_user = ({p_key: users_ranked[0][0], "n": users_ranked[0][1]}
                if users_ranked else None)
    top_share = (100.0 * int(top_user["n"]) / total
                 if top_user and total else 0.0)

    ctx = d["queries"].get("tenant_sources_24h", {}).get("rows", []) or []
    rank = next((i + 1 for i, r in enumerate(ctx)
                 if r.get("dataSource.name") == d["source"]), None)

    return {
        "total": total,
        "prim_key": prim_key,
        "by_action": by,
        "block": block_n,
        "modify": modify_n,
        "bypass": bypass_n,
        "log": log_n,
        "intervention_pct": (100.0 * (block_n + modify_n) / total)
                            if total else 0.0,
        "block_pct": (100.0 * block_n / total) if total else 0.0,
        "bypass_pct": (100.0 * bypass_n / total) if total else 0.0,
        "principal_count": len(users_ranked),
        "top_principal_key": p_key,
        "top_user": top_user,
        "top_share": top_share,
        "rank_24h": rank,
    }


# ----------------------------------------------------------------- orchestrator

def collect_all(client: S1Client, source: str, days: float,
                outdir: Path) -> Dict[str, Any]:
    hours = days * 24
    strategy = pick_strategy(hours)
    print(f"\n=== collect ===")
    print(f"  source      : {source}")
    print(f"  window      : {days} days ({hours:.1f} h)")
    print(f"  strategy    : {strategy['slice_kind']}-slicing, "
          f"n={strategy['n_slices']}, "
          f"poll_deadline={strategy['poll_deadline']}s")

    tenant_row = verify_source_exists(client, source)
    dims = probe_dimensions(client, source, hours)

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(hours=hours)

    out: Dict[str, Any] = {
        "source": source,
        "slug": slugify(source),
        "days": days,
        "window_label": strategy["window_label"],
        "collected_at": end.isoformat(),
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "base_filter": f"dataSource.name = '{source}' "
                       "(tag != 'logVolume' OR !(tag = *))",
        "dims": dims,
        "strategy": strategy,
        "tenant_24h_row": tenant_row,
        "queries": {},
    }

    # Phase 2: aggregates + tenant_context + timeline slices, all
    # packed into ONE parallel pool. The two 7d aggregates dominate
    # wall time (~120s each on ~37k events, tenant-side scan). The
    # tenant context query (18s) and the 7 short timeline slices
    # (~5-15s each) fill the third pool slot while the aggregates run,
    # so they're effectively free. Pool cap = MAX_WORKERS per the 3 rps
    # user-token cap.
    BASE = f"dataSource.name = '{source}' (tag != 'logVolume' OR !(tag = *))"
    sec_dim = "action" if dims.get("action") else (
        "event.type" if dims.get("event_type") else None)

    jobs = build_jobs(source, dims)
    slices = _timeline_slices(strategy, end)
    slice_deadline = max(60, int(strategy["poll_deadline"] / 2))

    print(f"\n  phase 2: {len(jobs)} aggregates + 1 context + "
          f"{len(slices)} timeline slices, all parallel "
          f"(max_workers={MAX_WORKERS})...")

    def _agg_job(name: str, q: str):
        return ("agg", name, _run_q(client, name, q,
                                     hours=hours,
                                     poll_deadline_s=strategy["poll_deadline"]))

    def _context_job():
        return ("ctx", "tenant_sources_24h", _run_q(
            client, "tenant_sources_24h",
            "dataSource.name = * | group ct = count() "
            "by dataSource.name | sort -ct | limit 30",
            hours=24, poll_deadline_s=150,
        ))

    def _slice_job(label: str, s: datetime, e: datetime):
        return ("slice", label,
                _run_slice(client, BASE, sec_dim, label, s, e,
                           poll_deadline_s=slice_deadline))

    timeline_rows: List[Dict[str, Any]] = []
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = []
        # Submit heavy aggregates FIRST so they claim slots 1 and 2.
        # The FIFO pool will then feed the short jobs into slot 3.
        for name, q in jobs:
            futs.append(ex.submit(_agg_job, name, q))
        futs.append(ex.submit(_context_job))
        for label, s, e in slices:
            futs.append(ex.submit(_slice_job, label, s, e))
        for fut in cf.as_completed(futs):
            kind, name, res = fut.result()
            if kind == "slice":
                timeline_rows.append(res)
            else:
                out["queries"][name] = res
    timeline_rows.sort(key=lambda x: x["date"])
    out["queries"]["daily_by_action"] = {
        "name": ("daily_by_action" if strategy["slice_kind"] == "day"
                 else "hourly_by_action"),
        "method": f"client-side-{strategy['slice_kind']}-slicing",
        "slice_kind": strategy["slice_kind"],
        "n_slices": strategy["n_slices"],
        "rows": timeline_rows,
    }
    print(f"    phase 2 done in {time.time()-t0:.1f}s")

    out["summary"] = summarise(out)

    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "data.json"
    json_path.write_text(json.dumps(out, indent=2, default=str))
    print(f"\n  wrote {json_path} ({json_path.stat().st_size:,} bytes)")
    s = out["summary"]
    print(f"  summary: total={s['total']:,}  "
          f"intervention={s['intervention_pct']:.1f}%  "
          f"principals={s['principal_count']}  "
          f"top_share={s['top_share']:.1f}%  rank24h={s['rank_24h']}")
    return out


def main():
    ap = argparse.ArgumentParser(
        description=("Collect aggregated SDL data for a single "
                     "dataSource.name over a given window. Produces a "
                     "single JSON artefact with data-driven summary "
                     "stats. Chart / DOCX / PPTX rendering happens in "
                     "separate scripts that read this artefact."))
    ap.add_argument("--source", required=True,
                    help="Exact dataSource.name on the tenant.")
    ap.add_argument("--days", type=float, default=7.0,
                    help="Window length in days. Default 7. "
                         "Supports 1, 7, 30; <=24h also works.")
    ap.add_argument("--output-dir", default=None,
                    help="Override output directory. "
                         "Default ./reports/<slug>_<window>/")
    args = ap.parse_args()

    client = S1Client()
    slug = slugify(args.source)
    strat = pick_strategy(args.days * 24)
    outdir = Path(args.output_dir) if args.output_dir else (
        REPORTS_DIR / f"{slug}_{strat['window_label']}")
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"Tenant: {client.base_url}")
    print(f"Output: {outdir}")
    collect_all(client, args.source, args.days, outdir)
    print(f"\nDONE. data.json ready at {outdir}/data.json")


if __name__ == "__main__":
    main()
