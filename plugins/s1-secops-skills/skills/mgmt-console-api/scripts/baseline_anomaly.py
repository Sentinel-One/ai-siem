"""
Source-agnostic behavioral baseline + z-score anomaly detection.

Composes ``inspect_source.discover_schema`` + ``pick_keys`` + ``pq.run_pq``
to baseline ANY ``dataSource.name`` ingested into SDL, EDR, identity,
network, cloud, email, SaaS, custom, without hardcoding principal /
action fields per source.

Pipeline:

  1. Schema discovery picks ``prim_key`` (principal: user / host / IP / role)
     and ``action_key`` (action / event.type / activity_name) from what the
     source actually carries. Caller can override either.
  2. N daily count slices (default 30) over the baseline window via LRQ,
     run 3 concurrent (per-user 3 rps cap). Daily slicing keeps each call
     under the LRQ per-call deadline.
  3. One 24h live slice.
  4. Client-side merge with two baseline strategies:
       - ``pooled``, all daily samples in one bucket per (action, principal)
       - ``dow``   , separate bucket per (action, principal, day_of_week)
                      eliminates the weekday/weekend false-positive
  5. Three anomaly classes surfaced:
       - matched z-score deviations (SPIKE / DROP)
       - silent pairs (baseline → live=0)
       - new-behavior pairs (live with no baseline)

State is checkpointed to disk per source so the script is fully
resumable across short shell budgets, re-invoke until ``all phases
complete`` is reported.

Usage:

  python scripts/baseline_anomaly.py --source "Okta"
  python scripts/baseline_anomaly.py --source "FortiGate" --days 30 --stratify dow
  python scripts/baseline_anomaly.py --source "<name>" --principal src.ip.address --action unmapped.action
  python scripts/baseline_anomaly.py --source "<name>" reset

PQ building blocks the pipeline wraps live in the ``sentinelone-powerquery``
skill at ``examples/behavioral-baselines.md``. Read that file when authoring
the equivalent as a STAR / PowerQuery Alert detection rule body.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from s1_client import S1Client  # noqa: E402
from pq import run_pq  # noqa: E402
from inspect_source import discover_schema, pick_keys  # noqa: E402


DOW_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _state_dir() -> Path:
    """State directory. Override with BASELINE_ANOMALY_DIR for custom location."""
    d = Path(os.environ.get("BASELINE_ANOMALY_DIR", str(HERE.parent / "baselines")))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _state_path(source: str) -> Path:
    return _state_dir() / f"baseline_anomaly_{_slug(source)}_state.json"


def _result_path(source: str) -> Path:
    return _state_dir() / f"baseline_anomaly_{_slug(source)}_result.json"


def _load_state(source: str) -> Optional[Dict[str, Any]]:
    p = _state_path(source)
    if not p.exists():
        return None
    return json.loads(p.read_text())


def _save_state(state: Dict[str, Any]) -> None:
    p = _state_path(state["source"])
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, default=str))
    tmp.replace(p)


# ----------------------------------------------------------------------
# Query construction
# ----------------------------------------------------------------------

# Server-side row cap on the per-day count PQ. When a phase returns exactly
# this many rows the result was truncated by the cap and low-volume
# (action, principal) pairs may be missing from that slice.
COUNT_PQ_ROW_LIMIT = 5000


def _build_count_pq(source: str, principal: str, action: str, count_alias: str) -> str:
    """Per-day count PQ: produces (action, principal, count_alias) rows over 1 day."""
    # PQ string literals escape a single quote by doubling it; unescaped
    # quotes in a source name would break the filter (same pattern as
    # inspect_source.py).
    safe = source.replace("'", "''")
    return (
        f"dataSource.name = '{safe}' (tag != 'logVolume' OR !(tag = *))\n"
        f"| filter {principal} = * AND {action} = *\n"
        f"| group {count_alias} = count() by action_v = {action}, principal_v = {principal}\n"
        "| sort -" + count_alias + "\n"
        f"| limit {COUNT_PQ_ROW_LIMIT}"
    )


# ----------------------------------------------------------------------
# Initialization
# ----------------------------------------------------------------------

def _init_state(
    source: str, days: int, principal: str, action: str, stratify: str
) -> Dict[str, Any]:
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    phases: List[Dict[str, Any]] = []
    for i in range(1, days + 1):
        start = today - timedelta(days=i + 1)
        end = today - timedelta(days=i)
        phases.append({
            "label": f"baseline_d-{i}",
            "kind": "baseline",
            "start": _iso(start),
            "end": _iso(end),
            "dow": start.weekday(),
        })
    live_start = today - timedelta(days=1)
    live_end = today
    phases.append({
        "label": "live",
        "kind": "live",
        "start": _iso(live_start),
        "end": _iso(live_end),
        "dow": live_start.weekday(),
    })
    return {
        "source": source,
        "principal": principal,
        "action": action,
        "stratify": stratify,
        "days": days,
        "today": _iso(today),
        "phases": phases,
        "phase_results": {},
        "completed": [],
    }


# ----------------------------------------------------------------------
# Phase execution
# ----------------------------------------------------------------------

def _normalize_lrq(resp: Dict[str, Any]) -> Dict[str, Any]:
    data = resp.get("data") or resp
    cols = data.get("columns") or []
    names = [c.get("name") if isinstance(c, dict) else str(c) for c in cols]
    values = data.get("values") or []
    rows = [dict(zip(names, v)) for v in values]
    return {
        "rows": rows,
        "columns": names,
        "matchCount": data.get("matchCount"),
        "row_count": len(rows),
    }


def _run_phase(client: Any, source: str, principal: str, action: str,
               phase: Dict[str, Any], deadline_s: float = 38.0) -> Dict[str, Any]:
    count_alias = "live_count" if phase["kind"] == "live" else "day_count"
    pq_text = _build_count_pq(source, principal, action, count_alias)
    raw = run_pq(
        client, pq_text,
        start_time=phase["start"], end_time=phase["end"],
        poll_deadline_s=deadline_s,
    )
    return _normalize_lrq(raw)


# ----------------------------------------------------------------------
# Merge / report
# ----------------------------------------------------------------------

def _merge_pooled(state: Dict[str, Any]) -> Dict[str, Any]:
    """Pooled baseline: all daily samples in one bucket per (action, principal).

    Inactive sampled days are zero-padded to the number of baseline phases,
    mirroring ``_merge_dow``. Without the padding a pair active 2 of 30 days
    at 100/day baselines at mean=100 instead of ~6.67, so its true daily rate
    is overstated and a normal active day never registers as a SPIKE.
    """
    per_pair_counts = defaultdict(list)
    n_sampled = 0
    for label, res in state["phase_results"].items():
        if not label.startswith("baseline_"):
            continue
        n_sampled += 1
        for r in res["rows"]:
            key = (r.get("action_v"), r.get("principal_v"))
            # LRQ can return null counts; coerce at ingestion so stats and
            # sorts never see None.
            per_pair_counts[key].append(int(r.get("day_count") or 0))

    baseline = {}
    for key, counts in per_pair_counts.items():
        n_active = len(counts)
        full = counts + [0] * max(0, n_sampled - n_active)
        if len(full) < 2:
            continue
        sd = statistics.stdev(full)
        # Flat pairs (identical count on every sampled day, sd == 0 after
        # padding) are KEPT with an is_constant marker, not dropped. A perfectly
        # regular pair is the strongest baseline there is: any deviation from
        # the constant is anomalous. _detect_pooled treats is_constant pairs as
        # "any change from moving_average = anomaly" instead of dividing by zero.
        # (2026-07-29: previously these were dropped, so a spike on a service
        # account or scheduled job was misclassified as new_behavior and a
        # silence was never flagged.)
        baseline[key] = {
            # n_days kept for compatibility; it now equals n_sampled (the
            # number of baseline phases), not the number of active days.
            "n_days": n_sampled,
            "n_active": n_active,
            "n_sampled": n_sampled,
            "moving_average": statistics.mean(full),
            "stddev_val": sd,
            "is_constant": sd <= 0,
        }
    return baseline


def _merge_dow(state: Dict[str, Any]) -> Tuple[Dict[Tuple[str, str, int], Dict[str, Any]], Dict[int, int]]:
    """Day-of-week-stratified baseline: bucket per (action, principal, dow)."""
    per_pair_dow = defaultdict(lambda: defaultdict(list))
    sampled_dows = defaultdict(int)

    for label, res in state["phase_results"].items():
        if not label.startswith("baseline_"):
            continue
        phase = next((p for p in state["phases"] if p["label"] == label), None)
        if not phase:
            continue
        dow = phase["dow"]
        sampled_dows[dow] += 1
        for r in res["rows"]:
            key = (r.get("action_v"), r.get("principal_v"))
            # LRQ can return null counts; coerce at ingestion.
            per_pair_dow[key][dow].append(int(r.get("day_count") or 0))

    # Pad inactive sampled days with zeros so the DoW baseline reflects the
    # true rate (active 4-of-4 Sundays vs 2-of-4 are not the same).
    baseline_dow: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
    for key, by_dow in per_pair_dow.items():
        for dow, counts in by_dow.items():
            n_active = len(counts)
            n_sampled = sampled_dows[dow]
            # Defensive: a dow with zero sampled phases carries no baseline
            # signal; skip instead of feeding empty/zero-length stats.
            if n_sampled <= 0:
                continue
            full = counts + [0] * max(0, n_sampled - n_active)
            if len(full) < 2:
                continue
            sd = statistics.stdev(full)
            # Keep flat (sd == 0) pairs with an is_constant marker instead of
            # dropping them; see _merge_pooled for the rationale.
            baseline_dow[(key[0], key[1], dow)] = {
                "n_active": n_active, "n_sampled": n_sampled,
                "moving_average": statistics.mean(full),
                "stddev_val": sd,
                "is_constant": sd <= 0,
            }
    return baseline_dow, dict(sampled_dows)


# Sentinel z for a deviation from a perfectly constant (sd==0) baseline. A real
# z is undefined there (divide by zero); this flags "changed from a constant" as
# a strong anomaly while keeping the value finite and sortable.
CONSTANT_DEVIATION_Z = 999.0


def _score_z(live_c: float, b: Dict[str, Any]) -> float:
    """z-score that tolerates a constant (sd==0) baseline.

    Constant baseline: 0 if the live value equals the constant, else a signed
    sentinel. Normal baseline: the usual (live - mean) / sd.
    """
    if b.get("is_constant") or b["stddev_val"] <= 0:
        if live_c == b["moving_average"]:
            return 0.0
        return CONSTANT_DEVIATION_Z if live_c > b["moving_average"] else -CONSTANT_DEVIATION_Z
    return (live_c - b["moving_average"]) / b["stddev_val"]


def _detect_pooled(state: Dict[str, Any], baseline: Dict, z_threshold: float) -> Dict[str, Any]:
    live = state["phase_results"].get("live", {"rows": []})["rows"]
    # LRQ can return null counts; coerce at ingestion.
    live_lookup = {(r.get("action_v"), r.get("principal_v")): int(r.get("live_count") or 0)
                   for r in live}

    matched, silent, new_b = [], [], []
    for r in live:
        key = (r.get("action_v"), r.get("principal_v"))
        c = live_lookup[key]
        if key not in baseline:
            new_b.append({"action": key[0], "principal": key[1], "live_count": c})
            continue
        b = baseline[key]
        z = _score_z(c, b)
        rec = {
            "action": key[0], "principal": key[1], "live_count": c,
            "baseline_avg": round(b["moving_average"], 2),
            "baseline_stddev": round(b["stddev_val"], 2),
            "baseline_constant": bool(b.get("is_constant")),
            "n_baseline_days": b["n_days"],
            "n_active_days": b.get("n_active", b["n_days"]),
            "n_sampled_days": b.get("n_sampled", b["n_days"]),
            "z_score": round(z, 4),
            "direction": "SPIKE" if z > 0 else "DROP",
        }
        if abs(z) >= z_threshold:
            matched.append(rec)

    for key, b in baseline.items():
        if key in live_lookup:
            continue
        z = _score_z(0, b)
        if abs(z) >= z_threshold:
            silent.append({
                "action": key[0], "principal": key[1], "live_count": 0,
                "baseline_avg": round(b["moving_average"], 2),
                "baseline_stddev": round(b["stddev_val"], 2),
                "baseline_constant": bool(b.get("is_constant")),
                "n_baseline_days": b["n_days"],
                "n_active_days": b.get("n_active", b["n_days"]),
                "n_sampled_days": b.get("n_sampled", b["n_days"]),
                "z_score": round(z, 4),
                "direction": "SILENT",
            })
    matched.sort(key=lambda r: abs(r["z_score"]), reverse=True)
    silent.sort(key=lambda r: r["z_score"])
    new_b.sort(key=lambda r: r["live_count"], reverse=True)
    return {"matched": matched, "silent": silent, "new_behavior": new_b}


def _detect_dow(state: Dict[str, Any], baseline_dow: Dict, sampled_dows: Dict[int, int],
                z_threshold: float) -> Dict[str, Any]:
    live_phase = next(p for p in state["phases"] if p["label"] == "live")
    live_dow = live_phase["dow"]
    # Guard the missing-live-phase case (mirrors _detect_pooled), and coerce
    # null counts at ingestion.
    live_rows = state["phase_results"].get("live", {"rows": []})["rows"]
    live_lookup = {(r.get("action_v"), r.get("principal_v")): int(r.get("live_count") or 0)
                   for r in live_rows}

    pair_keys = set()
    for k in baseline_dow.keys():
        pair_keys.add((k[0], k[1]))
    for k in live_lookup.keys():
        pair_keys.add(k)

    matched, silent, new_b = [], [], []
    for action_v, principal_v in pair_keys:
        dow_key = (action_v, principal_v, live_dow)
        live_c = live_lookup.get((action_v, principal_v), 0)

        if dow_key not in baseline_dow:
            # Pair has no baseline on this DoW: either always silent here, or first-time
            if live_c > 0:
                new_b.append({"action": action_v, "principal": principal_v, "live_count": live_c})
            continue
        b = baseline_dow[dow_key]
        z = _score_z(live_c, b)
        rec = {
            "action": action_v, "principal": principal_v, "live_count": live_c,
            "baseline_avg": round(b["moving_average"], 2),
            "baseline_stddev": round(b["stddev_val"], 2),
            "baseline_constant": bool(b.get("is_constant")),
            "n_active_on_this_dow": b["n_active"],
            "n_sampled_on_this_dow": b["n_sampled"],
            "z_score": round(z, 4),
            "direction": "SPIKE" if z > 0 else ("DROP" if live_c > 0 else "SILENT"),
            "live_dow": DOW_NAMES[live_dow],
        }
        if abs(z) < z_threshold:
            continue
        if live_c == 0 and b["moving_average"] > 0:
            silent.append(rec)
        elif live_c > 0:
            matched.append(rec)

    matched.sort(key=lambda r: abs(r["z_score"]), reverse=True)
    silent.sort(key=lambda r: r["z_score"])
    new_b.sort(key=lambda r: r["live_count"], reverse=True)
    return {"matched": matched, "silent": silent, "new_behavior": new_b,
            "live_dow": DOW_NAMES[live_dow], "sampled_dows": sampled_dows}


def _print_report(state: Dict[str, Any], detection: Dict[str, Any], z_threshold: float) -> None:
    src = state["source"]
    bar = "=" * 100
    print(f"\n{bar}")
    print(f"BASELINE + ANOMALY DETECTION: {src}")
    print(f"  principal={state['principal']}  action={state['action']}")
    print(f"  baseline window={state['days']}d  strategy={state['stratify']}  z_threshold={z_threshold}")
    if state["stratify"] == "dow":
        print(f"  live day-of-week={detection.get('live_dow')}  sampled_dow_counts={detection.get('sampled_dows')}")
    print(bar)

    matched = detection["matched"]
    silent = detection["silent"]
    new_b = detection["new_behavior"]

    print(f"Matched anomalies (|z| >= {z_threshold}):  {len(matched)}")
    print(f"Silent pairs (baseline -> live=0):          {len(silent)}")
    print(f"New-behavior pairs (no baseline):           {len(new_b)}")

    def _show(rows: List[Dict[str, Any]], label: str, n: int = 15) -> None:
        if not rows:
            return
        print(f"\nTop {min(n, len(rows))} {label}:")
        for r in rows[:n]:
            principal = (str(r.get("principal", "")))[:30]
            action = (str(r.get("action", "")))[:42]
            live = r.get("live_count", 0)
            avg = r.get("baseline_avg", "")
            sd = r.get("baseline_stddev", "")
            z = r.get("z_score", "")
            d = r.get("direction", "")
            avg_str = f"{avg:>7.1f}" if isinstance(avg, (int, float)) else str(avg).rjust(7)
            sd_str = f"{sd:>6.1f}" if isinstance(sd, (int, float)) else str(sd).rjust(6)
            z_str = f"{z:>+6.2f}" if isinstance(z, (int, float)) else str(z).rjust(6)
            print(f"    {principal:<32} {action:<44} live={live:>5}  baseline={avg_str}±{sd_str}  z={z_str} {d}")

    _show(matched, "matched anomalies")
    _show(silent, "silent pairs")
    if new_b:
        print(f"\nTop 10 NEW-behavior pairs (no baseline on this {('DoW' if state['stratify']=='dow' else 'window')}):")
        for r in new_b[:10]:
            principal = (str(r.get("principal", "")))[:30]
            action = (str(r.get("action", "")))[:48]
            print(f"    {principal:<32} {action:<50}  live={r['live_count']}")


# ----------------------------------------------------------------------
# Top-level
# ----------------------------------------------------------------------

def setup(client: Any, source: str, days: int, principal: Optional[str],
          action: Optional[str], stratify: str) -> Dict[str, Any]:
    """Discover schema (if needed), pick keys, init state."""
    if not principal or not action:
        print(f"[{source}] discovering schema (this may take 5-30s on cold sources)...", flush=True)
        schema = discover_schema(
            client, source, hours=24, sample=150,
            extra_filter="(tag != 'logVolume' OR !(tag = *))",
            backend="auto", escalate=True,
        )
        auto_principal, auto_action = pick_keys(schema)
        principal = principal or auto_principal
        action = action or auto_action
    if not principal or not action:
        raise RuntimeError(
            f"could not determine principal/action for {source}, pass --principal and --action"
        )
    print(f"[{source}] principal={principal}  action={action}", flush=True)
    return _init_state(source, days, principal, action, stratify)


def step(client: Any, state: Dict[str, Any], max_workers: int = 3) -> int:
    """Run up to max_workers pending phases in parallel. Returns number of phases run.

    Stays under the per-user 3 rps cap with default max_workers=3. State is
    persisted after the batch.
    """
    pending = [p for p in state["phases"] if p["label"] not in state["completed"]]
    if not pending:
        return 0
    todo = pending[:max_workers]
    print(f"[{state['source']}] running {[p['label'] for p in todo]} (remaining after: {len(pending) - len(todo)})", flush=True)
    return _step_serial(client, state, todo)


def _step_serial(client: Any, state: Dict[str, Any], todo: List[Dict[str, Any]]) -> int:
    with cf.ThreadPoolExecutor(max_workers=min(3, len(todo))) as ex:
        futs = {
            ex.submit(_run_phase, client, state["source"],
                      state["principal"], state["action"], p): p
            for p in todo
        }
        for fut in cf.as_completed(futs):
            p = futs[fut]
            try:
                res = fut.result()
                # row_count == COUNT_PQ_ROW_LIMIT means the | limit cap
                # truncated the result: low-volume pairs may be missing.
                limit_hit = res["row_count"] >= COUNT_PQ_ROW_LIMIT
                state["phase_results"][p["label"]] = {"rows": res["rows"], "matchCount": res["matchCount"],
                                                      "limit_hit": limit_hit}
                state["completed"].append(p["label"])
                print(f"  ✓ {p['label']} {p['start']}→{p['end']} matchCount={res['matchCount']} rows={res['row_count']}", flush=True)
                if limit_hit:
                    print(f"  ⚠ {p['label']}: row count hit the | limit {COUNT_PQ_ROW_LIMIT} cap; "
                          "low-volume (action, principal) pairs may be missing from this slice", flush=True)
            except Exception as e:
                print(f"  ✗ {p['label']}: {e}", flush=True)
    _save_state(state)
    return len(todo)


def report(state: Dict[str, Any], z_threshold: float = 2.0) -> Dict[str, Any]:
    if state["stratify"] == "pooled":
        baseline = _merge_pooled(state)
        detection = _detect_pooled(state, baseline, z_threshold)
        detection["baseline_pair_count"] = len(baseline)
    else:
        baseline_dow, sampled_dows = _merge_dow(state)
        detection = _detect_dow(state, baseline_dow, sampled_dows, z_threshold)
        detection["baseline_pair_count"] = len({(k[0], k[1]) for k in baseline_dow.keys()})
        detection["baseline_dow_cells"] = len(baseline_dow)
    # Surface phases whose per-day count PQ hit the | limit row cap: their
    # counts are truncated and low-volume pairs may be missing entirely.
    capped = sorted(label for label, res in state["phase_results"].items()
                    if res.get("limit_hit"))
    detection["limit_capped_phases"] = capped
    _print_report(state, detection, z_threshold)
    if capped:
        print(f"\nWARNING: {len(capped)} phase(s) hit the | limit {COUNT_PQ_ROW_LIMIT} row cap "
              f"({', '.join(capped)}). Low-volume (action, principal) pairs may be missing "
              "from the baseline/live counts, so silent/new-behavior verdicts for rare pairs "
              "are unreliable in those slices.")

    out = {
        "source": state["source"],
        "principal": state["principal"],
        "action": state["action"],
        "stratify": state["stratify"],
        "days": state["days"],
        "z_threshold": z_threshold,
        **detection,
    }
    _result_path(state["source"]).write_text(json.dumps(out, indent=2, default=str))
    print(f"\nResults → {_result_path(state['source'])}")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="Source-agnostic baseline + anomaly detection")
    p.add_argument("--source", required=False, help="dataSource.name to baseline")
    p.add_argument("--days", type=int, default=30, help="Baseline window in days (default 30)")
    p.add_argument("--principal", default=None, help="Override auto-picked principal field")
    p.add_argument("--action", default=None, help="Override auto-picked action field")
    p.add_argument("--stratify", choices=("pooled", "dow"), default="dow",
                   help="Baseline strategy: pooled (one bucket) or dow (one bucket per day-of-week)")
    p.add_argument("--z", type=float, default=2.0, help="Z-score threshold for anomaly (default 2.0)")
    p.add_argument("--max-workers", type=int, default=3,
                   help="Parallel LRQ slices per invocation (default 3, per-user 3 rps cap)")
    p.add_argument("command", nargs="?", default="run",
                   help="run | reset | report (default run)")
    args = p.parse_args()

    if not args.source:
        p.error("--source is required")
    src = args.source

    if args.command == "reset":
        for path in (_state_path(src), _result_path(src)):
            if path.exists():
                path.unlink()
        print(f"reset: {src}")
        return 0

    client = S1Client()
    state = _load_state(src)
    if state is None:
        state = setup(client, src, args.days, args.principal, args.action, args.stratify)
        _save_state(state)
    elif args.command == "run":
        # If user changed flags, warn but use saved state
        if state.get("days") != args.days or state.get("stratify") != args.stratify:
            print(f"[{src}] NOTE: saved state uses days={state['days']} stratify={state['stratify']} (passed flags ignored; use 'reset' to start over)")

    if args.command == "report":
        report(state, args.z)
        return 0

    n = _step_serial(client, state,
                     [p for p in state["phases"] if p["label"] not in state["completed"]][:args.max_workers])
    remaining = [p for p in state["phases"] if p["label"] not in state["completed"]]
    print(f"[{src}] saved. completed={len(state['completed'])}, remaining={len(remaining)}", flush=True)
    if not remaining:
        report(state, args.z)
    return 0


if __name__ == "__main__":
    sys.exit(main())
