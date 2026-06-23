"""Benchmark source + schema discovery across 5 representative sources.

Enumerates dataSource.name, runs discover_schema for each of 5 picked
sources with the logVolume exclusion filter, and prints a compact
results table: wall time, n_sampled, n_present, prim_key, action_key,
and the top 6 populated real-event attributes per source.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from s1_client import S1Client  # noqa: E402
from inspect_source import discover_schema, pick_keys  # noqa: E402

SOURCES = [
    "SentinelOne",
    "Windows Event Logs",
    "FortiGate",
    "Zscaler Internet Access",
    "Example Source",
]

LOG_VOLUME_FILTER = "(tag != 'logVolume' OR !(tag = *))"


def run() -> int:
    client = S1Client()
    print(f"Tenant: {client.base_url}")
    print(f"Benchmarking schema discovery on {len(SOURCES)} sources "
          f"(logVolume excluded, backend=auto, escalating window 1h->24h)\n")

    rows = []
    for src in SOURCES:
        t0 = time.monotonic()
        schema = discover_schema(
            client, src, hours=24, sample=150,
            extra_filter=LOG_VOLUME_FILTER,
            backend="auto",
        )
        dt = time.monotonic() - t0
        prim, action = pick_keys(schema)
        rows.append({
            "source": src,
            "wall_s": dt,
            "effective_h": schema.get("effective_hours"),
            "n_sampled": schema.get("n_sampled", 0),
            "n_present": schema.get("n_present", 0),
            "prim_key": prim,
            "action_key": action,
            "error": schema.get("error"),
            "fields": schema.get("fields", {}),
        })
        status = "OK" if not schema.get("error") else "ERR"
        print(f"[{status}] {src:<26s}  {dt:5.1f}s  "
              f"eff={schema.get('effective_hours'):>5}h  "
              f"n={schema.get('n_sampled', 0):>3}  "
              f"attrs={schema.get('n_present', 0):>3}  "
              f"prim={prim}  action={action}")

    # detailed per-source breakdown
    print("\n" + "=" * 78)
    for r in rows:
        print(f"\n--- {r['source']} ---")
        if r["error"]:
            print(f"  error: {r['error']}")
            continue
        fields = r["fields"]
        # Show top 6 populated, excluding boilerplate (dataSource.*, account.*, site.id, sca:, tenant)
        def is_noise(name: str) -> bool:
            low = name.lower()
            return (low.startswith("datasource.")
                    or low.startswith("account.")
                    or low == "site.id" or low == "tenant"
                    or low.startswith("sca:") or low == "region"
                    or low == "timestamp" or low == "severity"
                    or low.startswith("parser.") or low == "logfile")
        interesting = [
            (n, m) for n, m in fields.items() if not is_noise(n)
        ]
        interesting.sort(key=lambda kv: (-kv[1]["populated_frac"], kv[0]))
        print(f"  sampled {r['n_sampled']} events in {r['effective_h']}h "
              f"window, {r['n_present']} distinct attributes")
        print(f"  prim_key   = {r['prim_key']}")
        print(f"  action_key = {r['action_key']}")
        print(f"  top attributes (excl. framework/boilerplate):")
        for name, meta in interesting[:6]:
            pct = int(meta["populated_frac"] * 100)
            samp = ", ".join(meta["samples"][:1])
            if len(samp) > 55:
                samp = samp[:55] + "..."
            print(f"    {meta['classified_as']:17s}  "
                  f"{name:35s}  pop={pct:>3}%  e.g. {samp}")

    # summary table
    print("\n" + "=" * 78)
    print("SUMMARY\n")
    print(f"{'source':<26s}  {'wall':>6s}  {'eff':>5s}  {'n':>4s}  "
          f"{'attrs':>5s}  {'prim_key':<14s}  {'action_key':<14s}")
    print("-" * 84)
    for r in rows:
        print(f"{r['source']:<26s}  {r['wall_s']:>5.1f}s  "
              f"{r['effective_h']:>4}h  {r['n_sampled']:>4}  "
              f"{r['n_present']:>5}  "
              f"{str(r['prim_key']):<14s}  {str(r['action_key']):<14s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
