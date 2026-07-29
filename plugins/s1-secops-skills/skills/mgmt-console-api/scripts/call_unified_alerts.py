#!/usr/bin/env python3
"""CLI wrapper around the Unified Alert Management (UAM) GraphQL API.

Subcommands:
  list           List alerts (filter, sort, paginate, CSV export).
  get            Fetch a single alert by id.
  raw-indicators Fetch alert + rawIndicators payload.
  history        Audit history for an alert.
  timeline       Timeline events for an alert.
  notes          List notes on an alert.
  add-note       Create a note on an alert.
  update-note    Update an existing note (retries during mgmt_note_id window).
  delete-note    Delete an existing note (retries during mgmt_note_id window).
  actions        List available actions (scope + optional alert filter).
  trigger        Run a set of actions against a filter (blast radius warning).
  set-status     Convenience: status update on one or more alert ids.
  set-verdict    Convenience: analyst-verdict update on alert ids.
  assign         Convenience: assign alerts to a user.
  group-by       alertGroupByCount — faceted counts (deprecated in API).
  groups         alertGroups — group-by listing, paginated.
  facets         alertFiltersCount — values + counts for a facet.
  autocomplete   autocompleteOptions — value suggestions for a field.
  columns        alertColumnMetadata — queryable field list.
  availability   alertsViewDataAvailability — which views have data.
  ai             aiInvestigations for one or more alert ids.
  mitigations    alertMitigationActionResults for one alert.
  csv-export     Bulk alerts CSV export.
  history-csv    CSV export of an alert's audit history.

Filter syntax (for `list`, `csv-export`):
  --filter fieldId=VALUE            (stringEqual)
  --filter fieldId~=VALUE           (stringStartsWith)
  --filter fieldId=VAL1,VAL2        (stringIn)
  --filter fieldId:fullText=TEXT    (FULLTEXT)

Examples:
  call_unified_alerts.py list --filter detectionProduct=EDR --first 5
  call_unified_alerts.py list --filter 'status=NEW,IN_PROGRESS' --first 20
  call_unified_alerts.py notes <alert-id>
  call_unified_alerts.py add-note <alert-id> "Investigating"
  call_unified_alerts.py set-status --scope 12345 --alert-id <id> RESOLVED
  call_unified_alerts.py facets status severity detectionProduct
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from s1_client import S1Client, S1APIError  # noqa: E402
import unified_alerts as uam  # noqa: E402


# --------------------------------------------------------------------------- filters

def parse_filter(spec: str) -> dict:
    """Parse a `fieldId=value` / `fieldId=v1,v2` / `fieldId~=prefix` /
    `fieldId:fullText=text` expression into a FilterInput dict."""
    # FULLTEXT form: fieldId:fullText=value
    if ":fullText=" in spec:
        fid, _, val = spec.partition(":fullText=")
        return uam.build_filter(fieldId=fid, fullText={"value": val})
    if "~=" in spec:
        fid, _, val = spec.partition("~=")
        return uam.build_filter(fieldId=fid, stringStartsWith={"value": val})
    if "=" in spec:
        fid, _, val = spec.partition("=")
        if "," in val:
            return uam.build_filter(
                fieldId=fid, stringIn={"values": [v for v in val.split(",") if v]}
            )
        return uam.build_filter(fieldId=fid, stringEqual={"value": val})
    raise argparse.ArgumentTypeError(f"unrecognized filter syntax: {spec}")


def collect_filters(args) -> list:
    return [parse_filter(s) for s in (args.filter or [])]


# --------------------------------------------------------------------------- handlers

def cmd_list(c, args):
    page = uam.list_alerts(
        c,
        filters=collect_filters(args),
        sort_by=args.sort_by,
        sort_order=args.sort_order,
        first=args.first,
        after=args.after,
    )
    if args.json:
        print(json.dumps(page, indent=2))
        return 0
    print(f"totalCount: {page.get('totalCount'):,}")
    for e in page.get("edges") or []:
        n = e.get("node") or {}
        print(
            f"  {n.get('id')}  {n.get('severity','?'):<8} "
            f"{n.get('status','?'):<12} "
            f"[{(n.get('detectionSource') or {}).get('product','?')}] "
            f"{(n.get('name') or '')[:60]}"
        )
    pi = page.get("pageInfo") or {}
    if pi.get("hasNextPage"):
        print(f"\n(next page: --after {pi.get('endCursor')})")
    return 0


def cmd_get(c, args):
    a = uam.get_alert(c, args.alert_id)
    print(json.dumps(a, indent=2))
    return 0


def cmd_raw_indicators(c, args):
    r = uam.get_alert_with_raw_indicators(c, args.alert_id)
    print(json.dumps(r, indent=2))
    return 0


def cmd_history(c, args):
    h = uam.alert_history(c, args.alert_id, first=args.first, after=args.after)
    if args.json:
        print(json.dumps(h, indent=2))
        return 0
    print(f"totalCount: {h.get('totalCount')}")
    for e in h.get("edges") or []:
        n = e.get("node") or {}
        print(f"  [{n.get('eventType')}] {n.get('createdAt')}: {(n.get('eventText') or '')[:100]}")
    return 0


def cmd_timeline(c, args):
    t = uam.alert_timeline(c, args.alert_id, first=args.first, after=args.after)
    if args.json:
        print(json.dumps(t, indent=2))
        return 0
    print(f"totalCount: {t.get('totalCount')}")
    for e in t.get("edges") or []:
        n = e.get("node") or {}
        print(f"  [{n.get('eventType')}] {n.get('createdAt')}: {(n.get('eventText') or '')[:100]}")
    return 0


def cmd_notes(c, args):
    notes = uam.alert_notes(c, args.alert_id)
    if args.json:
        print(json.dumps(notes, indent=2))
        return 0
    print(f"{len(notes)} note(s)")
    for n in notes:
        author = (n.get("author") or {}).get("fullName", "?")
        print(f"  {n.get('id')}  {n.get('createdAt')}  by {author}")
        print(f"    {(n.get('text') or '')[:200]}")
    return 0


def cmd_add_note(c, args):
    data = uam.add_alert_note(c, args.alert_id, args.text)
    print(f"note count after add: {len(data)}")
    for n in data:
        if n.get("text") == args.text:
            print(f"  created: {n.get('id')}")
    return 0


def cmd_update_note(c, args):
    data = uam.update_alert_note(c, args.note_id, args.text)
    for n in data:
        if n.get("id") == args.note_id:
            print(f"updated {n.get('id')}: {(n.get('text') or '')[:120]}")
            return 0
    print("update ok but note not found in response")
    return 0


def cmd_delete_note(c, args):
    uam.delete_alert_note(c, args.note_id)
    print(f"deleted {args.note_id}")
    return 0


def _build_scope(args):
    return uam.scope(args.scope, scope_type=args.scope_type)


def cmd_actions(c, args):
    filt = None
    if args.alert_id:
        filt = uam.or_filter(
            [uam.build_filter(fieldId="id", stringEqual={"value": args.alert_id})]
        )
    r = uam.available_actions(c, scope_input=_build_scope(args), filter_input=filt)
    if args.json:
        print(json.dumps(r, indent=2))
        return 0
    data = r.get("data") or []
    print(f"{len(data)} action(s)")
    for a in data:
        flag = " (DISABLED)" if a.get("isDisabled") else ""
        print(f"  {a.get('id'):<55} {a.get('type'):<12} {a.get('title')}{flag}")
    return 0


def cmd_trigger(c, args):
    filt = None
    if args.alert_id:
        filt = uam.or_filter(
            [uam.build_filter(fieldId="id", stringIn={"values": args.alert_id})]
        )
    elif args.filter:
        filt = uam.or_filter([collect_filters(args)])
    actions = [json.loads(a) for a in args.action]
    r = uam.trigger_actions(
        c, scope_input=_build_scope(args), actions=actions,
        filter_input=filt, view_type=args.view_type,
    )
    print(json.dumps(r, indent=2))
    return 0


def cmd_set_status(c, args):
    r = uam.set_alert_status(
        c, scope_input=_build_scope(args),
        alert_ids=args.alert_id, status=args.status, note=args.note,
    )
    print(json.dumps(r, indent=2))
    return 0


def cmd_set_verdict(c, args):
    r = uam.set_analyst_verdict(
        c, scope_input=_build_scope(args),
        alert_ids=args.alert_id, verdict=args.verdict, note=args.note,
    )
    print(json.dumps(r, indent=2))
    return 0


def cmd_assign(c, args):
    r = uam.assign_alerts(
        c, scope_input=_build_scope(args),
        alert_ids=args.alert_id, user_email=args.user_email,
    )
    print(json.dumps(r, indent=2))
    return 0


def cmd_group_by(c, args):
    data = uam.group_by_count(c, args.field_id, filters=collect_filters(args), limit=args.limit)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    for g in data:
        print(f"{g.get('fieldId')} (hasNextPage={g.get('hasNextPage')}):")
        for v in g.get("values") or []:
            print(f"  {v.get('value')} ({v.get('label')}): {v.get('count'):,}")
    return 0


def cmd_groups(c, args):
    r = uam.alert_groups(
        c, args.field_id, filters=collect_filters(args),
        first=args.first, after=args.after,
    )
    if args.json:
        print(json.dumps(r, indent=2))
        return 0
    print(f"totalCount: {r.get('totalCount')}")
    for e in r.get("edges") or []:
        n = e.get("node") or {}
        print(f"  {n.get('value')} ({n.get('label')}): {n.get('count'):,}")
    pi = r.get("pageInfo") or {}
    if pi.get("hasNextPage"):
        print(f"(next: --after {pi.get('endCursor')})")
    return 0


def cmd_facets(c, args):
    data = uam.filters_count(c, args.field_id, filters=collect_filters(args))
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    for f in data:
        print(f"{f.get('fieldId')}:")
        for v in f.get("values") or []:
            print(f"  {v.get('value')} ({v.get('label')}): {v.get('count'):,}")
    return 0


def cmd_autocomplete(c, args):
    r = uam.autocomplete(c, args.field_id, args.search_text)
    if args.json:
        print(json.dumps(r, indent=2))
        return 0
    for v in r.get("values") or []:
        print(f"  {v.get('value')}: {v.get('count'):,}")
    return 0


def cmd_columns(c, args):
    cols = uam.column_metadata(c)
    if args.json:
        print(json.dumps(cols, indent=2))
        return 0
    for col in cols:
        flags = []
        if col.get("sortable"):
            flags.append("sort")
        if col.get("groupable"):
            flags.append("group")
        ev = col.get("enumValues")
        evs = f" enum={','.join(ev)}" if ev else ""
        print(
            f"  {col.get('fieldId'):<35} filters={','.join(col.get('filterTypes') or [])} "
            f"{'/'.join(flags)}{evs}"
        )
    return 0


def cmd_availability(c, args):
    data = uam.view_data_availability(c)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    for v in data:
        print(f"  {v.get('viewType'):<20} dataAvailable={v.get('dataAvailable')}")
    return 0


def cmd_ai(c, args):
    data = uam.ai_investigations(c, args.alert_id)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    for i in data:
        print(
            f"  alert={i.get('alertId')} status={i.get('status')} "
            f"verdict={i.get('verdict')} purple={i.get('purpleAiStatus')}"
        )
    return 0


def cmd_mitigations(c, args):
    data = uam.alert_mitigation_action_results(c, args.alert_id)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    print(f"{len(data)} mitigation result(s)")
    for m in data:
        print(f"  {m.get('id')}  {m.get('mitigationActionType')}  {m.get('status')}  {m.get('createdAt')}")
    return 0


def cmd_csv_export(c, args):
    csv = uam.export_alerts_csv(c, filters=collect_filters(args), view_type=args.view_type)
    if args.output:
        Path(args.output).write_text(csv)
        print(f"wrote {len(csv)} chars to {args.output}")
    else:
        sys.stdout.write(csv)
    return 0


def cmd_history_csv(c, args):
    csv = uam.export_alert_history_csv(c, args.alert_id)
    if args.output:
        Path(args.output).write_text(csv)
        print(f"wrote {len(csv)} chars to {args.output}")
    else:
        sys.stdout.write(csv)
    return 0


# --------------------------------------------------------------------------- arg parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_scope_flags(sp):
        sp.add_argument("--scope", nargs="+", required=True, help="ScopeId(s) (account/site/group IDs)")
        sp.add_argument("--scope-type", default="ACCOUNT", choices=uam.SCOPE_TYPES)

    # list
    sp = sub.add_parser("list", help="List alerts")
    sp.add_argument("--filter", action="append", default=[])
    sp.add_argument("--sort-by", default="detectedAt")
    sp.add_argument("--sort-order", default="DESC", choices=["ASC", "DESC"])
    sp.add_argument("--first", type=int, default=10)
    sp.add_argument("--after", default=None)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_list)

    # get
    sp = sub.add_parser("get", help="Fetch one alert by id")
    sp.add_argument("alert_id")
    sp.set_defaults(func=cmd_get)

    # raw-indicators
    sp = sub.add_parser("raw-indicators", help="Alert + rawIndicators payload")
    sp.add_argument("alert_id")
    sp.set_defaults(func=cmd_raw_indicators)

    # history
    sp = sub.add_parser("history", help="Audit history for an alert")
    sp.add_argument("alert_id")
    sp.add_argument("--first", type=int, default=50)
    sp.add_argument("--after", default=None)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_history)

    # timeline
    sp = sub.add_parser("timeline", help="Timeline events for an alert")
    sp.add_argument("alert_id")
    sp.add_argument("--first", type=int, default=50)
    sp.add_argument("--after", default=None)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_timeline)

    # notes
    sp = sub.add_parser("notes", help="List notes on an alert")
    sp.add_argument("alert_id")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_notes)

    # add-note
    sp = sub.add_parser("add-note", help="Create a note on an alert")
    sp.add_argument("alert_id")
    sp.add_argument("text")
    sp.set_defaults(func=cmd_add_note)

    # update-note
    sp = sub.add_parser("update-note", help="Update an existing alert note")
    sp.add_argument("note_id")
    sp.add_argument("text")
    sp.set_defaults(func=cmd_update_note)

    # delete-note
    sp = sub.add_parser("delete-note", help="Delete an existing alert note")
    sp.add_argument("note_id")
    sp.set_defaults(func=cmd_delete_note)

    # actions
    sp = sub.add_parser("actions", help="List available actions (optionally for one alert)")
    add_scope_flags(sp)
    sp.add_argument("--alert-id", default=None, help="Optional: constrain to this alert id")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_actions)

    # trigger
    sp = sub.add_parser("trigger", help="Run alertTriggerActions (blast radius warning)")
    add_scope_flags(sp)
    sp.add_argument("--alert-id", nargs="+", default=None)
    sp.add_argument("--filter", action="append", default=[])
    sp.add_argument("--view-type", default="ALL", choices=uam.VIEW_TYPES)
    sp.add_argument(
        "--action", action="append", required=True,
        help='TriggerActionInput as JSON, e.g. \'{"id":"S1/alert/addNote","payload":{"note":{"value":"x"}}}\'',
    )
    sp.set_defaults(func=cmd_trigger)

    # set-status
    sp = sub.add_parser("set-status", help="Convenience: status update on specific alerts")
    add_scope_flags(sp)
    sp.add_argument("--alert-id", nargs="+", required=True)
    sp.add_argument("status")
    sp.add_argument("--note", default=None)
    sp.set_defaults(func=cmd_set_status)

    # set-verdict
    sp = sub.add_parser("set-verdict", help="Convenience: analyst verdict on specific alerts")
    add_scope_flags(sp)
    sp.add_argument("--alert-id", nargs="+", required=True)
    sp.add_argument("verdict")
    sp.add_argument("--note", default=None)
    sp.set_defaults(func=cmd_set_verdict)

    # assign
    sp = sub.add_parser("assign", help="Convenience: assign alerts to a user")
    add_scope_flags(sp)
    sp.add_argument("--alert-id", nargs="+", required=True)
    sp.add_argument("--user-email", required=True)
    sp.set_defaults(func=cmd_assign)

    # group-by
    sp = sub.add_parser("group-by", help="alertGroupByCount (deprecated but live)")
    sp.add_argument("field_id", nargs="+")
    sp.add_argument("--filter", action="append", default=[])
    sp.add_argument("--limit", type=int, default=None)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_group_by)

    # groups
    sp = sub.add_parser("groups", help="alertGroups (paginated group-by)")
    sp.add_argument("field_id")
    sp.add_argument("--filter", action="append", default=[])
    sp.add_argument("--first", type=int, default=20)
    sp.add_argument("--after", default=None)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_groups)

    # facets
    sp = sub.add_parser("facets", help="alertFiltersCount — facet counts")
    sp.add_argument("field_id", nargs="+")
    sp.add_argument("--filter", action="append", default=[])
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_facets)

    # autocomplete
    sp = sub.add_parser("autocomplete", help="autocompleteOptions for a field")
    sp.add_argument("field_id")
    sp.add_argument("search_text")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_autocomplete)

    # columns
    sp = sub.add_parser("columns", help="alertColumnMetadata")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_columns)

    # availability
    sp = sub.add_parser("availability", help="alertsViewDataAvailability")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_availability)

    # ai
    sp = sub.add_parser("ai", help="aiInvestigations for alert ids")
    sp.add_argument("alert_id", nargs="+")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_ai)

    # mitigations
    sp = sub.add_parser("mitigations", help="alertMitigationActionResults for one alert")
    sp.add_argument("alert_id")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_mitigations)

    # csv-export
    sp = sub.add_parser("csv-export", help="alertsCsvExport")
    sp.add_argument("--filter", action="append", default=[])
    sp.add_argument("--view-type", default="ALL", choices=uam.VIEW_TYPES)
    sp.add_argument("-o", "--output", default=None, help="Write CSV to this file")
    sp.set_defaults(func=cmd_csv_export)

    # history-csv
    sp = sub.add_parser("history-csv", help="alertHistoryCsvExport")
    sp.add_argument("alert_id")
    sp.add_argument("-o", "--output", default=None)
    sp.set_defaults(func=cmd_history_csv)

    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        c = S1Client()
    except RuntimeError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    try:
        return args.func(c, args)
    except uam.UAMError as e:
        print(f"UAM error: {e}", file=sys.stderr)
        return 1
    except S1APIError as e:
        print(f"HTTP error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
