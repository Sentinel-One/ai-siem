#!/usr/bin/env python3
"""Check Network Discovery "Missing EPP" devices against the SentinelOne agent list.

Network Discovery (ND) can list a device that already runs the agent as unprotected: the
agent reported a different NIC, the ND record has no MAC, the agent sits in another site,
or the device was seen before its agent registered. This script matches every unprotected
ND device to the agents the token can see and gives each device one verdict.

Inputs are files the MCP tools already write, so no customer data passes through the chat:

    --nd       asset_inventory_search(surface: NETWORK_DISCOVERY,
                 filters: [missingCoverage EPP], outputFile: nd.json)
    --agents   one or more s1_api_get(path: /web/api/v2.1/agents, outputFile: agents-N.json)
               pages: every agent in scope, including decommissioned ones

    python3 nd_agent_crosscheck.py --nd nd.json --agents agents-*.json --out verdicts.json

Matching rules (assets/nd_agent_crosscheck.pq applies equivalent rules to the asset inventory; see the
playbook's Dashboard section for where the two differ):

- MAC: normalised to 12 hex digits. Only globally unique unicast MACs count (the second hex
  digit is 0, 4, 8 or c), never all zeros or a known shared VPN adapter MAC, and never a MAC
  that more than one ND device carries.
- IP: an ND IP matches an agent NIC only when that same NIC reports the same gateway MAC, and
  that gateway MAC is a real, non-shared one (not VRRP, HSRP or the Azure virtual gateway).
- Hostname: lower case, domain removed, at least 3 characters, not a number, IP or MAC, and
  not a placeholder or generic device name.
- IP plus hostname counts only when both point at the same agent.
- A live agent is one that is neither decommissioned nor uninstalled. A match to a live agent
  that has not been active for --stale-days days is a review item, not a false positive.

Verdicts: see VERDICTS. A device takes the best verdict over every agent it matches, in this order:
1, 2, 5, 3, 4, 6, 7 (a strong match to an offline agent outranks a hostname-only or IP-only match).
Zero dependencies.
"""
import argparse
import csv
import json
import re
import sys
from datetime import datetime, timedelta, timezone

VERDICTS = {
    1: "Likely false positive: agent MAC matches",
    2: "Likely false positive: agent IP and hostname match",
    3: "Review: hostname matches an agent",
    4: "Review: IP matches an agent",
    5: "Review: matched agent has been offline",
    6: "Unprotected: matched agent is decommissioned or uninstalled",
    7: "Unprotected: no agent match",
}

GOOD_MAC = re.compile(r"^[0-9a-f][048c][0-9a-f]{10}$")
BAD_MACS = {"000000000000", "00059a3c7a00"}
SHARED_GATEWAY = re.compile(r"^(00005e0001|00000c07ac|00000c9ff|123456789abc)")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
GENERIC_NAME = re.compile(
    r"^(unknown.*|localhost|iphone.*|ipad.*|watch|android.*|galaxy.*|macbook.*|imac|raspberrypi)$")
MAC_SHAPED = re.compile(r"^([0-9a-f]{2}[:-]?){5}[0-9a-f]{2}$")


def norm_mac(m):
    m = re.sub(r"[^0-9a-f]", "", (m or "").lower())
    return m if GOOD_MAC.match(m) and m not in BAD_MACS else None


def norm_gw(m):
    m = re.sub(r"[^0-9a-f]", "", (m or "").lower())
    return m if len(m) == 12 and not SHARED_GATEWAY.match(m) and m != "000000000000" else None


def norm_name(n):
    n = (n or "").strip().lower().split(".")[0]
    if len(n) < 3 or re.fullmatch(r"[0-9-]+", n) or MAC_SHAPED.match(n) or GENERIC_NAME.match(n):
        return None
    return n


def parse_time(s):
    if not s:
        return None
    try:
        t = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def load_rows(path, key):
    data = json.load(open(path, encoding="utf-8"))
    if isinstance(data, list):
        return data
    for k in (key, "rows", "data"):
        if isinstance(data.get(k), list):
            return data[k]
    raise SystemExit(f"{path}: no '{key}' list found")


def nd_keys(d):
    macs = {m for m in (norm_mac(x) for x in d.get("macAddresses") or []) if m}
    gws = {g for g in (norm_gw(x) for x in d.get("gatewayMacs") or []) if g}
    ips = {(ip, g) for ip in d.get("internalIps") or [] if IPV4.match(ip or "") for g in gws}
    return macs, ips, norm_name(d.get("name"))


def agent_live(a):
    return not a.get("isDecommissioned") and not a.get("isUninstalled")


def build_index(agents):
    mac_ix, ip_ix, name_ix = {}, {}, {}
    for a in agents:
        for nic in a.get("networkInterfaces") or []:
            m = norm_mac(nic.get("physical"))
            if m:
                mac_ix.setdefault(m, set()).add(a["id"])
            g = norm_gw(nic.get("gatewayMacAddress"))
            if g:
                for ip in nic.get("inet") or []:
                    if IPV4.match(ip or ""):
                        ip_ix.setdefault((ip, g), set()).add(a["id"])
        n = norm_name(a.get("computerName"))
        if n:
            name_ix.setdefault(n, set()).add(a["id"])
    return mac_ix, ip_ix, name_ix


def raw_macs(d):
    raw = [re.sub(r"[^0-9a-f]", "", (m or "").lower()) for m in d.get("macAddresses") or []]
    return [m for m in raw if len(m) == 12]


def identity_flags(d, ghost_gateways=(), now=None):
    raw = raw_macs(d)
    flags = []
    if not raw:
        flags.append("no MAC address")
        gws = {re.sub(r"[^0-9a-f]", "", (g or "").lower()) for g in d.get("gatewayMacs") or []}
        if gws & set(ghost_gateways):
            flags.append("possible middlebox ghost")
    elif not any(norm_mac(m) for m in raw):
        flags.append("randomised or shared MAC")
    if not norm_name(d.get("name")):
        flags.append("no usable hostname")
    if (d.get("discoveryMethods") or []) == ["neighbor"]:
        flags.append("seen by neighbour discovery only")
    last = parse_time(d.get("lastActiveDt"))
    if now and last and last < now - timedelta(hours=24):
        flags.append("not seen in the last 24 hours")
    return flags


def ghost_gateways(nd_rows, threshold):
    """Gateway MACs behind which at least `threshold` ND devices have no MAC: a firewall, NAT or
    virtual edge answering scans for a whole range produces these."""
    counts = {}
    for d in nd_rows:
        if not raw_macs(d):
            for g in {re.sub(r"[^0-9a-f]", "", (g or "").lower()) for g in d.get("gatewayMacs") or []}:
                if g:
                    counts[g] = counts.get(g, 0) + 1
    return {g for g, n in counts.items() if n >= threshold}


def check(nd_rows, agents, now, stale_days, ghost_threshold=50):
    by_id = {a["id"]: a for a in agents}
    mac_ix, ip_ix, name_ix = build_index(agents)
    mac_owners = {}
    for d in nd_rows:
        for m in nd_keys(d)[0]:
            mac_owners.setdefault(m, set()).add(d["id"])
    stale_before = now - timedelta(days=stale_days)
    ghosts = ghost_gateways(nd_rows, ghost_threshold)
    out = []
    for d in nd_rows:
        macs, ips, name = nd_keys(d)
        macs = {m for m in macs if len(mac_owners.get(m, ())) == 1}
        hits = {}  # agent id -> set of key kinds
        for m in macs:
            for aid in mac_ix.get(m, ()):
                hits.setdefault(aid, set()).add("mac")
        for k in ips:
            for aid in ip_ix.get(k, ()):
                hits.setdefault(aid, set()).add("ip")
        for aid in name_ix.get(name, ()) if name else ():
            hits.setdefault(aid, set()).add("name")
        # A strong match to an offline agent (5) says more than a weak match to a live one (3, 4).
        priority = {1: 0, 2: 1, 5: 2, 3: 3, 4: 4, 6: 5, 7: 6}
        best, best_agent = 7, None
        for aid, kinds in hits.items():
            a = by_id[aid]
            if not agent_live(a):
                rank = 6
            else:
                strong = "mac" in kinds or {"ip", "name"} <= kinds
                last = parse_time(a.get("lastActiveDate"))
                if strong and last and last < stale_before:
                    rank = 5
                elif "mac" in kinds:
                    rank = 1
                elif {"ip", "name"} <= kinds:
                    rank = 2
                elif "name" in kinds:
                    rank = 3
                else:
                    rank = 4
            if priority[rank] < priority[best]:
                best, best_agent = rank, a
        row = {
            "id": d["id"], "name": d.get("name"), "ndSiteId": d.get("s1SiteId"),
            "rank": best, "verdict": VERDICTS[best], "identity": identity_flags(d, ghosts, now),
            "agentId": None, "agentName": None, "agentSiteId": None, "agentSiteName": None,
            "agentLastActive": None, "agentInAnotherSite": False,
        }
        if best_agent:
            row.update(agentId=best_agent["id"], agentName=best_agent.get("computerName"),
                       agentSiteId=best_agent.get("siteId"), agentSiteName=best_agent.get("siteName"),
                       agentLastActive=best_agent.get("lastActiveDate"))
            row["agentInAnotherSite"] = bool(d.get("s1SiteId") and best_agent.get("siteId")
                                             and str(d["s1SiteId"]) != str(best_agent["siteId"]))
        out.append(row)
    return out


OTHER_VERDICTS = {
    1: "Likely false positive: agent MAC and IP match",
    3: "Review: hostname matches an agent",
    7: "Unprotected: no agent match",
}


def check_other(rows, agents, nd_rows):
    """Gap rows from other inventories (IDENTITY Missing EPP, CLOUD Missing CWS). These rows carry
    no gateway, so an IP never counts alone. Cloud interfaces use locally administered MACs, so here
    a MAC counts only on the same agent NIC as the same IP. AD and Entra computer objects carry a
    name only, which is a review match at best."""
    live = [a for a in agents if agent_live(a)]
    pair_ix, name_ix = {}, {}
    for a in live:
        for nic in a.get("networkInterfaces") or []:
            m = re.sub(r"[^0-9a-f]", "", (nic.get("physical") or "").lower())
            if len(m) == 12 and m != "000000000000":
                for ip in nic.get("inet") or []:
                    pair_ix.setdefault((m, ip), a)
        n = norm_name(a.get("computerName"))
        if n:
            name_ix.setdefault(n, a)
    nd_names = {norm_name(d.get("name")) for d in nd_rows} - {None}
    out = []
    for r in rows:
        macs = [re.sub(r"[^0-9a-f]", "", (m or "").lower()) for m in r.get("macAddresses") or []]
        hit = next((pair_ix[(m, ip)] for m in macs for ip in r.get("internalIps") or [] if (m, ip) in pair_ix), None)
        rank = 1 if hit else 7
        if not hit:
            hit = name_ix.get(norm_name(r.get("name")) or "")
            rank = 3 if hit else 7
        out.append({"id": r["id"], "name": r.get("name"), "resourceType": r.get("resourceType"),
                    "missingCoverage": r.get("missingCoverage"), "rank": rank, "verdict": OTHER_VERDICTS[rank],
                    "agentId": hit and hit["id"], "agentName": hit and hit.get("computerName"),
                    "alsoInNetworkDiscovery": norm_name(r.get("name")) in nd_names})
    return out


def summarise(rows, agents_loaded):
    s = {"devices": len(rows), "agentsLoaded": agents_loaded, "verdicts": {}, "identity": {},
         "agentInAnotherSite": sum(r["agentInAnotherSite"] for r in rows if r["rank"] <= 2)}
    for r in rows:
        s["verdicts"][r["verdict"]] = s["verdicts"].get(r["verdict"], 0) + 1
        if r["rank"] == 7:
            for f in r["identity"] or ["hardware MAC and hostname"]:
                s["identity"][f] = s["identity"].get(f, 0) + 1
    s["likelyFalsePositives"] = sum(1 for r in rows if r["rank"] <= 2)
    s["review"] = sum(1 for r in rows if 3 <= r["rank"] <= 5)
    s["unprotected"] = sum(1 for r in rows if r["rank"] >= 6)
    return s


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--nd", required=True, help="asset_inventory_search outputFile (.json)")
    ap.add_argument("--agents", required=True, nargs="+", help="s1_api_get /agents outputFile pages")
    ap.add_argument("--out", help="write per-device verdicts (.json or .csv)")
    ap.add_argument("--other", nargs="*", default=[],
                    help="asset_inventory_search outputFiles of other gap lists (IDENTITY Missing EPP, CLOUD Missing CWS)")
    ap.add_argument("--other-out", help="write verdicts for --other rows (.json)")
    ap.add_argument("--stale-days", type=int, default=30)
    ap.add_argument("--ghost-threshold", type=int, default=50,
                    help="MAC-less devices behind one gateway MAC that mark a possible middlebox")
    ap.add_argument("--now", help="ISO time to judge agent staleness against (default: now)")
    a = ap.parse_args(argv)
    nd = load_rows(a.nd, "rows")
    agents = {}
    for f in a.agents:
        for ag in load_rows(f, "data"):
            agents[ag["id"]] = ag
    now = parse_time(a.now) if a.now else datetime.now(timezone.utc)
    rows = check(nd, list(agents.values()), now, a.stale_days, a.ghost_threshold)
    if a.out:
        if a.out.endswith(".csv"):
            with open(a.out, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["id"])
                w.writeheader()
                for r in rows:
                    w.writerow({**r, "identity": "; ".join(r["identity"])})
        else:
            json.dump(rows, open(a.out, "w", encoding="utf-8"), indent=1)
    summary = summarise(rows, len(agents))
    if a.other:
        other = check_other([r for f in a.other for r in load_rows(f, "rows")], list(agents.values()), nd)
        if a.other_out:
            json.dump(other, open(a.other_out, "w", encoding="utf-8"), indent=1)
        summary["other"] = {"rows": len(other), "alsoInNetworkDiscovery": sum(r["alsoInNetworkDiscovery"] for r in other),
                            "verdicts": {}}
        for r in other:
            summary["other"]["verdicts"][r["verdict"]] = summary["other"]["verdicts"].get(r["verdict"], 0) + 1
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
