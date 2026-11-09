"""Every verdict path and every key guard of scripts/nd_agent_crosscheck.py."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import nd_agent_crosscheck as x  # noqa: E402

NOW = datetime(2026, 11, 9, tzinfo=timezone.utc)
GW = "18:69:45:25:85:58"


def nd(i, name="host-a", macs=(), ips=(), gws=(GW,), site="S1", methods=("arp",)):
    return {"id": i, "name": name, "macAddresses": list(macs), "internalIps": list(ips),
            "gatewayMacs": list(gws), "s1SiteId": site, "discoveryMethods": list(methods)}


def agent(i, name="HOST-A", mac="84:47:09:56:21:be", ip="10.0.0.5", gw=GW, site="S1",
          last="2026-11-08T00:00:00Z", decom=False, uninst=False):
    return {"id": i, "computerName": name, "siteId": site, "siteName": "Site " + site,
            "isDecommissioned": decom, "isUninstalled": uninst, "lastActiveDate": last,
            "networkInterfaces": [{"physical": mac, "inet": [ip], "gatewayMacAddress": gw}]}


def run(nds, agents):
    return {r["id"]: r for r in x.check(nds, agents, NOW, 30)}


class Verdicts(unittest.TestCase):
    def test_mac_match_is_a_likely_false_positive(self):
        r = run([nd("n1", name="other", macs=["84-47-09-56-21-BE"])], [agent("a1")])["n1"]
        self.assertEqual(1, r["rank"])
        self.assertEqual("a1", r["agentId"])

    def test_ip_and_name_on_the_same_agent(self):
        r = run([nd("n1", name="host-a.corp.local", ips=["10.0.0.5"])], [agent("a1", mac="00:11:22:33:44:55")])["n1"]
        self.assertEqual(2, r["rank"])

    def test_ip_and_name_on_different_agents_is_not_rank_2(self):
        agents = [agent("a1", name="HOST-A", mac="00:11:22:33:44:55", ip="10.0.0.9"),
                  agent("a2", name="HOST-B", mac="00:11:22:33:44:66", ip="10.0.0.5")]
        self.assertEqual(3, run([nd("n1", name="host-a", ips=["10.0.0.5"])], agents)["n1"]["rank"])

    def test_hostname_only_is_review(self):
        r = run([nd("n1", name="HOST-A")], [agent("a1", mac="00:11:22:33:44:55", ip="10.9.9.9")])["n1"]
        self.assertEqual(3, r["rank"])

    def test_ip_only_is_review(self):
        r = run([nd("n1", name="printer-7", ips=["10.0.0.5"])], [agent("a1", mac="00:11:22:33:44:55")])["n1"]
        self.assertEqual(4, r["rank"])

    def test_strong_match_to_a_long_offline_agent_is_review(self):
        r = run([nd("n1", macs=["84:47:09:56:21:be"])], [agent("a1", last="2026-08-01T00:00:00Z")])["n1"]
        self.assertEqual(5, r["rank"])

    def test_offline_strong_match_outranks_a_live_hostname_match(self):
        agents = [agent("old", last="2026-08-01T00:00:00Z"),
                  agent("live", name="HOST-A", mac="00:11:22:33:44:55", ip="10.9.9.9")]
        r = run([nd("n1", name="host-a", macs=["84:47:09:56:21:be"])], agents)["n1"]
        self.assertEqual((5, "old"), (r["rank"], r["agentId"]))

    def test_decommissioned_or_uninstalled_agent_stays_unprotected(self):
        for kw in ({"decom": True}, {"uninst": True}):
            r = run([nd("n1", macs=["84:47:09:56:21:be"])], [agent("a1", **kw)])["n1"]
            self.assertEqual(6, r["rank"], kw)

    def test_live_agent_beats_a_dead_one(self):
        agents = [agent("dead", decom=True), agent("live", mac="00:11:22:33:44:55")]
        r = run([nd("n1", macs=["84:47:09:56:21:be", "00:11:22:33:44:55"])], agents)["n1"]
        self.assertEqual((1, "live"), (r["rank"], r["agentId"]))

    def test_no_match(self):
        self.assertEqual(7, run([nd("n1", name="zzz-9", macs=["00:aa:bb:cc:dd:ee"])], [agent("a1")])["n1"]["rank"])

    def test_times_without_an_offset_are_utc(self):
        self.assertEqual(timezone.utc, x.parse_time("2026-11-09T00:00:00").tzinfo)
        r = x.check([nd("n1", macs=["84:47:09:56:21:be"])], [agent("a1", last="2026-11-08T00:00:00")], NOW, 30)[0]
        self.assertEqual(1, r["rank"])

    def test_agent_in_another_site_is_flagged(self):
        r = run([nd("n1", macs=["84:47:09:56:21:be"], site="S1")], [agent("a1", site="S2")])["n1"]
        self.assertTrue(r["agentInAnotherSite"])


class Guards(unittest.TestCase):
    def test_locally_administered_and_multicast_macs_never_match(self):
        for m in ("02:42:ac:11:00:02", "3a:f4:49:96:98:35", "01:00:5e:00:00:01"):
            r = run([nd("n1", name="zzz-9", macs=[m])], [agent("a1", mac=m)])["n1"]
            self.assertEqual(7, r["rank"], m)

    def test_zero_and_vpn_adapter_macs_never_match(self):
        for m in ("00:00:00:00:00:00", "00:05:9a:3c:7a:00"):
            self.assertEqual(7, run([nd("n1", name="zzz-9", macs=[m])], [agent("a1", mac=m)])["n1"]["rank"])

    def test_mac_on_two_nd_devices_clears_neither(self):
        res = run([nd("n1", name="zzz-1", macs=["84:47:09:56:21:be"]), nd("n2", name="zzz-2", macs=["84:47:09:56:21:be"])], [agent("a1")])
        self.assertEqual({7}, {r["rank"] for r in res.values()})

    def test_ip_needs_the_same_gateway_on_the_same_nic(self):
        r = run([nd("n1", name="zzz-9", ips=["10.0.0.5"], gws=["aa:bb:cc:dd:ee:00"])], [agent("a1")])["n1"]
        self.assertEqual(7, r["rank"])

    def test_ip_without_a_gateway_never_matches(self):
        r = run([nd("n1", name="zzz-9", ips=["10.0.0.5"], gws=[])], [agent("a1", gw=None)])["n1"]
        self.assertEqual(7, r["rank"])

    def test_shared_gateway_macs_never_qualify_an_ip(self):
        for g in ("00:00:5e:00:01:01", "00:00:0c:07:ac:01", "12:34:56:78:9a:bc"):
            r = run([nd("n1", name="zzz-9", ips=["10.0.0.5"], gws=[g])], [agent("a1", gw=g)])["n1"]
            self.assertEqual(7, r["rank"], g)

    def test_junk_hostnames_never_match(self):
        for n in ("", "ab", "192.168.1.20", "84:47:09:56:21:be", "Unknown Workstation Name", "iPhone", "localhost"):
            r = run([nd("n1", name=n)], [agent("a1", name=n, mac="00:11:22:33:44:55", ip="10.9.9.9")])["n1"]
            self.assertEqual(7, r["rank"], repr(n))

    def test_identity_flags(self):
        r = run([nd("n1", name="Unknown Workstation Name", macs=["3a:f4:49:96:98:35"], methods=["neighbor"])], [])["n1"]
        self.assertEqual(["randomised or shared MAC", "no usable hostname", "seen by neighbour discovery only"], r["identity"])
        self.assertIn("no MAC address", run([nd("n2")], [])["n2"]["identity"])

    def test_many_macless_devices_behind_one_gateway_are_flagged_as_ghosts(self):
        rows = [nd(f"g{i}", name=f"ghost-{i}", gws=["00:0c:29:aa:bb:cc"]) for i in range(50)]
        rows.append(nd("real", name="lonely-1", gws=["00:0c:29:11:22:33"]))
        res = {r["id"]: r for r in x.check(rows, [], NOW, 30, ghost_threshold=50)}
        self.assertIn("possible middlebox ghost", res["g0"]["identity"])
        self.assertNotIn("possible middlebox ghost", res["real"]["identity"])

    def test_stale_nd_record_is_flagged(self):
        d = nd("n1", name="zzz-9")
        d["lastActiveDt"] = "2026-11-01T00:00:00Z"
        self.assertIn("not seen in the last 24 hours", run([d], [])["n1"]["identity"])


class OtherInventories(unittest.TestCase):
    def test_cloud_mac_counts_only_with_the_same_ip_on_the_same_nic(self):
        a = agent("a1", mac="0a:1b:2c:3d:4e:5f", ip="172.31.0.10")
        both = {"id": "c1", "name": "i-0abc", "macAddresses": ["0a:1b:2c:3d:4e:5f"], "internalIps": ["172.31.0.10"]}
        mac_only = {"id": "c2", "name": "i-0def", "macAddresses": ["0a:1b:2c:3d:4e:5f"], "internalIps": ["172.31.9.9"]}
        res = {r["id"]: r["rank"] for r in x.check_other([both, mac_only], [a], [])}
        self.assertEqual({"c1": 1, "c2": 7}, res)

    def test_ad_computer_name_match_is_review_and_dead_agents_do_not_count(self):
        ad = {"id": "ad1", "name": "WS-0042", "resourceType": "Windows desktop"}
        self.assertEqual(3, x.check_other([ad], [agent("a1", name="ws-0042.corp.local")], [])[0]["rank"])
        self.assertEqual(7, x.check_other([ad], [agent("a1", name="WS-0042", decom=True)], [])[0]["rank"])

    def test_flags_rows_that_network_discovery_also_lists(self):
        ad = {"id": "ad1", "name": "WS-0042"}
        self.assertTrue(x.check_other([ad], [], [nd("n1", name="ws-0042")])[0]["alsoInNetworkDiscovery"])


class Cli(unittest.TestCase):
    def test_reads_tool_output_files_and_summarises(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            (p / "nd.json").write_text(json.dumps({"rows": [nd("n1", macs=["84:47:09:56:21:be"]), nd("n2", name="zzz-9")]}))
            (p / "a1.json").write_text(json.dumps({"data": [agent("a1")], "pagination": {}}))
            (p / "a2.json").write_text(json.dumps({"data": [agent("a1")], "pagination": {}}))
            import contextlib, io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                x.main(["--nd", str(p / "nd.json"), "--agents", str(p / "a1.json"), str(p / "a2.json"),
                        "--out", str(p / "v.csv"), "--now", "2026-11-09T00:00:00Z"])
            s = json.loads(buf.getvalue())
            self.assertEqual((2, 1, 1, 1), (s["devices"], s["agentsLoaded"], s["likelyFalsePositives"], s["unprotected"]))
            self.assertTrue((p / "v.csv").read_text().startswith("id,"))


if __name__ == "__main__":
    unittest.main()
