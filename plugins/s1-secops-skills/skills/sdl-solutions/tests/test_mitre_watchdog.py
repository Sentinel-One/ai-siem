"""Tests for the custom-detection MITRE solution (render_mitre_watchdog.py + template).

Zero dependencies: run with `python3 -m unittest discover -s tests`.
"""
import importlib.util
import json
import re
import unittest
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parents[1]
SPECS = SKILL_DIR / "assets" / "mitre_rule_specs"
spec = importlib.util.spec_from_file_location(
    "render_mitre_watchdog", SKILL_DIR / "scripts" / "render_mitre_watchdog.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

ARGS = dict(prefix="T", account_id="1", site_id="2",
            hec_url="https://ingest.example", sdl_integration_id="intg")


def alert_of(wf):
    raw = next(v["value"] for a in wf["actions"]
               for v in a["action"]["data"].get("variables", []) if v["name"] == "MitreAlert")
    return json.loads(re.sub(r"\{\{Function\.DATETIME_TO_MS\(Function\.DATETIME_NOW\(\)\)\}\}", "0", raw))


def slugs_referenced(wf):
    text = json.dumps(wf)
    return set(re.findall(r"\{\{(?:Function\.JQ\()?([a-z0-9]+(?:-[a-z0-9]+)+)\.(?:body|headers|status_code)", text))


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


class RenderEverySpec(unittest.TestCase):
    def test_every_example_spec_renders(self):
        files = sorted(SPECS.glob("*.json"))
        self.assertGreaterEqual(len(files), 3)
        for f in files:
            with self.subTest(spec=f.name):
                wf = R.render(json.loads(f.read_text()), **ARGS)
                self.assertEqual(len(wf["actions"]), 16)

    def test_attacks_sit_on_the_indicator_not_the_finding(self):
        s = json.loads((SPECS / "encoded_powershell.json").read_text())
        al = alert_of(R.render(s, **ARGS))
        self.assertNotIn("attacks", al["finding_info"],
                         "UAM ignores finding_info.attacks; MITRE must be on related_events")
        att = al["finding_info"]["related_events"][0]["attacks"]
        self.assertEqual([a["tactic"]["uid"] for a in att], ["TA0002", "TA0005"])
        self.assertEqual(att[1]["tactic"]["name"], "Stealth")
        self.assertEqual(al["class_uid"], 99602001)

    def test_query_survives_double_escaping(self):
        q = "dataSource.name='X' msg contains:anycase (\"a b\") | group n=count() by host | limit 5"
        s = {"name": "N", "description": "D", "query": q,
             "mitre": [{"tactic": "TA0002", "technique": "T1059"}]}
        wf = R.render(s, **ARGS)
        payload = json.loads(wf["actions"][1]["action"]["data"]["payload"]
                             .replace("{{Function.DELTA_NOW(1)}}", "x")
                             .replace("{{Function.DATETIME_NOW()}}", "y"))
        self.assertEqual(payload["pq"]["query"], q)

    def test_action_references_resolve_to_action_names(self):
        """HA resolves {{launch-lrq...}} from the action NAME; a rename breaks it silently."""
        for tpl in ("mitre_watchdog.workflow.template.json", "ha_watchdog.workflow.template.json"):
            with self.subTest(template=tpl):
                # {{INTERVAL_MINUTES}} is an unquoted number token; stub it so the raw
                # template parses.
                wf = json.loads((SKILL_DIR / "assets" / tpl).read_text()
                                .replace("{{INTERVAL_MINUTES}}", "60"))
                names = {slug(a["action"]["data"]["name"]) for a in wf["actions"]}
                missing = slugs_referenced(wf) - names
                self.assertFalse(missing, f"references with no matching action name: {missing}")


class RejectsBadSpecs(unittest.TestCase):
    def base(self, **kw):
        s = {"name": "N", "description": "D", "query": "x=1 | limit 1",
             "mitre": [{"tactic": "TA0002", "technique": "T1059.001"}]}
        s.update(kw)
        return s

    def assert_rejected(self, s):
        with self.assertRaises(SystemExit) as cm:
            R.render(s, **ARGS)
        self.assertEqual(cm.exception.code, 2)

    def test_unknown_tactic(self):
        self.assert_rejected(self.base(mitre=[{"tactic": "TA9999", "technique": "T1059"}]))

    def test_bad_technique(self):
        self.assert_rejected(self.base(mitre=[{"tactic": "TA0002", "technique": "1059"}]))

    def test_empty_mitre(self):
        self.assert_rejected(self.base(mitre=[]))

    def test_quote_in_name(self):
        self.assert_rejected(self.base(name='say "hi"'))

    def test_bad_severity(self):
        self.assert_rejected(self.base(severity="urgent"))

    def test_from_rule_needs_scheduled(self):
        with self.assertRaises(SystemExit):
            R.spec_from_rule({"queryType": "events", "name": "x", "s1ql": "a=1"},
                             [{"tactic": "TA0002", "technique": "T1059"}])


class FromRule(unittest.TestCase):
    def test_scheduled_rule_converts(self):
        rule = {"name": "Brute", "description": "d", "severity": "High", "queryType": "scheduled",
                "scheduledParams": {"query": "a=1 | group n=count() by h", "lookbackWindowMinutes": 90,
                                    "runIntervalMinutes": 30}}
        s = R.spec_from_rule(rule, [{"tactic": "TA0006", "technique": "T1110"}])
        wf = R.render(s, **ARGS)
        self.assertIn("DELTA_NOW(2)", wf["actions"][1]["action"]["data"]["payload"])  # 90 min -> 2 h
        self.assertEqual(wf["actions"][0]["action"]["data"]["schedule_value"][0]["interval_value"], 30)


if __name__ == "__main__":
    unittest.main()
