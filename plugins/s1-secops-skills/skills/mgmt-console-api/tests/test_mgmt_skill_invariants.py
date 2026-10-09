"""Structural tests for the `mgmt-console-api` skill. No network, no tenant.

These pin the rules that have cost real time on this API:

1. `isLegacy=false` on GET /cloud-detection/rules. Omitting it returns a WRONG
   result set, not a smaller one: every scheduled PowerQuery rule is dropped
   with no error. Both the documentation and the client-side guard are pinned.
2. UAM writes go through `alertTriggerActions`, with the alert id in the FILTER
   and never as the action `id`, and the write is verified by re-reading.
3. The PowerQuery recipes shipped with this skill still pass the repo linter in
   `tools/run_evals.py`, which is imported rather than reimplemented.
4. Live-measured platform-rule and UAM query facts (2026-10-09) stay stated,
   and the superseded claims they replaced stay gone.

Run:
    python3 -m unittest discover -s mgmt-console-api/tests
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import sys
import unittest

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
ROOT = SKILL_DIR.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))


def _load_linter():
    """Import `tools/run_evals.py`, or return None where the repo has no such tree.

    A fixed `ROOT / "tools"` path exists only in this repo. Skills vendored into
    another repository land several levels deeper, and because this import runs
    at module scope the resulting FileNotFoundError aborted collection: the whole
    suite contributed no signal instead of failing anything visibly. Walk up for
    the linter, and skip only the tests that actually need it.
    """
    for base in [SKILL_DIR, *SKILL_DIR.parents]:
        cand = base / "tools" / "run_evals.py"
        if cand.is_file():
            spec = importlib.util.spec_from_file_location("run_evals", str(cand))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


LINTER = _load_linter()
NEEDS_LINTER = unittest.skipIf(
    LINTER is None, "tools/run_evals.py not present in this repository layout")

FENCE = re.compile(r"^```(\w*)\n(.*?)^```", re.M | re.S)
PQ_LANGS = {"text", "powerquery", "pq"}
COUNTER_EXAMPLE = re.compile(r"←|^\s*(?:#|//)\s*(?:wrong|bad|do not|don't)\b",
                             re.I | re.M)
SENTINEL = "event.time=*\n"


class IsLegacyRule(unittest.TestCase):
    """The single most expensive listing mistake on this API."""

    def test_documented_in_the_skill(self):
        text = (SKILL_DIR / "references" / "detection-rules.md").read_text(
            encoding="utf-8")
        self.assertIn("isLegacy=false", text)
        self.assertRegex(
            text, r"(?i)(?:silently|no error|omits)",
            "the reference no longer says the omission is silent, which is the "
            "whole reason the rule exists")
        self.assertRegex(text, r"(?i)scheduled")

    def test_client_guard_still_injects(self):
        from s1_client import _maybe_inject_islegacy

        for path in ("/web/api/v2.1/cloud-detection/rules",
                     "/web/api/v2.1/cloud-detection/rules/",
                     "/web/api/v2.1/cloud-detection/rules/2487612380083288142"):
            self.assertEqual({"isLegacy": "false"},
                             _maybe_inject_islegacy("GET", path, None),
                             f"guard stopped injecting on GET {path}")

    def test_guard_does_not_touch_writes(self):
        from s1_client import _maybe_inject_islegacy

        # isLegacy is a GET-listing param only; in a body it returns
        # 400 filter: isLegacy: Unknown field.
        out = _maybe_inject_islegacy(
            "POST", "/web/api/v2.1/cloud-detection/rules", None)
        self.assertNotIn("isLegacy", out or {})

    def test_guard_preserves_an_explicit_value(self):
        from s1_client import _maybe_inject_islegacy

        out = _maybe_inject_islegacy(
            "GET", "/web/api/v2.1/cloud-detection/rules", {"isLegacy": "true"})
        self.assertEqual("true", out["isLegacy"])


class UamWriteShape(unittest.TestCase):
    def setUp(self):
        self.skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        self.ref = (SKILL_DIR / "references" / "UNIFIED_ALERTS.md").read_text(
            encoding="utf-8")

    def test_mutation_and_action_ids_documented(self):
        self.assertIn("alertTriggerActions", self.skill)
        for action in ("S1/alert/addNote", "analystVerdictUpdate",
                       "statusUpdate"):
            self.assertIn(action, self.skill,
                          f"{action} is no longer documented in SKILL.md")

    def test_alert_id_is_the_filter_not_the_action_id(self):
        self.assertRegex(
            self.skill, r'fieldId:"id"|fieldId="id"|fieldId:\s*"id"',
            "the id-goes-in-the-filter shape is no longer spelled out")
        self.assertRegex(self.skill, r"(?i)the alert id is the FILTER")

    def test_write_must_be_verified_by_rereading(self):
        self.assertRegex(
            self.skill, r"(?i)always re-query|re-query \(",
            "SKILL.md no longer tells the reader to re-read after a write")
        self.assertIn("ActionsTriggered", self.skill)

    def test_action_catalogue_present_in_reference(self):
        self.assertIn("S1/alert/statusUpdate", self.ref)
        self.assertIn("S1/alert/analystVerdictUpdate", self.ref)


class PlatformRulesWorkingNotes(unittest.TestCase):
    """Platform-rule facts measured live on 3 consoles, 2026-10-09."""

    def setUp(self):
        text = (SKILL_DIR / "references" / "tags" /
                "Platform_Detection_Rules.md").read_text(encoding="utf-8")
        # Only the hand-written notes; the generated spec sections below repeat
        # upstream wording (for example "use cursor") that was measured false.
        self.notes = text.split("## `GET ", 1)[0]

    def test_settings_is_a_one_call_posture_read(self):
        self.assertIn("/detection-library/platform-rules/settings?scopeLevel=", self.notes)
        for field in ("disableInheritance", "inheritanceAvailable", "coreCount",
                      "autoDefaultCount", "emergingThreatCount", "smartDefault"):
            self.assertIn(field, self.notes, f"settings read no longer lists {field}")

    def test_paging_limits_are_stated(self):
        for frag in ("less than or equal to 1000", "4000080", "4000010",
                     "Invalid cursor value received", "nextCursor",
                     '400 "Unknown field"'):
            self.assertIn(frag, self.notes, f"paging note lost {frag!r}")

    def test_full_catalog_recipe_pages_by_severity(self):
        for sev in ("`Info`", "`Low`", "`Medium`", "`High`", "`Critical`"):
            self.assertIn(sev, self.notes)
        self.assertIn("skip=1000", self.notes)
        self.assertIn("pagination.totalItems", self.notes)
        self.assertRegex(self.notes, r"`sources`.*valid alternative")
        self.assertNotIn("To reach the full catalog, filter by `sources`", self.notes,
                         "the superseded sources-only full-catalog advice is back")

    def test_core_label_is_sentinelone_only(self):
        self.assertRegex(self.notes, r"(?i)no third-party rule carries `core`")
        self.assertRegex(self.notes, r"label `core` hides every third-party rule")
        self.assertIn("coreCount", self.notes)

    def test_inheritance_facts(self):
        self.assertIn("5000010", self.notes)
        self.assertIn('{"data":{"affected":1}}', self.notes)
        self.assertRegex(self.notes, r"own copy of every rule it inherited")
        self.assertRegex(self.notes, r"stayed `Disabled` at the account")

    def test_activation_and_ingest_timing(self):
        self.assertRegex(self.notes, r"`Activating`.*`Active` in 35 s")
        self.assertRegex(self.notes, r"only data ingested after the rule is `Active`")
        self.assertRegex(self.notes, r"back-dated 2 h")
        self.assertRegex(self.notes, r"ingest time, not the back-dated event time")

    def test_audit_activity_and_asset_binding(self):
        self.assertIn("activityTypes=3776", self.notes)
        self.assertIn("Platform Library Rule Enabled", self.notes)
        self.assertRegex(self.notes, r"Other Device.*`agentUuid: null`")


class UamQueryShapeFacts(unittest.TestCase):
    """UAM GraphQL facts measured live, 2026-10-09."""

    def setUp(self):
        self.ref = (SKILL_DIR / "references" / "UNIFIED_ALERTS.md").read_text(
            encoding="utf-8")

    def test_available_actions_scope_is_optional_but_changes_the_answer(self):
        # Corrected 2026-10-09: an unscoped call is NOT silently empty (15 actions on
        # 3 consoles); an empty list means the filter matched no visible alert.
        self.assertRegex(self.ref, r"`scope` is optional but changes the answer")
        self.assertIn("scope: {scopeIds, scopeType}", self.ref)
        self.assertNotRegex(self.ref, r"Without `scope` it returns `\{\"data\": \[\]",
                            "the refuted 'unscoped is silently empty' claim is back")

    def test_name_filter_and_sort_shape(self):
        self.assertIn('fieldId: "alertName", match: {value: [...]}', self.ref)
        self.assertIn("Field name does not exist or not supported for FILTER API call",
                      self.ref)
        self.assertIn("UnknownArgument", self.ref)
        self.assertIn('sort: {by: "<field>", order: ASC|DESC}', self.ref)
        self.assertIn("alerts(first, after, last, before, scope, viewType, sort, "
                      "filters, sorts, orFilter)", self.ref)
        self.assertIn("TriggerActionInput {id: ID!, payload: TriggerPayloadInput}",
                      self.ref)

    def test_sdl_graphql_rejects_introspection(self):
        self.assertIn("/sdl/v2/graphql", self.ref)
        self.assertRegex(self.ref, r"only `__typename` answers")

    def test_ai_investigation_availability_is_read_per_alert(self):
        self.assertIn("This alert type is not supported by AI investigations", self.ref)
        self.assertRegex(self.ref, r"do not infer it from severity")


class GetVsPostRule(unittest.TestCase):
    def test_nonexistent_post_paths_documented(self):
        skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        for bad in ("POST /web/api/v2.1/agents/ids",
                    "POST /web/api/v2.1/threats/summary",
                    "POST /web/api/v2.1/export/threats"):
            self.assertIn(bad, skill,
                          f"the never-call table no longer lists {bad}")
        self.assertIn("countOnly=true", skill)


class RecipeQueriesLintClean(unittest.TestCase):
    FILES = ("references/POWERQUERY_RECIPES.md",
             "references/detection-rules.md",
             "references/querying-logs.md")

    def _blocks(self):
        for rel in self.FILES:
            path = SKILL_DIR / rel
            if not path.is_file():
                continue
            for lang, body in FENCE.findall(path.read_text(encoding="utf-8")):
                if lang not in PQ_LANGS or COUNTER_EXAMPLE.search(body):
                    continue
                yield path, body

    @NEEDS_LINTER
    def test_recipes_pass_the_repo_linter(self):
        failures = []
        for path, body in self._blocks():
            probe = SENTINEL + body if body.lstrip().startswith("|") else body
            problems = LINTER.pq_problems(probe)
            if problems:
                failures.append(f"{path.relative_to(ROOT)}:\n"
                                f"{body.strip()[:200]}\n  -> "
                                + "; ".join(problems))
        self.assertEqual([], failures, "\n\n".join(failures))

    def test_some_recipes_were_actually_linted(self):
        self.assertGreaterEqual(sum(1 for _ in self._blocks()), 8)


class EvalSuiteIsGradable(unittest.TestCase):
    def setUp(self):
        self.path = SKILL_DIR / "evals" / "evals.json"
        self.suite = json.loads(self.path.read_text(encoding="utf-8"))

    @NEEDS_LINTER
    def test_structure_is_clean(self):
        errs = LINTER.check_structure(self.suite, self.path)
        self.assertEqual([], errs, "\n".join(errs))

    def test_every_case_has_assertions(self):
        for case in self.suite["evals"]:
            self.assertTrue(case.get("assertions"),
                            f"case {case.get('name')} grades nothing")

    def test_islegacy_is_covered_by_the_suite(self):
        blob = json.dumps(self.suite)
        self.assertIn("isLegacy", blob,
                      "no eval case asserts the isLegacy=false rule")


class AssetLinkageOnPlatformAlerts(unittest.TestCase):
    """Measured 2026-10-09: which event field links a platform alert to an endpoint."""

    def test_agent_uuid_links_and_moves_the_alert_to_the_agent_site(self):
        ref = (SKILL_DIR / "references" / "ASSET_LINKAGE.md").read_text(encoding="utf-8")
        self.assertRegex(ref, r"`agent.uuid` set to a real agent's UUID is enough to link")
        self.assertIn("belongs to the AGENT's site", ref)
        self.assertRegex(ref, r"real agent's hostname in `device.hostname` without `agent.uuid`")


if __name__ == "__main__":
    unittest.main()
