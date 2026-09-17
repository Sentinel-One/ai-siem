"""Structural tests for the `mgmt-console-api` skill. No network, no tenant.

These pin the rules that have cost real time on this API:

1. `isLegacy=false` on GET /cloud-detection/rules. Omitting it returns a WRONG
   result set, not a smaller one: every scheduled PowerQuery rule is dropped
   with no error. Both the documentation and the client-side guard are pinned.
2. UAM writes go through `alertTriggerActions`, with the alert id in the FILTER
   and never as the action `id`, and the write is verified by re-reading.
3. The PowerQuery recipes shipped with this skill still pass the repo linter in
   `tools/run_evals.py`, which is imported rather than reimplemented.

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


if __name__ == "__main__":
    unittest.main()
