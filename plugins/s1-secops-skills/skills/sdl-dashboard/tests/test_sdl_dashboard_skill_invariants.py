"""Structural tests for the `sdl-dashboard` skill. No network, no tenant.

`test_panel_safety_check.py` alongside this file covers the two site-scope
rules in depth. This file covers the rest of the skill's contract, which is
the set of rendering defects that the API accepts silently:

1. A markdown panel needs its body under `markdown:`. Under `content:` the
   panel mounts and draws nothing, with no error anywhere.
2. `transpose` is the terminal command; anything after it fails the render.
3. The PowerQuery parser reads `total-min` as one identifier, so arithmetic
   needs spaces.
4. A number panel must terminate with `| limit 1`.
5. Bucket size must match the dashboard window.

Each of those is asserted twice over: that `SKILL.md` still documents it, and
that `scripts/panel_safety_check.py` still detects it. Documentation without a
detector rots; a detector without documentation cannot be acted on.

The PowerQuery linter is imported from `tools/run_evals.py`, never copied.

Run:
    python3 -m unittest discover -s sdl-dashboard/tests
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

import panel_safety_check as psc  # noqa: E402


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
MIN_PQ_BLOCKS = 50


def dash(*panels):
    return {"configType": "TABBED", "tabs": [{"tabName": "t", "graphs": list(panels)}]}


def ids(issues):
    return sorted({rule_id for rule_id, _, _ in issues})


LAYOUT = {"x": 0, "y": 0, "w": 30, "h": 10}


class RenderingPitfallsAreStillDetected(unittest.TestCase):
    """Every documented silent-render defect keeps a working detector."""

    def test_M01_markdown_body_under_content_is_flagged(self):
        d = dash({"graphStyle": "markdown", "title": "hdr",
                  "content": "this renders as a blank tile", "layout": LAYOUT})
        self.assertIn("M01", ids(psc.check(d, [])))

    def test_M01_does_not_fire_on_the_correct_markdown_key(self):
        d = dash({"graphStyle": "markdown", "title": "hdr",
                  "markdown": "this renders", "layout": LAYOUT})
        self.assertNotIn("M01", ids(psc.check(d, [])))

    def test_P01_command_after_transpose_is_flagged(self):
        q = ("dataSource.name='alert' | group c=count() by timestamp=timebucket('1h'), "
             "sev=severity_id | transpose sev on timestamp | limit 20")
        d = dash({"graphStyle": "stacked_bar", "title": "t", "query": q, "layout": LAYOUT})
        self.assertIn("P01", ids(psc.check(d, [])))

    def test_P01_does_not_fire_when_transpose_is_terminal(self):
        q = ("dataSource.name='alert' | group c=count() by timestamp=timebucket('1h'), "
             "sev=severity_id | transpose sev on timestamp")
        d = dash({"graphStyle": "stacked_bar", "title": "t", "query": q, "layout": LAYOUT})
        self.assertNotIn("P01", ids(psc.check(d, [])))

    def test_P02_unspaced_hyphen_arithmetic_is_flagged(self):
        q = "dataSource.name='alert' | let spread = max-min | limit 1"
        d = dash({"graphStyle": "number", "title": "n", "query": q, "layout": LAYOUT})
        self.assertIn("P02", ids(psc.check(d, [])))

    def test_P02_scans_expression_stages_after_the_first(self):
        # Regression guard. The segment terminator used to CONSUME the pipe that
        # starts the next stage, so in this shape only the `group` was scanned
        # and `max-min` in the trailing `let` sailed through unflagged.
        q = ("dataSource.name='alert' | group total=count(), min=min(severity_id), "
             "max=max(severity_id) | let spread = max-min | limit 1")
        d = dash({"graphStyle": "number", "title": "n", "query": q, "layout": LAYOUT})
        self.assertIn("P02", ids(psc.check(d, [])))

    def test_P02_accepts_the_spaced_form(self):
        q = ("dataSource.name='alert' | group total=count(), min=min(severity_id), "
             "max=max(severity_id) | let spread = max - min | limit 1")
        d = dash({"graphStyle": "number", "title": "n", "query": q, "layout": LAYOUT})
        self.assertNotIn("P02", ids(psc.check(d, [])))

    def test_P02_does_not_flag_hyphens_inside_string_literals(self):
        # A hyphenated LABEL is not arithmetic. Flagging it would train people
        # to ignore the rule.
        q = ("dataSource.name='alert' | group c=count() by "
             "kind='command-and-control' | limit 25")
        d = dash({"graphStyle": "table", "title": "t", "query": q, "layout": LAYOUT})
        self.assertNotIn("P02", ids(psc.check(d, [])))

    def test_N01_number_panel_without_limit_1_is_flagged(self):
        d = dash({"graphStyle": "number", "title": "n",
                  "query": "dataSource.name='alert' | group c=count()", "layout": LAYOUT})
        self.assertIn("N01", ids(psc.check(d, [])))

    def test_N01_accepts_a_terminating_limit_1(self):
        d = dash({"graphStyle": "number", "title": "n",
                  "query": "dataSource.name='alert' | group c=count() | limit 1",
                  "layout": LAYOUT})
        self.assertNotIn("N01", ids(psc.check(d, [])))

    def test_Q01_area_panel_driven_by_a_query_is_flagged(self):
        d = dash({"graphStyle": "area", "title": "t",
                  "query": "dataSource.name='alert' | group c=count() | limit 1",
                  "layout": LAYOUT})
        self.assertIn("Q01", ids(psc.check(d, [])))

    def test_L01_missing_layout_is_flagged(self):
        d = dash({"graphStyle": "number", "title": "n",
                  "query": "dataSource.name='alert' | group c=count() | limit 1"})
        self.assertIn("L01", ids(psc.check(d, [])))

    def test_the_documented_rule_ids_all_still_exist(self):
        for name in ("rule_L01", "rule_Q01", "rule_M01",
                     "rule_P01_transpose_not_terminal", "rule_P02_hyphen_arith",
                     "rule_N01_number_no_limit", "rule_N02_table_no_limit",
                     "rule_S01_site_scope_missing", "rule_S02_site_name_as_scope"):
            self.assertTrue(callable(getattr(psc, name, None)),
                            f"panel_safety_check.{name} is gone; SKILL.md still "
                            f"tells the user to run it")


class SkillDocumentsThePitfalls(unittest.TestCase):
    """A detector nobody is told about does not change behaviour."""

    def setUp(self):
        self.skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")

    def test_markdown_key_is_named_explicitly(self):
        self.assertRegex(
            self.skill, r"(?i)`markdown:`\s*\(NOT\s*`content:`\)",
            "the markdown-vs-content fix is no longer spelled out")

    def test_transpose_terminal_error_is_quoted_verbatim(self):
        self.assertIn('"transpose" can only be used as the last command in a query',
                      self.skill)

    def test_hyphenated_arithmetic_is_documented(self):
        self.assertRegex(self.skill, r"(?i)is ambiguous")
        self.assertIn("total - min", self.skill)

    def test_number_panel_limit_rule_is_documented(self):
        self.assertRegex(
            self.skill,
            r"(?i)terminate number panels with[^\n]{0,20}limit 1",
            "the `| limit 1` rule for number panels is gone")

    def test_bucket_sizing_rule_is_documented(self):
        self.assertRegex(self.skill, r"(?i)match bucket to duration")
        self.assertIn("timebucket", self.skill)

    def test_safety_check_is_still_a_mandatory_workflow_step(self):
        self.assertIn("scripts/panel_safety_check.py", self.skill)
        self.assertTrue((SKILL_DIR / "scripts" / "panel_safety_check.py").is_file())

    def test_every_reference_file_named_in_the_skill_exists(self):
        # Targets are relative to the skill directory and may cross into a
        # sibling skill (`../sdl-api/references/...`), so resolve rather than
        # assuming `references/` under this skill.
        named = set(re.findall(
            r"((?:\.\./)?(?:[A-Za-z0-9._-]+/)?references/[A-Za-z0-9._-]+\.md)",
            self.skill))
        self.assertTrue(named, "SKILL.md no longer points at any reference file")

        def _sibling_variants(n: str):
            head, _, tail = n.lstrip("./").partition("/")
            if not tail:
                return
            for alt in (f"sentinelone-{head}", head.replace("sentinelone-", "", 1)):
                yield ROOT / alt / tail

        def resolves(n: str) -> bool:
            return ((SKILL_DIR / n).is_file() or (ROOT / n).is_file()
                    or any(c.is_file() for c in _sibling_variants(n)))

        missing = [n for n in sorted(named) if not resolves(n)]
        self.assertEqual([], missing,
                         "SKILL.md points at reference files that do not exist: "
                         + ", ".join(missing))


class ShippedExampleStaysClean(unittest.TestCase):
    """The example dashboard is what people copy. It must pass its own check."""

    def setUp(self):
        self.path = SKILL_DIR / "examples" / "panel-showcase.json"

    def test_example_parses_as_strict_json(self):
        json.loads(self.path.read_text(encoding="utf-8"))

    def test_example_passes_panel_safety_check(self):
        d = json.loads(self.path.read_text(encoding="utf-8"))
        issues = psc.check(d, [])
        self.assertEqual([], issues,
                         "the shipped example now trips its own safety check: "
                         + "; ".join(f"{i[0]} {i[1]}" for i in issues))


class DocumentedQueriesLintClean(unittest.TestCase):
    def _blocks(self):
        files = [SKILL_DIR / "SKILL.md"]
        files += sorted((SKILL_DIR / "references").glob("*.md"))
        for f in files:
            for lang, body in FENCE.findall(f.read_text(encoding="utf-8")):
                if lang not in PQ_LANGS or COUNTER_EXAMPLE.search(body):
                    continue
                yield f, body

    @NEEDS_LINTER
    def test_examples_pass_the_repo_linter(self):
        failures = []
        for f, body in self._blocks():
            probe = SENTINEL + body if body.lstrip().startswith("|") else body
            problems = LINTER.pq_problems(probe)
            if problems:
                failures.append(f"{f.relative_to(ROOT)}:\n{body.strip()[:200]}\n  -> "
                                + "; ".join(problems))
        self.assertEqual([], failures, "\n\n".join(failures))

    def test_enough_blocks_were_actually_linted(self):
        n = sum(1 for _ in self._blocks())
        self.assertGreaterEqual(
            n, MIN_PQ_BLOCKS,
            f"only {n} PowerQuery blocks linted; the skip rules have gone too "
            f"wide or the references were gutted")


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

    def test_suite_exercises_the_pq_linter(self):
        kinds = {a["type"] for c in self.suite["evals"] for a in c["assertions"]}
        self.assertIn("pq_valid", kinds,
                      "a dashboard suite that never runs pq_valid is not testing "
                      "the queries the panels are built from")

    def test_rendering_pitfalls_are_covered_by_the_suite(self):
        blob = json.dumps(self.suite)
        for token in ("markdown", "transpose", "timebucket", "site.id"):
            self.assertIn(token, blob,
                          f"no eval case mentions {token}; the pitfall it guards "
                          f"is untested")


if __name__ == "__main__":
    unittest.main()
