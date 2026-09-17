"""Structural tests for the `powerquery` skill. No network, no tenant.

These pin the things a careless edit would quietly break:

1. Every PowerQuery example in the skill's own markdown still passes the repo
   linter in `tools/run_evals.py`. The linter is imported, never reimplemented,
   so a new rule added there is enforced here on the next run.
2. The eval suite is structurally gradable and actually exercises `pq_valid`.
3. The detection-engineering section still documents the rule-type choice and
   the custom correlation-key shape, which is the part of this skill that is
   expensive to get wrong.

Run:
    python3 -m unittest discover -s powerquery/tests
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import unittest

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
ROOT = SKILL_DIR.parent


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

# Blocks that deliberately show a WRONG query. The repo annotates these with a
# left-arrow callout or a "# Wrong" style comment; linting them would assert the
# opposite of what the docs are teaching.
COUNTER_EXAMPLE = re.compile(r"←|^\s*(?:#|//)\s*(?:wrong|bad|do not|don't)\b",
                             re.I | re.M)

# `tools/run_evals.py` rejects a leading `|` outright. SKILL.md documents the
# empty-initial-filter form (`| group ct=count() by event.type`) as legal, and
# `| join` MUST start with a pipe. Prepending a sentinel predicate bypasses that
# one rule only; the rule is anchored to the start of the string, so every other
# rule still applies to the whole block.
SENTINEL = "event.time=*\n"

# Floor on how many blocks get linted. Without it, an over-broad skip rule could
# hollow the test out while it still reported green.
MIN_BLOCKS = 120


def _pq_blocks():
    files = [SKILL_DIR / "SKILL.md"]
    files += sorted((SKILL_DIR / "examples").glob("*.md"))
    files += sorted((SKILL_DIR / "references").glob("*.md"))
    for f in files:
        for lang, body in FENCE.findall(f.read_text(encoding="utf-8")):
            if lang not in PQ_LANGS:
                continue
            if COUNTER_EXAMPLE.search(body):
                continue
            yield f, body


class DocumentedQueriesLintClean(unittest.TestCase):
    @NEEDS_LINTER
    def test_examples_pass_the_repo_linter(self):
        failures = []
        for f, body in _pq_blocks():
            probe = SENTINEL + body if body.lstrip().startswith("|") else body
            problems = LINTER.pq_problems(probe)
            if problems:
                failures.append(
                    f"{f.relative_to(ROOT)}:\n{body.strip()[:200]}\n  -> "
                    + "; ".join(problems))
        self.assertEqual([], failures, "\n\n".join(failures))

    def test_enough_blocks_were_actually_linted(self):
        n = sum(1 for _ in _pq_blocks())
        self.assertGreaterEqual(
            n, MIN_BLOCKS,
            f"only {n} PowerQuery blocks linted; the skip rules have gone too "
            f"wide or the examples were deleted")


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
                      "a PowerQuery suite that never runs pq_valid is not "
                      "testing the syntax rules this skill exists for")


class DetectionEngineeringDocumented(unittest.TestCase):
    def setUp(self):
        self.skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")

    def test_rule_type_choice_documented(self):
        for token in ("`events`", "`correlation`", "`scheduled`"):
            self.assertIn(token, self.skill,
                          f"rule-type table no longer mentions {token}")

    def test_custom_correlation_key_shape_documented(self):
        self.assertIn("entitiesAndFields", self.skill)
        self.assertIn("list of lists", self.skill)
        self.assertRegex(self.skill, r"(?i)duplicate alias",
                         "the unique-alias constraint is no longer documented")

    def test_entity_binding_documented(self):
        self.assertIn("entityMappings", self.skill)
        self.assertRegex(self.skill, r"(?i)unknown device")

    def test_banned_sort_and_head_forms_documented(self):
        self.assertRegex(self.skill, r"sort\s+count\s+desc")
        self.assertRegex(self.skill, r"(?i)\bnot a valid initial filter\b|"
                                     r"\*\* alone is NOT a valid initial filter")


if __name__ == "__main__":
    unittest.main()
