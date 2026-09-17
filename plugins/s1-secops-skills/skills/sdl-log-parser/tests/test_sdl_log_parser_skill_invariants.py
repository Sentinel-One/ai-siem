"""Structural tests for the `sdl-log-parser` skill. No network, no tenant.

These pin the facts a careless edit would erase, each with a concrete failure
attached:

1. Gate 0. The SDL parser sees exactly two attributes, `message` and `parser`,
   and that decides whether authoring a parser is possible at all. Lose the
   gate and the skill happily writes a parser for a source it can never run on.
2. The two hard rules on every parser: `dataSource.category` hardcoded to
   `"security"`, and a semver `metadata.version`. Both are enforced against the
   shipped `examples/` so a new example cannot regress them.
3. The key=value catch-all needs its leading `.*`. Without it the format
   anchors at position 0 and captures nothing, silently, on any line that
   starts with a syslog priority, a CEF header or a timestamp.
4. `severity` is reserved and coerced to a 0-6 integer, so the raw string goes
   into `severity_name`.
5. The eval suite is structurally gradable and every case grades something.

The PowerQuery linter is imported from `tools/run_evals.py`, never copied, so a
rule added there is enforced here on the next run.

Run:
    python3 -m unittest discover -s sdl-log-parser/tests
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
COUNTER_EXAMPLE = re.compile(r"←|^\s*(?:#|//)\s*(?:wrong|bad|do not|don't)\b",
                             re.I | re.M)
# `tools/run_evals.py` has no rule against a leading `|`, but a block that opens
# with one has no initial predicate to lint against, so prepend a sentinel. The
# bare-`*` rule is anchored to the start of the string; every other rule still
# applies to the whole block.
SENTINEL = "event.time=*\n"

# Floor on how many blocks get linted, so an over-broad skip rule cannot hollow
# the test out while it still reports green.
MIN_PQ_BLOCKS = 8

# The canonical key=value catch-all, verbatim from the built-in `keyValue`
# parser. The leading `.*` is the load-bearing part.
KV_CATCHALL = "$_=identifier$=$_=quoteOrSpace$"


def _example_files():
    return sorted((SKILL_DIR / "examples").glob("*.json"))


class GateZeroIsDocumented(unittest.TestCase):
    """Gate 0 decides whether a parser can run at all. It must survive edits."""

    def setUp(self):
        self.skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        self.ref = (SKILL_DIR / "references"
                    / "parser-eligibility.md").read_text(encoding="utf-8")

    def test_gate_zero_section_exists(self):
        self.assertRegex(self.skill, r"(?im)^##\s*Gate 0\b",
                         "the Gate 0 section is gone from SKILL.md")

    def test_the_two_visible_attributes_are_named(self):
        self.assertRegex(
            self.skill,
            r"(?i)parser sees (?:exactly )?\*\*?two\*\*? attributes",
            "the 'parser sees exactly two attributes' rule is no longer stated")
        for token in ("`message`", "`parser`"):
            self.assertIn(token, self.skill)

    def test_all_four_eligibility_cases_are_covered(self):
        for pattern in (
            r"(?i)`parser`\s*and\s*`message`\s*both present",
            r"(?i)`message`\s*present,\s*`parser`\s*absent",
            r"(?i)neither present",
            r"(?i)already parsed in DPM",
        ):
            self.assertRegex(self.skill, pattern,
                             f"Gate 0 no longer covers /{pattern}/")

    def test_dpm_is_the_documented_escape_hatch(self):
        self.assertIn("Data Pipeline Management", self.skill)
        self.assertIn("Data Pipeline Management", self.ref)

    def test_reference_is_linked_from_the_skill(self):
        self.assertIn("references/parser-eligibility.md", self.skill)
        self.assertTrue((SKILL_DIR / "references" / "parser-eligibility.md").is_file())

    def test_absent_field_idiom_keeps_its_parentheses(self):
        # Bare `!field` matches EVERY row. Losing the parentheses turns the
        # eligibility probe into a report that the whole source is broken.
        self.assertIn("!(field = *)", self.ref)
        self.assertRegex(self.ref, r"(?i)bare\s+`?!field`?\s+matches every row")

    @NEEDS_LINTER
    def test_probe_queries_pass_the_repo_linter(self):
        failures = []
        for lang, body in FENCE.findall(self.ref):
            if lang not in PQ_LANGS or COUNTER_EXAMPLE.search(body):
                continue
            probe = SENTINEL + body if body.lstrip().startswith("|") else body
            problems = LINTER.pq_problems(probe)
            if problems:
                failures.append(f"{body.strip()[:120]} -> " + "; ".join(problems))
        self.assertEqual([], failures, "\n".join(failures))


class TwoHardRulesHold(unittest.TestCase):
    """`dataSource.category` = security and a semver `metadata.version`."""

    CAT = re.compile(r'"?dataSource\.category"?\s*:\s*"([^"]+)"')
    VER = re.compile(r'"?metadata\.version"?\s*:\s*"(\d+\.\d+\.\d+[^"]*)"')

    def setUp(self):
        self.skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")

    def test_rule_is_still_stated_in_the_skill(self):
        self.assertRegex(
            self.skill,
            r'(?i)`?dataSource\.category`?[^.\n]{0,60}(?:is fixed at|hardcoded to|'
            r'MUST always be hardcoded to)[^.\n]{0,20}"?`?security',
            "the category-is-always-security rule is no longer stated")
        self.assertRegex(
            self.skill,
            r"(?i)`metadata\.version`[^.\n]{0,60}(?:mandatory|semver)",
            "the metadata.version rule is no longer stated")

    def test_every_example_parser_carries_both(self):
        missing = []
        for f in _example_files():
            text = f.read_text(encoding="utf-8")
            if "aliasTo" in text:
                # An alias parser delegates wholesale to a built-in and carries
                # no attributes block of its own. That is the documented shape.
                continue
            cat = self.CAT.search(text)
            ver = self.VER.search(text)
            if not cat or cat.group(1) != "security":
                missing.append(f"{f.name}: dataSource.category = "
                               f"{cat.group(1) if cat else '<absent>'}")
            if not ver:
                missing.append(f"{f.name}: metadata.version absent or not semver")
        self.assertEqual([], missing, "\n".join(missing))

    def test_the_example_set_was_not_emptied(self):
        self.assertGreaterEqual(len(_example_files()), 10,
                                "the shipped parser examples have gone missing")


class KeyValueCatchAllKeepsItsLeadingDotStar(unittest.TestCase):
    def test_rule_is_documented(self):
        skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn(".*" + KV_CATCHALL, skill,
                      "the canonical catch-all with its leading `.*` is gone")
        self.assertRegex(skill, r"(?i)REQUIRES?\s+(?:a\s+)?leading\s+`?\.\*`?")

    def test_no_example_ships_the_unanchored_form(self):
        bad = []
        for f in _example_files():
            text = f.read_text(encoding="utf-8")
            for m in re.finditer(re.escape(KV_CATCHALL), text):
                if not text[max(0, m.start() - 2):m.start()] == ".*":
                    bad.append(f"{f.name}: catch-all at offset {m.start()} has no "
                               f"leading `.*`; it will capture nothing")
        self.assertEqual([], bad, "\n".join(bad))


class ReservedSeverityHandling(unittest.TestCase):
    def test_severity_is_documented_as_reserved(self):
        skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        self.assertRegex(skill, r"(?i)`severity`\s+is\s+a?\s*RESERVED field")
        self.assertIn("severity_name", skill)
        self.assertRegex(skill, r"(?i)never emit both `severity` and `severity_id`")

    def test_no_example_emits_a_bare_severity_capture(self):
        bad = []
        for f in _example_files():
            text = f.read_text(encoding="utf-8")
            if re.search(r"\$severity(?:\$|\{|=)", text):
                bad.append(f.name)
        self.assertEqual([], bad,
                         "these examples capture into the reserved `severity` "
                         "field instead of `severity_name`: " + ", ".join(bad))


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

    def test_every_referenced_sample_file_exists(self):
        for case in self.suite["evals"]:
            for rel in case.get("files") or []:
                self.assertTrue((SKILL_DIR / rel).is_file(),
                                f"{case['name']} references missing sample {rel}")

    def test_eligibility_gate_is_covered_by_the_suite(self):
        blob = json.dumps(self.suite)
        self.assertIn("Data Pipeline Management", blob,
                      "no eval covers the DPM steer, which is the whole point "
                      "of Gate 0")
        self.assertIn("!(", blob,
                      "no eval pins the parenthesised absent-field idiom")

    def test_suite_exercises_the_pq_linter(self):
        kinds = {a["type"] for c in self.suite["evals"] for a in c["assertions"]}
        self.assertIn("pq_valid", kinds)


if __name__ == "__main__":
    unittest.main()
