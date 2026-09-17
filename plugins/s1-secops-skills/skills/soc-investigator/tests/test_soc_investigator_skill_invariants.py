"""Structural tests for the `soc-investigator` skill. No network, no tenant.

The value of this skill is what it refuses to say. Everything below pins one of
those refusals, or the machinery that makes a refusal checkable:

1. The verdict gate. A detection-engine severity, even CRITICAL, is a
   hypothesis. Without one of the three confirmations the ceiling is
   SUSPICIOUS - Pending Confirmation. Losing the ceiling phrase is how the skill
   quietly starts calling engine output a true positive again.
2. Notes and history are read FIRST, and a recorded MDR or analyst verdict takes
   precedence. This is the documented lesson-learned, kept with its worked case
   so it reads as evidence and not as a slogan.
3. Enrichment is external-only. RFC1918 and no-external-indicator cases are
   enrichment-not-applicable and must say so; a fabricated lookup is the worst
   failure this skill can produce, because it is unfalsifiable downstream.
4. The confidence ladder keeps all five rungs. A ladder missing its weak rungs
   pushes every finding upward.
5. The query appendix is mandatory in every report, with all five per-query
   fields, and empty results are recorded rather than curated away.
6. Every documented PowerQuery still passes the repo linter.
7. The eval suite is gradable, and it still contains the two refusal cases and
   the no-fabrication case that are the point of having a suite here at all.

The PowerQuery linter is imported from `tools/run_evals.py`, never copied.

Run:
    python3 -m unittest discover -s soc-investigator/tests
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import unittest

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
ROOT = SKILL_DIR.parent
REFS = SKILL_DIR / "references"


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

SKILL = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
DISCIPLINE = (REFS / "evidence-and-verdict-discipline.md").read_text(
    encoding="utf-8")
MODES = (REFS / "investigation-modes.md").read_text(encoding="utf-8")
SWEEP = (REFS / "ttp-sweep.md").read_text(encoding="utf-8")

FENCE = re.compile(r"^```(\w*)\n(.*?)^```", re.M | re.S)
PQ_LANGS = {"text", "powerquery", "pq"}
# Most `text` fences in this skill are console UI mock-ups, not queries.
PQ_COMMAND = re.compile(
    r"\|\s*(?:group|filter|columns|sort|limit|lookup|let|parse|join|savelookup"
    r"|dataset|top|transpose|nolimit)\b")
MIN_PQ_BLOCKS = 4

LADDER = ("confirmed", "consistent with", "suggests", "possible",
          "no evidence of")


class VerdictGate(unittest.TestCase):
    def test_engine_severity_alone_is_never_enough(self):
        for text, where in ((SKILL, "SKILL.md"),
                            (DISCIPLINE, "evidence-and-verdict-discipline.md")):
            self.assertRegex(
                text, r"(?i)detection[- ]engine severity alone|on a "
                      r"detection-engine severity alone|engine severity alone",
                f"{where} no longer states that an engine severity alone "
                f"cannot produce a CRITICAL or TRUE POSITIVE verdict")

    def test_the_three_confirmations_are_all_present(self):
        for pattern, what in (
                (r"(?i)threat[- ]intel", "threat-intel confirmation"),
                (r"(?i)MDR", "MDR / analyst confirmation"),
                (r"(?i)2\+ (?:independent|unrelated) sources|multi-source",
                 "multi-source corroboration")):
            self.assertRegex(DISCIPLINE, pattern,
                             f"the gate lost its {what} branch")

    def test_the_ceiling_phrase_survives_verbatim(self):
        for text, where in ((SKILL, "SKILL.md"),
                            (DISCIPLINE, "evidence-and-verdict-discipline.md")):
            self.assertRegex(
                text, r"SUSPICIOUS\s*[-–—]\s*Pending Confirmation",
                f"{where} lost the ceiling classification; without a named "
                f"ceiling there is nothing to cap an unconfirmed finding at")

    def test_the_worked_lesson_is_kept_not_just_the_rule(self):
        self.assertRegex(
            DISCIPLINE, r"(?i)Lesson learned",
            "the worked case (a CRITICAL Fileless PowerShell/ransomware alert "
            "called a true positive on engine classification alone, later "
            "confirmed False Positive - Benign) has been cut; the rule without "
            "its case reads as a slogan and gets waived")
        self.assertRegex(DISCIPLINE, r"(?i)False Positive - Benign")

    def test_true_positive_benign_is_treated_like_a_false_positive(self):
        self.assertIn("TRUE_POSITIVE_BENIGN", DISCIPLINE)
        self.assertRegex(DISCIPLINE, r"(?i)do\s*\n?not override without new "
                                     r"evidence")


class NotesAndHistoryComeFirst(unittest.TestCase):
    def test_both_calls_are_named(self):
        for text, where in ((SKILL, "SKILL.md"),
                            (DISCIPLINE, "evidence-and-verdict-discipline.md")):
            self.assertIn("get_alert_notes", text, where)
            self.assertIn("get_alert_history", text, where)

    def test_they_are_ordered_before_the_investigation(self):
        self.assertRegex(
            DISCIPLINE, r"(?i)check `get_alert_notes` and `get_alert_history` "
                        r"FIRST",
            "the ordering (notes and history BEFORE investigating) is gone; "
            "read late, an MDR verdict arrives after the analysis has already "
            "committed to a conclusion")

    def test_precedence_is_explicit(self):
        for text, where in ((SKILL, "SKILL.md"),
                            (DISCIPLINE, "evidence-and-verdict-discipline.md")):
            self.assertRegex(text, r"(?i)takes precedence", where)


class EnrichmentIsExternalOnlyAndNeverFabricated(unittest.TestCase):
    def test_rfc1918_is_enrichment_not_applicable(self):
        for text, where in ((SKILL, "SKILL.md"),
                            (DISCIPLINE, "evidence-and-verdict-discipline.md")):
            self.assertRegex(text, r"(?i)RFC1918", where)
            self.assertRegex(
                text, r"(?i)enrichment-N/A",
                f"{where} no longer marks internal-only indicators as "
                f"enrichment-N/A")

    def test_fabricating_a_lookup_is_prohibited_in_words(self):
        for text, where in ((SKILL, "SKILL.md"),
                            (DISCIPLINE, "evidence-and-verdict-discipline.md")):
            self.assertRegex(
                text, r"(?i)never fabricate a lookup",
                f"{where} lost the explicit prohibition on inventing an "
                f"enrichment result")

    def test_declining_enrichment_caps_the_verdict(self):
        self.assertRegex(
            SKILL, r"(?i)opt-in",
            "external enrichment is opt-in because indicators leave the "
            "tenant; that framing is gone")
        self.assertRegex(
            SKILL, r"(?i)cap the verdict at SUSPICIOUS",
            "the consequence of skipping enrichment (the verdict is capped, "
            "not silently unaffected) has been removed")

    def test_no_fabrication_rule_covers_counts_and_names(self):
        self.assertRegex(DISCIPLINE, r"(?i)Empty, null, and zero results are "
                                     r"findings")
        self.assertRegex(DISCIPLINE, r"(?i)Tool errors are findings")


class ConfidenceLadderKeepsEveryRung(unittest.TestCase):
    def test_all_five_rungs_are_present(self):
        low = DISCIPLINE.lower()
        for rung in LADDER:
            self.assertIn(rung, low,
                          f"the confidence ladder lost the `{rung}` rung; a "
                          f"ladder missing its weak rungs pushes every finding "
                          f"upward")

    def test_confirmed_requires_two_sources_and_positive_intel(self):
        row = re.search(r"\|\s*Confirmed\s*\|([^|]*)\|", DISCIPLINE)
        self.assertIsNotNone(row, "the `Confirmed` row of the ladder is gone")
        self.assertRegex(row.group(1), r"(?i)2\+")
        self.assertRegex(row.group(1), r"(?i)threat intel")

    def test_the_skill_repeats_the_ladder(self):
        for rung in LADDER:
            self.assertIn(rung, SKILL.lower(),
                          f"SKILL.md no longer names the `{rung}` rung")


class QueryAppendixIsMandatory(unittest.TestCase):
    def test_it_is_required_of_every_report(self):
        self.assertRegex(SKILL, r"(?i)Query appendix \(mandatory in every "
                                r"report\)")
        self.assertRegex(SKILL, r"(?i)non-negotiable and applies to all modes")

    def test_all_five_per_query_fields_survive(self):
        block = SKILL[SKILL.index("## Query appendix"):]
        for field in ("Purpose", "Query", "Scope", "Result", "Evidence"):
            self.assertRegex(
                block, rf"(?m)^- {field}:",
                f"the appendix no longer requires `{field}` per query, so a "
                f"peer cannot reproduce the result")

    def test_empty_results_are_recorded_not_curated(self):
        block = SKILL[SKILL.index("## Query appendix"):]
        self.assertRegex(block, r"(?i)0 rows / empty")
        self.assertRegex(
            block, r"(?i)Do not curate down to only the \"?interesting\"? ones",
            "the ban on curating the appendix to the interesting queries is "
            "gone, which is how a negative result quietly disappears")

    def test_every_mode_produces_a_report_that_carries_it(self):
        for artifact in ("summary.md", "report.md", "full_report.md",
                         "sweep_report.md", "third_party_report.md"):
            self.assertIn(artifact, SKILL,
                          f"{artifact} is no longer named in the appendix "
                          f"scope, so that mode's output escapes the rule")


class ModesAndReferencesResolve(unittest.TestCase):
    def test_every_reference_named_in_the_skill_exists(self):
        named = set(re.findall(
            r"((?:\.\./)?(?:[A-Za-z0-9._-]+/)?references/[A-Za-z0-9._-]+\.md)",
            SKILL))
        self.assertTrue(named, "SKILL.md no longer points at any reference")
        missing = [n for n in sorted(named)
                   if not ((SKILL_DIR / n).is_file() or (ROOT / n).is_file())]
        self.assertEqual([], missing,
                         "SKILL.md points at references that do not exist: "
                         + ", ".join(missing))

    def test_no_orphan_references(self):
        named = set(re.findall(r"references/([A-Za-z0-9._-]+\.md)", SKILL))
        orphans = sorted(p.name for p in REFS.glob("*.md") if p.name not in named)
        self.assertEqual([], orphans,
                         "reference files exist that SKILL.md never loads: "
                         + ", ".join(orphans))

    def test_all_three_modes_are_documented_in_both_places(self):
        for mode in ("SHORT", "MEDIUM", "LONG"):
            self.assertIn(mode, SKILL, f"SKILL.md lost the {mode} mode")
            self.assertRegex(
                MODES, rf"(?m)^## Workflow: {mode} Mode",
                f"investigation-modes.md has no run instructions for {mode}, "
                f"so the mode is advertised and unrunnable")

    def test_modes_are_cumulative(self):
        self.assertRegex(MODES, r"(?i)MEDIUM includes SHORT, and LONG includes "
                                r"MEDIUM")


class DocumentedQueriesLintClean(unittest.TestCase):
    def _blocks(self):
        for f in [SKILL_DIR / "SKILL.md"] + sorted(REFS.glob("*.md")):
            for lang, body in FENCE.findall(f.read_text(encoding="utf-8")):
                if lang in PQ_LANGS and PQ_COMMAND.search(body):
                    yield f, body

    @NEEDS_LINTER
    def test_examples_pass_the_repo_linter(self):
        failures = []
        for f, body in self._blocks():
            problems = LINTER.pq_problems(body)
            if problems:
                failures.append(f"{f.relative_to(ROOT)}:\n"
                                f"{body.strip()[:200]}\n  -> "
                                + "; ".join(problems))
        self.assertEqual([], failures, "\n\n".join(failures))

    def test_enough_blocks_were_actually_linted(self):
        n = sum(1 for _ in self._blocks())
        self.assertGreaterEqual(
            n, MIN_PQ_BLOCKS,
            f"only {n} PowerQuery blocks linted; the skip rules have gone too "
            f"wide or the mode instructions were gutted")

    def test_the_syntax_rules_the_linter_enforces_are_also_written_down(self):
        for pattern in (r"\|\s*head N", r"sort field desc", r"bare `\*`"):
            self.assertRegex(
                DISCIPLINE, pattern,
                "the PowerQuery syntax rules section has lost a rule the "
                "repo linter still enforces")


class EvalSuiteIsGradable(unittest.TestCase):
    def setUp(self):
        self.path = SKILL_DIR / "evals" / "evals.json"
        self.suite = json.loads(self.path.read_text(encoding="utf-8"))
        self.blob = json.dumps(self.suite)

    @NEEDS_LINTER
    def test_structure_is_clean(self):
        errs = LINTER.check_structure(self.suite, self.path)
        self.assertEqual([], errs, "\n".join(errs))

    def test_every_case_has_assertions(self):
        for case in self.suite["evals"]:
            self.assertTrue(case.get("assertions"),
                            f"case {case.get('name')} grades nothing")

    def test_the_suite_grades_verdicts_structurally(self):
        kinds = {a["type"] for c in self.suite["evals"] for a in c["assertions"]}
        for kind in ("json_parses", "file_json_path", "pq_valid"):
            self.assertIn(
                kind, kinds,
                f"a verdict suite that never uses {kind} is grading prose")

    def test_at_least_two_cases_forbid_an_unsupported_escalation(self):
        """The refusals are the point; they must not be edited out."""
        refusals = 0
        for case in self.suite["evals"]:
            forbids_tp = any(
                a["type"] == "file_matches" and a.get("count") == 0
                and re.search(r"true\[ _-\]positive", a["pattern"], re.I)
                for a in case["assertions"])
            if forbids_tp:
                refusals += 1
        self.assertGreaterEqual(
            refusals, 2,
            "fewer than two cases assert that a TRUE POSITIVE verdict is NOT "
            "written; without them the suite never checks the refusal this "
            "skill exists for")

    def test_a_case_forbids_a_fabricated_enrichment_result(self):
        fabricated = [
            c["name"] for c in self.suite["evals"]
            for a in c["assertions"]
            if a["type"] == "file_matches" and a.get("count") == 0
            and re.search(r"malicious|/\\s\*\(\?:70\|72", a["pattern"])]
        self.assertTrue(
            fabricated,
            "no case asserts the absence of an invented detection ratio or "
            "malicious count, so a hallucinated threat-intel result would "
            "grade as a pass")

    def test_the_ceiling_and_the_mdr_precedence_are_both_exercised(self):
        self.assertRegex(self.blob, r"(?i)pending confirmation")
        self.assertRegex(self.blob, r"(?i)\bMDR\b")

    def test_a_case_still_earns_a_confirmed_true_positive(self):
        """A suite that can only refuse is as broken as one that never does."""
        earns = [c["name"] for c in self.suite["evals"]
                 for a in c["assertions"]
                 if a["type"] == "file_json_path" and a["path"] == "verdict"
                 and re.search(r"true", a.get("matches", ""), re.I)]
        self.assertTrue(
            earns,
            "no case asserts a TRUE POSITIVE verdict on strong evidence; a "
            "suite that only rewards refusal teaches the skill to hedge")


class SweepModeIsRunnableAndHonest(unittest.TestCase):
    def test_the_mode_is_advertised_and_documented(self):
        self.assertIn("SWEEP", SKILL, "SKILL.md lost the SWEEP mode")
        self.assertRegex(
            SWEEP, r"(?m)^## Phase 0",
            "ttp-sweep.md has no run instructions, so the mode is advertised "
            "and unrunnable")

    def test_sweep_is_declared_a_peer_not_a_cumulative_step(self):
        self.assertRegex(
            SKILL + MODES, r"(?i)SWEEP is a peer",
            "without this, SWEEP gets read as cumulative with LONG and an "
            "operator waits for alert phases that never run")

    def test_bracketed_attack_fields_are_warned_against(self):
        self.assertRegex(
            SWEEP, r"finding_info\.attacks\[0\]",
            "the HTTP 400 trap on bracketed array fields is undocumented; the "
            "quoted-name workaround fails silently and looks like a result")
        self.assertRegex(SWEEP, r"(?i)400")

    def test_suppression_pass_exists_and_cannot_delete_evidence(self):
        self.assertRegex(SWEEP, r"(?i)simulation")
        self.assertRegex(
            SWEEP, r"(?i)never deleted|not deleted",
            "suppressed activity must still be reported; a suppression pass "
            "that can delete evidence launders a real finding")
        self.assertRegex(
            SWEEP, r"(?i)requires a named agent, host, or principal",
            "suppression without a named cause is just an excuse to discount "
            "inconvenient telemetry")

    def test_event_and_alert_counts_are_distinguished(self):
        self.assertRegex(
            SWEEP, r"(?i)never conflated|alert \*events\*",
            "conflating alert events with distinct alerts overstates volume "
            "by roughly 5x on an observed tenant")

    def test_truncation_reconciliation_is_required(self):
        self.assertRegex(SWEEP, r"(?i)truncat")
        self.assertRegex(SWEEP, r"(?i)match count|matchCount")


if __name__ == "__main__":
    unittest.main()
