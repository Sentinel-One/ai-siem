"""Structural tests for the `sdl-solutions` skill. No network, no tenant.

This skill is an orchestration layer: almost everything it ships is a catalog
row, a playbook, or a tokenized template, so the failure mode is drift between
those three rather than a broken function. Each test below pins a fact whose
loss has a concrete, expensive consequence:

1. Catalog / playbook / template wiring. A catalog row whose playbook does not
   exist, or a playbook naming a template that was renamed, breaks a deployment
   only at the point where the operator is already half way through it.
2. The Step 0 parser-eligibility gate. The SDL parser sees exactly two
   attributes, `message` and `parser`. Lose that and onboarding happily authors
   a parser for a source no parser can ever run against, instead of routing the
   fix to Data Pipeline Management.
3. Scheduled STAR rule invariants in every shipped detection template:
   `queryLang "2.0"`, no inline mitigation, and `entityMappings` capped at three
   (a fourth is rejected `400: Longer than maximum length 3`).
4. The RBA collector's two-credential split. The ingest action takes an SDL Log
   Write Key and sends no `S1-Scope` header; binding the console-token
   connection to it fails `400 Missing S1-Scope header`, which reads like a
   missing header and is not one.
5. Ingest-health scope lives in an editable CSV lookup, and the internal
   streams are listed BY NAME because a vendor filter keeps null-vendor rows.
6. Every documented PowerQuery still passes the repo linter.
7. The eval suite is structurally gradable and every case grades something.

The PowerQuery linter is imported from `tools/run_evals.py`, never copied.

Run:
    python3 -m unittest discover -s sdl-solutions/tests
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
ASSETS = SKILL_DIR / "assets"


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
ONBOARDING = (REFS / "data-source-onboarding.md").read_text(encoding="utf-8")
RBA = (REFS / "risk-based-alerting.md").read_text(encoding="utf-8")
INGEST = (REFS / "ingest-health-monitoring.md").read_text(encoding="utf-8")
EXCLUSIONS = (REFS / "custom-detection-exclusions.md").read_text(encoding="utf-8")

FENCE = re.compile(r"^```(\w*)\n(.*?)^```", re.M | re.S)
PQ_LANGS = {"text", "powerquery", "pq"}
# A fence only counts as a query if it actually pipes into a PQ command. The
# references are full of API bodies and CSV samples in `text` fences.
PQ_COMMAND = re.compile(
    r"\|\s*(?:group|filter|columns|sort|limit|lookup|let|parse|join|savelookup"
    r"|dataset|top|transpose|nolimit)\b")
MIN_PQ_BLOCKS = 15


class CatalogPlaybookAndTemplateWiring(unittest.TestCase):
    def test_every_reference_named_in_the_skill_exists(self):
        named = set(re.findall(
            r"((?:\.\./)?(?:[A-Za-z0-9._-]+/)?references/[A-Za-z0-9._-]+\.md)",
            SKILL))
        self.assertTrue(named, "SKILL.md no longer points at any playbook")
        # Some references are cross-skill (`powerquery/references/...`, and one
        # named bare in prose as "the `references/x.md` there"), so a name
        # resolves against this skill, the repo root, or any sibling skill.
        def resolves(n: str) -> bool:
            if (SKILL_DIR / n).is_file() or (ROOT / n).is_file():
                return True
            if any((d / n).is_file() for d in ROOT.iterdir() if d.is_dir()):
                return True
            # A vendoring repo prefixes sibling skill directories, so
            # `powerquery/references/x.md` lives at `sentinelone-powerquery/...`
            # there. Accept either spelling.
            head, _, tail = n.lstrip("./").partition("/")
            return bool(tail) and any(
                (ROOT / alt / tail).is_file()
                for alt in (f"sentinelone-{head}",
                            head.replace("sentinelone-", "", 1)))

        missing = [n for n in sorted(named) if not resolves(n)]
        self.assertEqual([], missing,
                         "SKILL.md points at playbooks that do not exist: "
                         + ", ".join(missing))

    def test_every_playbook_on_disk_is_reachable_from_the_catalog(self):
        named = set(re.findall(r"references/([A-Za-z0-9._-]+\.md)", SKILL))
        orphans = sorted(p.name for p in REFS.glob("*.md") if p.name not in named)
        self.assertEqual(
            [], orphans,
            "playbooks exist that the catalog never names, so the router cannot "
            "branch to them: " + ", ".join(orphans))

    def test_every_asset_path_named_anywhere_resolves(self):
        text = SKILL + "".join(p.read_text(encoding="utf-8")
                               for p in sorted(REFS.glob("*.md")))
        named = set(re.findall(r"assets/([A-Za-z0-9._/-]+)", text))
        self.assertGreater(len(named), 20, "the template list has been gutted")
        missing = [n for n in sorted(named)
                   if not (ASSETS / n.rstrip("/")).exists()]
        self.assertEqual([], missing,
                         "templates are named but absent from assets/: "
                         + ", ".join(missing))

    def test_catalog_table_has_a_playbook_column_entry_per_row(self):
        """The catalog must list every solution the description enumerates.

        Derived, not hardcoded. The count was pinned at 8, which broke the
        moment a repo legitimately carried a different set: the GHE guidelines
        repo drops Detection-as-Code, so its description enumerates 7 and its
        catalog has 7 rows, and a literal 8 failed a skill that was correct.
        Reading the expected count from the description keeps the real invariant,
        that the two agree, without assuming which solutions a given repo ships.

        Equality, not a lower bound. A `>=` here let the catalog grow past what
        the description advertises, which is the commoner drift of the two: a
        solution gets a catalog row and the frontmatter is never updated, so the
        skill stops triggering on it. Both counts are 8 in claude-skills and 7 in
        the scrubbed guidelines repo, exactly equal in each, so equality is the
        assertion the docstring was already claiming.
        """
        rows = [r for r in SKILL.splitlines()
                if r.startswith("|") and "references/" in r]
        m = re.search(r'^description:\s*"(.*?)"\s*$', SKILL, re.M | re.S)
        self.assertIsNotNone(m, "SKILL.md has no quoted description")
        advertised = [int(n) for n in re.findall(r"\((\d+)\)", m.group(1))]
        self.assertTrue(advertised,
                        "the description no longer enumerates its solutions")
        self.assertEqual(
            max(advertised), len(rows),
            f"the solution catalog has {len(rows)} rows but the frontmatter "
            f"description advertises {max(advertised)} solutions; a row without "
            f"a description entry means the skill will not trigger on it, and a "
            f"description entry without a row points at a playbook that is gone")


class ParserEligibilityGate(unittest.TestCase):
    """Step 0 decides whether a parser is built at all."""

    def test_the_two_visible_attributes_are_named(self):
        self.assertRegex(
            ONBOARDING,
            r"(?i)sees exactly two\s+attributes.{0,40}`message` and `parser`",
            "the rule that an SDL parser sees only `message` and `parser` is "
            "gone; without it onboarding authors parsers that can never run")

    def test_all_four_gate_cases_are_tabulated(self):
        table = re.search(r"\| `parser` \| `message` \| Action \|\n(.*?)\n\n",
                          ONBOARDING, re.S)
        self.assertIsNotNone(table, "the parser-eligibility gate table is gone")
        rows = [r for r in table.group(1).splitlines()
                if r.startswith("|") and not set(r) <= set("|- ")]
        self.assertEqual(4, len(rows),
                         "the gate has four cases (present/present, "
                         "absent/present, absent/absent, pre-parsed in DPM); "
                         f"found {len(rows)}")

    def test_the_dpm_route_is_named_not_implied(self):
        self.assertRegex(ONBOARDING, r"Data Pipeline Management \(DPM\)")
        self.assertRegex(
            ONBOARDING, r"(?i)do not invent a parser",
            "the instruction to stop rather than invent a parser when parsing "
            "must happen in DPM has been removed")

    def test_the_gate_runs_before_step_1(self):
        gate = ONBOARDING.index("## Step 0")
        step1 = ONBOARDING.index("## Step 1")
        self.assertLess(gate, step1)
        self.assertRegex(
            ONBOARDING, r"(?i)apply the parser-eligibility gate before doing "
                        r"anything else")

    def test_the_gate_is_repeated_in_the_onboarding_gotchas(self):
        gotchas = ONBOARDING[ONBOARDING.index("## Gotchas"):]
        self.assertRegex(gotchas, r"(?i)do not assume the source is editable")

    @NEEDS_LINTER
    def test_absence_probe_uses_the_parenthesised_idiom(self):
        # `!(field = *)`. Bare `!field` matches every row and reports a source
        # as entirely missing a field it has.
        self.assertIn("!(field = *)", ONBOARDING)
        self.assertEqual(
            [], LINTER.pq_problems("!(parser = *)"),
            "the linter no longer accepts the documented absence idiom")
        self.assertTrue(
            LINTER.pq_problems("!parser"),
            "the linter no longer rejects the bare-`!field` form, which is the "
            "mistake the parenthesised idiom exists to prevent")


class ScheduledDetectionTemplatesStayLegal(unittest.TestCase):
    """Every shipped STAR scheduled template, checked as a group."""

    def _scheduled(self):
        for p in sorted(ASSETS.glob("*.template.json")):
            text = p.read_text(encoding="utf-8")
            if '"queryType": "scheduled"' in text:
                yield p, text

    def test_there_are_scheduled_templates_to_check(self):
        self.assertGreaterEqual(len(list(self._scheduled())), 5)

    def test_powerquery_bodies_declare_query_lang_2_0(self):
        for p, text in self._scheduled():
            self.assertIn('"queryLang": "2.0"', text,
                          f"{p.name}: a PowerQuery body needs queryLang 2.0; "
                          f"1.0 is S1QL and the POST is rejected")

    def test_no_inline_mitigation_on_scheduled_rules(self):
        for p, text in self._scheduled():
            self.assertIn('"treatAsThreat": "UNDEFINED"', text,
                          f"{p.name}: scheduled rules cannot act inline; the "
                          f"API returns 400 'can't apply mitigation actions on "
                          f"a scheduled rule'")
            self.assertIn('"networkQuarantine": false', text, p.name)

    def test_entity_mappings_never_exceed_three_per_rule(self):
        seen = 0
        for p, text in self._scheduled():
            for block in re.findall(r'"entityMappings"\s*:\s*\[(.*?)\]',
                                    text, re.S):
                seen += 1
                n = len(re.findall(r'"columnName"', block))
                self.assertLessEqual(
                    n, 3,
                    f"{p.name}: {n} entityMappings entries; the API rejects a "
                    f"fourth with 400 'Longer than maximum length 3'")
        self.assertGreater(seen, 0, "no entityMappings blocks found at all")

    def test_the_onboarding_template_documents_the_cap_and_the_cool_off(self):
        text = (ASSETS / "onboarding_detection.template.json").read_text(
            encoding="utf-8")
        self.assertIn("Longer than maximum length 3", text)
        self.assertRegex(
            text, r"(?i)do NOT default to 24h",
            "the cool-off warning is gone; renotifyMinutes 1440 masks an "
            "ongoing threat for a full day")

    def test_lookup_reading_rules_are_account_scoped(self):
        for text, where in ((SKILL, "SKILL.md"),
                            (INGEST, "ingest-health-monitoring.md")):
            self.assertRegex(
                text, r"(?i)account[- ]level",
                f"{where} no longer states that lookups and datatables are "
                f"account-level, so a rule reading one cannot be site-scoped")


class RbaCollectorCredentialSplit(unittest.TestCase):
    def test_the_ingest_credential_is_named(self):
        self.assertRegex(RBA, r"(?i)SDL Log Write Key")
        self.assertIn("/services/collector/event", RBA)

    def test_the_console_token_refusal_is_recorded_with_its_error(self):
        self.assertIn("Missing S1-Scope header", RBA)
        self.assertRegex(
            RBA, r"(?i)adding the header does not help|an `?S1-Scope`? header "
                 r"does not fix it",
            "the note that the 400 is a wrong credential rather than a missing "
            "header is gone, which sends the next reader off adding headers")

    def test_two_connections_not_one(self):
        self.assertRegex(RBA, r"(?i)second, separate connection|two "
                              r"connections")
        self.assertIn("SentinelOne SDL", RBA)

    def test_the_collector_template_sends_no_s1_scope_header(self):
        text = (ASSETS / "rba_collector.workflow.template.json").read_text(
            encoding="utf-8")
        self.assertEqual(
            [], re.findall(r'"key"\s*:\s*"S1-Scope"', text),
            "the collector template now sends an S1-Scope header; the "
            "collector does not read it and its presence previously masked "
            "the real requirement")
        self.assertIn("/services/collector/event", text)

    def test_publish_before_prompt_before_activate(self):
        for token in ("/publish", "Shared Draft"):
            self.assertIn(token, RBA)
        self.assertLess(RBA.index("Publish to Shared Draft"),
                        RBA.index("**Activate**"),
                        "the collector must be a Shared Draft before the user "
                        "is asked to bind connections and activate")

    def test_numeric_cast_rule_survives(self):
        self.assertIn("number(risk_score)", RBA)


class IngestHealthScopeIsALookup(unittest.TestCase):
    def test_exclusions_are_a_csv_not_hardcoded_filters(self):
        self.assertRegex(
            INGEST, r"(?i)not by hardcoded\s*\n?`?dataSource\.name != ",
            "the rule that scope lives in the CSV rather than in query text "
            "has been removed")
        self.assertIn("ingestHealthExclusions.csv", INGEST)

    def test_the_anti_join_shape_is_documented(self):
        self.assertIn("ih_excl_n", INGEST)
        self.assertIn("ih_excl_v", INGEST)
        self.assertRegex(INGEST,
                         r"filter \(ih_excl_n = null and ih_excl_v = null\)")

    def test_the_null_vendor_trap_is_recorded(self):
        self.assertRegex(
            INGEST, r"(?i)KEEPS null-vendor rows",
            "the null-vendor trap is gone; a `dataSource.vendor != "
            "'SentinelOne'` filter silently keeps every internal stream")

    def test_internal_streams_are_listed_by_name_in_the_template(self):
        csv = (ASSETS / "ingesthealth_exclusions.csv.template").read_text(
            encoding="utf-8")
        self.assertTrue(csv.startswith("value,match_type,reason"),
                        "the exclusions CSV header changed; every anti-join "
                        "keys on `value`")
        for stream in ("alert", "indicator", "asset", "ActivityFeed",
                       "misconfiguration", "finding", "risk"):
            self.assertRegex(
                csv, rf"(?mi)^{stream},",
                f"the internal stream `{stream}` is no longer excluded by "
                f"name, so a vendor filter will not catch it")

    def test_the_table_is_deployed_first_and_why(self):
        self.assertRegex(INGEST, r"(?i)file not found")
        self.assertRegex(INGEST, r"(?i)Config lookups \(FIRST")


class ExclusionRuleTypeGate(unittest.TestCase):
    def test_the_rule_type_is_asked_before_anything_else(self):
        self.assertRegex(EXCLUSIONS, r"(?i)always ask which one before "
                                     r"configuring anything else")
        self.assertLess(EXCLUSIONS.index("## Step 0"),
                        EXCLUSIONS.index("## Single-event rule path"))

    def test_all_three_rule_types_are_covered(self):
        for t in ('queryType: "events"', 'queryType: "correlation"',
                  'queryType: "scheduled"'):
            self.assertIn(t, EXCLUSIONS)

    def test_the_pipeless_limit_is_stated(self):
        self.assertRegex(
            EXCLUSIONS, r"(?i)boolean S1QL with NO pipes",
            "the reason single-event and correlation cannot use a lookup "
            "anti-join (their bodies have no pipes) is gone")

    def test_the_anti_join_and_its_inverse_are_documented(self):
        self.assertIn("| filter excl = null", EXCLUSIONS)
        self.assertIn("| filter excl = *", EXCLUSIONS)


class DocumentedQueriesLintClean(unittest.TestCase):
    def _blocks(self):
        for f in [SKILL_DIR / "SKILL.md"] + sorted(REFS.glob("*.md")):
            for lang, body in FENCE.findall(f.read_text(encoding="utf-8")):
                if lang in PQ_LANGS and PQ_COMMAND.search(body):
                    yield f, body
        for f in sorted(ASSETS.glob("*.pq")):
            yield f, f.read_text(encoding="utf-8")

    @NEEDS_LINTER
    def test_examples_and_pq_assets_pass_the_repo_linter(self):
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
            f"wide or the playbooks were gutted")


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

    def test_suite_grades_json_and_powerquery_structurally(self):
        kinds = {a["type"] for c in self.suite["evals"] for a in c["assertions"]}
        for kind in ("json_parses", "file_json_path", "pq_valid"):
            self.assertIn(
                kind, kinds,
                f"a suite over rule payloads and query bodies that never uses "
                f"{kind} is not checking the shapes it exists to enforce")

    def test_the_parser_eligibility_gate_is_covered(self):
        blob = json.dumps(self.suite)
        self.assertIn("Data Pipeline Management", blob)
        self.assertIn("sdl_parser_eligible", blob)

    def test_the_rba_credential_split_is_covered(self):
        blob = json.dumps(self.suite)
        self.assertIn("Missing S1-Scope header", blob)
        self.assertRegex(blob, r"(?i)log\[ _-\]\?write\[ _-\]\?key|"
                               r"log write key")


if __name__ == "__main__":
    unittest.main()
