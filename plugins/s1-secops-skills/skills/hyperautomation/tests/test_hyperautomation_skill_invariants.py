"""Structural tests for the `hyperautomation` skill. No network, no tenant.

These pin the facts a careless edit would erase, each with a concrete failure
attached:

1. The workflow envelope and action-object shape. Get `parent_action` wrong and
   the import returns `422 "Invalid workflow data"` with every field looking
   correct, which is the single most expensive mistake this skill prevents.
2. The smoke-test workflow embedded in SKILL.md still parses and still matches
   the shape `references/workflow-schema.md` documents. A drifted example is
   worse than none, because it is what gets copied.
3. The connection split: SDL query endpoints need `Bearer` and reject the mgmt
   `ApiToken` with HTTP 500; the HEC event collector needs its own connection
   holding an SDL Log Write Key and refuses the console token with HTTP 400.
4. Approval gates fail CLOSED. A `not_equals` gate auto-runs the destructive
   action on a timeout, with nobody having approved anything.
5. Action `type` strings are not invented: everything the building-blocks
   reference emits is in the observed-in-production list SKILL.md publishes.
6. The eval suite is structurally gradable and every case grades something.

The PowerQuery linter is imported from `tools/run_evals.py`, never copied.

Run:
    python3 -m unittest discover -s hyperautomation/tests
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

    The skill is vendored into other repositories, where it lands several levels
    deep and the linter does not travel with it. A fixed `ROOT / "tools"` path
    raised FileNotFoundError at import time there, which aborted collection and
    cost this whole file its CI signal without failing anything visibly. Walk up
    for the linter instead, and degrade to skipping only the two tests that need
    it rather than silently losing the other twenty-seven.
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
MIN_PQ_BLOCKS = 8

SKILL = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")


def _first_json_fence(text: str):
    m = re.search(r"^```json\n(.*?)^```", text, re.M | re.S)
    assert m, "no ```json fence found"
    return json.loads(m.group(1))


class EnvelopeAndActionShape(unittest.TestCase):
    def setUp(self):
        self.schema = (REFS / "workflow-schema.md").read_text(encoding="utf-8")

    def test_top_level_envelope_keys_are_documented(self):
        for key in ('"name"', '"description"', '"actions"'):
            self.assertIn(key, self.schema,
                          f"the workflow envelope no longer documents {key}")

    def test_action_object_keys_are_documented(self):
        for key in ('"export_id"', '"connected_to"', '"parent_action"'):
            self.assertIn(key, self.schema,
                          f"the action object no longer documents {key}")

    def test_connected_to_is_the_edge_carrier(self):
        self.assertRegex(self.schema, r"(?i)`?target`?:\s*the\s+`?export_id`?")
        self.assertIn('"custom_handle"', self.schema)

    def test_import_ready_json_nulls_the_connection(self):
        self.assertRegex(
            self.schema, r"(?i)`?connection_id`?:\s*null",
            "the import-ready `connection_id: null` rule is gone; a hard-coded "
            "id from another tenant imports as 404")


class SmokeTestWorkflowStillMatchesTheSchema(unittest.TestCase):
    """The embedded minimal workflow is what people copy first."""

    def setUp(self):
        self.wf = _first_json_fence(SKILL)

    def test_it_parses_as_strict_json(self):
        self.assertIsInstance(self.wf, dict)

    def test_envelope_is_wrapped_in_data(self):
        self.assertIn("data", self.wf)
        for key in ("name", "description", "actions"):
            self.assertIn(key, self.wf["data"],
                          f"the smoke-test envelope lost `{key}`")

    def test_single_action_has_the_four_documented_keys(self):
        actions = self.wf["data"]["actions"]
        self.assertEqual(1, len(actions), "the smoke test is no longer minimal")
        for key in ("action", "export_id", "connected_to", "parent_action"):
            self.assertIn(key, actions[0], f"the action object lost `{key}`")

    def test_trigger_is_top_level_and_terminal(self):
        a = self.wf["data"]["actions"][0]
        self.assertIsNone(a["parent_action"],
                          "parent_action is loop membership only; a non-null "
                          "value here is the documented 422")
        self.assertEqual([], a["connected_to"])
        self.assertEqual("manual_trigger", a["action"]["type"])
        self.assertEqual("manual_trigger", a["action"]["data"]["action_type"])
        self.assertEqual("core_action", a["action"]["tag"])
        self.assertIsNone(a["action"]["connection_id"])


class ParentActionIsLoopMembershipOnly(unittest.TestCase):
    def setUp(self):
        self.rules = (REFS / "validation-rules.md").read_text(encoding="utf-8")

    def test_rule_is_stated_with_its_failure_mode(self):
        self.assertRegex(self.rules, r"(?i)LOOP membership ONLY")
        self.assertIn("422", self.rules)

    def test_flow_order_comes_from_connected_to(self):
        self.assertRegex(self.rules, r"(?i)connected_to\.target")


class ApprovalGatesFailClosed(unittest.TestCase):
    def setUp(self):
        self.rules = (REFS / "validation-rules.md").read_text(encoding="utf-8")

    def test_rule_is_stated_in_the_validation_checklist(self):
        self.assertRegex(self.rules, r"(?i)FAIL\s*CLOSED")
        self.assertRegex(self.rules, r'(?i)equals\s+"approved"')

    def test_the_fail_open_form_is_named_as_wrong(self):
        self.assertRegex(
            self.rules, r'(?i)NEVER\s+`?not_equals\s+"dismissed"',
            "the fail-open counter-example is no longer called out; without it "
            "a timeout silently auto-runs the destructive action")

    def test_skill_repeats_it_in_common_mistakes(self):
        self.assertRegex(SKILL, r"(?i)fail\s*CLOSED")


class ConnectionCredentialSplit(unittest.TestCase):
    def setUp(self):
        self.conn = (REFS / "connections.md").read_text(encoding="utf-8")

    def test_sdl_endpoints_require_bearer(self):
        self.assertIn("Header must start with Bearer", SKILL)
        self.assertIn("SentinelOne SDL", self.conn)
        self.assertIn("Bearer", self.conn)

    def test_mgmt_connection_signs_apitoken(self):
        self.assertIn("ApiToken", self.conn)
        self.assertIn("ApiToken", SKILL)

    def test_event_collector_needs_its_own_log_write_key_connection(self):
        for text, where in ((self.conn, "connections.md"), (SKILL, "SKILL.md")):
            self.assertRegex(text, r"(?i)log write key",
                             f"{where} no longer names the SDL Log Write Key")
            self.assertIn("/services/collector/", text)
        # SKILL.md wraps this inside a quoted JSON body, so tolerate the break.
        for text, where in ((self.conn, "connections.md"), (SKILL, "SKILL.md")):
            self.assertRegex(
                text, r"Missing\s+S1-Scope header",
                f"{where} no longer records that the console token is refused "
                f"by the event collector")

    def test_uam_alert_ingest_is_the_opposite_case(self):
        # /v1/alerts on the SAME host takes the console token AND S1-Scope.
        # Copying collector auth to it is the documented trap.
        self.assertIn("/v1/alerts", self.conn)
        self.assertIn("/v1/alerts", SKILL)


class ImportIsNotCompleteUntilPublished(unittest.TestCase):
    def test_publish_step_is_documented(self):
        self.assertIn("/publish", SKILL)
        self.assertRegex(SKILL, r"(?i)private draft")
        self.assertRegex(SKILL, r"(?i)shared draft")

    def test_reason_is_stated_not_just_the_call(self):
        self.assertRegex(
            SKILL, r"(?i)invisible in the console",
            "the why (an API import is owned by the token's user and nobody "
            "else can see it) is gone, leaving an unexplained extra call")


class ActionTypesAreNotInvented(unittest.TestCase):
    """SKILL.md publishes an OBSERVED list; nothing may emit outside it."""

    def _documented(self):
        m = re.search(r"action types \*\*observed in production\*\*.*?are:\n(.*?)\n\n",
                      SKILL, re.S | re.I)
        self.assertIsNotNone(m, "the observed-action-type list is gone from SKILL.md")
        return set(re.findall(r"`([a-z0-9_]+)`", m.group(1)))

    def test_the_list_is_still_published(self):
        self.assertGreaterEqual(len(self._documented()), 15)

    def test_building_blocks_emit_only_documented_types(self):
        documented = self._documented()
        text = (REFS / "building-blocks.md").read_text(encoding="utf-8")
        used = set(re.findall(r'"action_type"\s*:\s*"([a-z0-9_]+)"', text))
        self.assertTrue(used, "building-blocks.md no longer shows any action_type")
        undocumented = sorted(used - documented)
        self.assertEqual(
            [], undocumented,
            "building-blocks.md emits action types that SKILL.md does not list "
            "as observed: " + ", ".join(undocumented))

    def test_snippet_call_node_is_snippet_20(self):
        self.assertIn("snippet_20", self._documented())
        self.assertRegex(SKILL, r"(?i)uses a `snippet_20` node \(not `snippet`\)")


class ReferenceFilesResolve(unittest.TestCase):
    def test_every_reference_named_in_the_skill_exists(self):
        named = set(re.findall(
            r"((?:\.\./)?(?:[A-Za-z0-9._-]+/)?references/[A-Za-z0-9._-]+\.md)", SKILL))
        self.assertTrue(named, "SKILL.md no longer points at any reference file")

        def resolves(n: str) -> bool:
            if (SKILL_DIR / n).is_file() or (ROOT / n).is_file():
                return True
            # A cross-skill pointer such as `sdl-api/references/x.md` resolves
            # against ROOT here but against a prefixed sibling directory in repos
            # that vendor these skills. Accept either spelling of the sibling so
            # the invariant tests the reference, not the host repo's naming.
            head, _, tail = n.lstrip("./").partition("/")
            for alt in (f"sentinelone-{head}", head.replace("sentinelone-", "", 1)):
                if tail and (ROOT / alt / tail).is_file():
                    return True
            return False

        missing = [n for n in sorted(named) if not resolves(n)]
        self.assertEqual([], missing,
                         "SKILL.md points at reference files that do not exist: "
                         + ", ".join(missing))


class DocumentedQueriesLintClean(unittest.TestCase):
    def _blocks(self):
        files = [SKILL_DIR / "SKILL.md"] + sorted(REFS.glob("*.md"))
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

    def test_suite_grades_json_structurally(self):
        kinds = {a["type"] for c in self.suite["evals"] for a in c["assertions"]}
        for kind in ("json_parses", "file_json_path"):
            self.assertIn(kind, kinds,
                          f"a workflow-JSON suite that never uses {kind} is not "
                          f"checking the envelope shape it exists to enforce")

    def test_credential_split_is_covered_by_the_suite(self):
        blob = json.dumps(self.suite)
        self.assertIn("Bearer", blob)
        self.assertIn("Log Write Key", blob)
        self.assertIn("parent_action", blob)


if __name__ == "__main__":
    unittest.main()
