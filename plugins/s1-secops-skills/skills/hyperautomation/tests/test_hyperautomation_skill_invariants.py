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
   holding an SDL Log Write Key. A console-token connection gets HTTP 400
   "Missing S1-Scope header" without a scope header (and is accepted with one)
   on some consoles, HTTP 403 code 4 either way on others; the fix is the
   write key in both cases.
4. Approval gates fail CLOSED. A `not_equals` gate auto-runs the destructive
   action on a timeout, with nobody having approved anything.
5. Action `type` strings are not invented: everything the building-blocks
   reference emits is in the observed-in-production list SKILL.md publishes.
6. The eval suite is structurally gradable and every case grades something.
7. Workflow and connection API behaviour measured live on 2026-10-09 stays
   stated (run-now body, response-trigger limits, list/deactivate/delete/export
   paths, connection create), and the claims it superseded stay gone.

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
                f"{where} no longer records the 400 a console-token connection "
                f"gets from the event collector without a scope header")
            self.assertRegex(
                text, r"User token not allowed for this\s+endpoint",
                f"{where} no longer records the per-console 403 code 4 refusal")
            self.assertRegex(
                text, r"(?i)use the write\s+key\s+in both cases",
                f"{where} no longer says the write key is the fix for both errors")
            # Live 2026-10-09: with S1-Scope the console token IS accepted on
            # some consoles, so the old claim must not come back.
            self.assertNotRegex(
                text, r"(?i)S1-Scope`? header does\s+not\s+fix it",
                f"{where} again claims an S1-Scope header does not fix it")

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


def _section(text: str, start: str, end: str) -> str:
    i = text.index(start)
    return text[i:text.index(end, i)]


class WorkflowApiMeasuredFacts(unittest.TestCase):
    """Workflow API behaviour measured live on 2026-10-09."""

    def setUp(self):
        self.api = (REFS / "api-integration.md").read_text(encoding="utf-8")
        self.run_now = _section(self.api, "### 9. Trigger a Manual Workflow",
                                "### 10. List Workflow Executions")

    def test_list_limit_and_name_filter(self):
        self.assertRegex(self.api, r"Omitted, it returns 10 rows")
        self.assertIn("limit=2000", self.api)
        self.assertRegex(self.api, r"only `name__contains` is honoured")
        self.assertRegex(self.api, r"`name`,\s+`search` and `query` are silently ignored")
        self.assertIn("{id, workflow: {...}, actions: [{id, integration_id, type}]}",
                      self.api)
        self.assertIn("row.workflow", self.api)

    def test_deactivate_and_delete_paths(self):
        self.assertIn("/hyper-automate/api/v1/workflows/{id}/{version_id}/deactivate",
                      self.api)
        self.assertIn("/public/workflows/{id}/{version_id}/deactivate", self.api)
        self.assertIn("`DELETE /hyper-automate/api/public/workflows/{id}` returns `404`",
                      self.api)
        self.assertIn("Active workflows cannot be archived", self.api)

    def test_run_now_body_must_carry_data(self):
        self.assertIn("the `data` object is REQUIRED", self.run_now)
        self.assertRegex(self.run_now, r'`\{"data": \{\}\}` returned\s+(?:>\s*)?`201`')
        self.assertRegex(self.run_now, r"empty `\{\}` body returned a bare `500")
        self.assertRegex(self.run_now, r'422 "Field\s+(?:>\s*)?required"')
        self.assertNotIn("(all fields optional)", self.run_now,
                         "section 9 again says the run-now body is all optional")
        self.assertNotIn("Send the full envelope even when", self.run_now,
                         "the superseded full-envelope advice is back")

    def test_response_trigger_cannot_run_on_demand(self):
        self.assertRegex(self.run_now, r"On-demand execution is not supported for trigger"
                                       r"\s+(?:>\s*)?type 'singularity_response_trigger'")
        self.assertIn("run_automatically: true", self.run_now)
        self.assertRegex(self.run_now, r"6 to 8 s")
        self.assertIn('singularity_response_event_type: "alert"', self.run_now)

    def test_converting_response_trigger_to_manual(self):
        self.assertIn("`manual_trigger`", self.run_now)
        self.assertRegex(self.run_now, r"invalid references")
        self.assertIn("invalid_references", self.run_now)
        self.assertIn("dynamic_properties.data.title: Field required", self.run_now)

    def test_export_one_workflow_and_execution_rows(self):
        self.assertIn("workflow-import-export/export?workflow_ids=<id>", self.api)
        self.assertIn("/v1/workflows/single/{id}/{version_id}", self.api)
        self.assertRegex(self.api, r"`state` \(not `status`\) and no `error_actions`")

    def test_reimport_naming_documented_once(self):
        self.assertIn("`Name (1)`, `Name (2)`", SKILL)
        self.assertEqual(1, SKILL.count("Name (1)"),
                         "the re-import naming rule is stated more than once")


class ConnectionsCanBeCreatedByApi(unittest.TestCase):
    """Measured 2026-10-09; supersedes the old "cannot be created" line."""

    def setUp(self):
        self.api = (REFS / "api-integration.md").read_text(encoding="utf-8")
        self.conn = _section(self.api, "### 16. Integrations and connections", "\n---\n")

    def test_create_endpoint_and_errors(self):
        self.assertIn("POST /connections?siteIds=<site>", self.conn)
        self.assertIn("`201`", self.conn)
        for frag in ("Request body must include 'data'.",
                     "url and protocol are required for non-webhook connections",
                     "Connection name already exists",
                     "Connection which is in use cannot be deleted"):
            self.assertIn(frag, self.conn, f"connection error {frag!r} is gone")

    def test_read_routes(self):
        self.assertIn("default_connection_data", self.conn)
        self.assertRegex(self.conn, r"`GET /connections` and `GET /integrations` return `405`")
        self.assertIn("`GET /integrations/connections` returns `422`", self.conn)
        self.assertIn("`GET /connections/{id}`", self.conn)

    def test_skill_no_longer_says_connections_cannot_be_created(self):
        self.assertNotRegex(SKILL, r"CANNOT be \*created\* via API",
                            "SKILL.md again claims connections cannot be created")
        self.assertRegex(SKILL, r"connection CAN be created via API")
        conn_ref = (REFS / "connections.md").read_text(encoding="utf-8")
        self.assertIn("Returns `201`", conn_ref)


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


class DestructiveFindings20261009(unittest.TestCase):
    """Measured 2026-10-09 by import/activate/run/delete probes on three consoles."""

    def setUp(self):
        ref = SKILL_DIR / "references"
        self.blocks = (ref / "building-blocks.md").read_text(encoding="utf-8")
        self.fns = (ref / "functions-reference.md").read_text(encoding="utf-8")
        self.api = (ref / "api-integration.md").read_text(encoding="utf-8")
        self.conn = (ref / "connections.md").read_text(encoding="utf-8")

    def test_llm_response_format_enum(self):
        self.assertIn("Input should be 'off', 'auto' or 'strict'", self.blocks)
        # LLM availability depends on pre-release feature access, so it is deliberately
        # not documented per console.
        self.assertNotIn("not available on every console", self.blocks)
        self.assertNotIn("Insufficient Singularity Credits", self.blocks)

    def test_send_email_is_per_console(self):
        self.assertIn("MessageRejected", self.blocks)
        self.assertIn("CompletedWithErrors", self.blocks)

    def test_generate_uuid_does_not_exist(self):
        self.assertIn("There is no `GENERATE_UUID`", self.fns)
        self.assertIn("doesn't match any function name in the system", self.fns)
        self.assertNotRegex(self.fns, r"Function\.GENERATE_UUID\(\)")

    def test_jq_features_and_parsed_json_variables(self):
        for feature in ("`|=`", "`with_entries`", "`reduce ... setpath`", "`strftime`", "`floor`", "`tostring`"):
            self.assertIn(feature, self.fns)
        self.assertIn("stored already parsed", self.fns)

    def test_response_trigger_conversion_run_error(self):
        self.assertIn("Attribute id not found in Action singularity-response-trigger", self.api)

    def test_no_execution_output_route(self):
        self.assertIn("There is no route for action outputs", self.api)

    def test_connections_resolve_by_name_at_the_workflow_scope(self):
        self.assertIn("resolved by name at the workflow's own scope, at run time", self.conn)
        self.assertIn("Connection with name '<name>' could not\nbe found.", self.conn)
        self.assertRegex(self.conn, r"activation does not check it")


if __name__ == "__main__":
    unittest.main()
