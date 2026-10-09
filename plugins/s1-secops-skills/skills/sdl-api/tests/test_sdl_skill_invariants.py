"""Structural tests for the `sdl-api` skill. No network, no tenant.

These pin the facts a careless edit would erase, each of which has a concrete
failure attached:

1. The ingest credential split. Raw log ingest needs an SDL Log Write Key in
   `S1_HEC_TOKEN` (`Splunk` or `Bearer` prefix); whether the console token is
   accepted at the collector differs per console (400 "Missing S1-Scope
   header" without the header and accepted with it on one console, 403 code 4
   "User token not allowed for this endpoint" either way on another). UAM
   alert ingest at /v1/alerts is the other path and does use the console token
   with S1-Scope.
2. Config files are GraphQL. Dashboards are addressed by `udoId`; a
   name-addressed write creates a duplicate instead of updating.
3. The client still exposes the config-file round-trip surface used by the
   evals, with `expected_version` as the concurrent-edit guard.

The PowerQuery linter is imported from `tools/run_evals.py`, never copied.

Run:
    python3 -m unittest discover -s sdl-api/tests
"""
from __future__ import annotations

import importlib.util
import inspect
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


class IngestCredentialSplit(unittest.TestCase):
    def setUp(self):
        self.skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")

    def test_raw_log_ingest_uses_the_log_write_key(self):
        self.assertIn("S1_HEC_TOKEN", self.skill)
        self.assertRegex(self.skill, r"(?i)log\s+write\s+key")

    def test_console_token_acceptance_is_per_console(self):
        # Live 2026-10-09: on one console the console token gets 400 "Missing
        # S1-Scope header" without the header and is ACCEPTED with it (the
        # header then decides the landing scope); on another it gets 403 code 4
        # with or without the header. The write key works on both. Neither the
        # blanket "the console token is refused" claim nor the old "adding an
        # S1-Scope header does not fix it" claim may return.
        docs = {
            "SKILL.md": self.skill,
            "auth_and_limits.md": (SKILL_DIR / "references" /
                                   "auth_and_limits.md").read_text(encoding="utf-8"),
            "config-file-graphql.md": (SKILL_DIR / "references" /
                                       "config-file-graphql.md").read_text(encoding="utf-8"),
        }
        for name, text in docs.items():
            self.assertIn("User token not allowed for this endpoint", text, name)
            self.assertIn("Missing S1-Scope header", text, name)
            self.assertRegex(text, r"(?i)not a reliable substitute", name)
            self.assertRegex(text, r"(?i)use the write\s+key in both cases", name)
            self.assertNotRegex(text, r"(?i)does not fix it|does not help", name)
        self.assertRegex(
            self.skill, r"(?i)without an `S1-Scope` header and is accepted with one",
            "the console-token-with-S1-Scope acceptance is no longer recorded")
        self.assertRegex(
            self.skill, r"(?i)header then decides the landing scope",
            "for the console token the header decides the landing scope")
        self.assertRegex(
            self.skill, r"(?i)refused with or without the header",
            "the per-console 403 refusal is no longer recorded")
        self.assertNotRegex(
            self.skill, r"(?i)console API token, service user or personal, is refused",
            "the blanket console-token-is-refused claim is back")
        self.assertNotIn("The console API token is refused, `HTTP 400", self.skill)

    def test_write_key_prefixes_documented(self):
        self.assertRegex(self.skill, r"Splunk <key>")
        self.assertRegex(self.skill, r"Bearer <key>")

    def test_key_mint_scope_decides_landing_and_header_is_ignored(self):
        auth = (SKILL_DIR / "references" / "auth_and_limits.md").read_text(encoding="utf-8")
        for text in (self.skill, auth):
            self.assertRegex(text, r"(?i)collector ignores `S1-Scope`")
            self.assertRegex(text, r"(?i)account-minted key lands account-only data")
            self.assertRegex(text, r"(?i)site-scoped detection rules do not see")

    def test_landing_check_uses_powerquery_group_not_v1_or_log_values(self):
        auth = (SKILL_DIR / "references" / "auth_and_limits.md").read_text(encoding="utf-8")
        for text in (self.skill, auth):
            self.assertIn("group n=count() by account.id, site.id", text)
            self.assertIn("serverInfo", text)
            self.assertRegex(text, r"(?i)session level")
            self.assertIn("site.id='<site>'", text)

    def test_uam_alert_ingest_is_the_other_path(self):
        self.assertIn("/v1/alerts", self.skill)
        self.assertIn("S1_CONSOLE_API_TOKEN", self.skill)

    def test_datasource_category_is_pinned_to_security(self):
        self.assertRegex(self.skill, r"dataSource\.category")
        self.assertRegex(self.skill, r"(?i)hard-?coded to `?security")


class ConfigFileAddressing(unittest.TestCase):
    def setUp(self):
        self.skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")

    def test_graphql_is_the_canonical_surface(self):
        self.assertIn("/sdl/v2/graphql", self.skill)
        self.assertIn("configFiles", self.skill)

    def test_rest_listing_documented_as_incomplete(self):
        self.assertRegex(self.skill, r"(?i)incomplete|under-?report")

    def test_dashboards_are_addressed_by_udoid(self):
        self.assertIn("udoId", self.skill)
        self.assertRegex(
            self.skill, r"(?i)creates? a duplicate",
            "the name-addressed-dashboard-write-duplicates rule is gone")

    def test_parser_path_is_logparsers(self):
        self.assertIn("/logParsers/", self.skill)


class LiveFindings20261009(unittest.TestCase):
    """Facts measured live 2026-10-09 on three consoles."""

    def setUp(self):
        ref = SKILL_DIR / "references"
        self.graphql = (ref / "config-file-graphql.md").read_text(encoding="utf-8")
        self.ingest = (ref / "integration_patterns.md").read_text(encoding="utf-8")

    def test_addevents_scope_ts_and_attrs_behaviour(self):
        t = self.ingest
        self.assertIn("/sdl/api/addEvents", t)
        self.assertRegex(t, r"`S1-Scope: <accountId>:<siteId>` \| events carry `site\.id`")
        self.assertRegex(t, r"`S1-Scope: <accountId>` \| no `site\.id`")
        self.assertRegex(t, r"(?i)back-dated 3 h \| accepted")
        self.assertRegex(t, r"(?i)no `ts` \| not stored[^|]*`warnings`")
        self.assertRegex(t, r"(?i)nested object in `attrs` \| stored as one JSON string")
        # The collector stays the recommendation.
        self.assertRegex(t, r"(?i)has been removed from this skill")

    def test_config_files_are_per_scope_and_lookup_follows_the_header(self):
        t = self.graphql
        self.assertRegex(t, r"(?i)lookup tables and other config files are per scope")
        self.assertRegex(t, r"(?i)two independent files")
        self.assertIn("| dataset 'config://datatables/<name>'", t)
        self.assertRegex(t, r"(?i)reads the copy named by the `S1-Scope` header")
        self.assertRegex(t, r"(?i)global token with `accountIds` and no header got \"does not exist\"")

    def test_graphql_introspection_is_disabled_and_configfile_has_no_path(self):
        t = self.graphql
        self.assertIn("Field 'path' in type 'ConfigFile' is undefined", t)
        self.assertRegex(t, r"(?i)introspection is disabled")
        self.assertIn("FieldUndefined", t)
        self.assertRegex(t, r"only `__typename` answers")

    def test_rest_listfiles_shape_and_scope(self):
        self.assertIn('{"paths": [...]}', self.graphql)
        self.assertIn('`POST /sdl/api/listFiles` returns `{"paths": [...]}` '
                      'and honours `S1-Scope`', self.graphql)

    def test_eval_expected_output_drops_blanket_refusal(self):
        blob = (SKILL_DIR / "evals" / "evals.json").read_text(encoding="utf-8")
        self.assertNotIn("The Management Console API token is refused there", blob)
        self.assertIn("User token not allowed for this endpoint", blob)


class ClientSurfaceMatchesTheDocs(unittest.TestCase):
    """The evals drive these method names; a rename must break here first."""

    def setUp(self):
        from sdl_client import SDLClient

        self.cls = SDLClient

    def test_config_file_methods_exist(self):
        for name in ("config_files", "config_file", "put_config_file",
                     "delete_config_file", "query"):
            self.assertTrue(callable(getattr(self.cls, name, None)),
                            f"SDLClient.{name} is gone; the skill documents it")

    def test_writes_accept_the_expected_version_guard(self):
        for name in ("put_config_file", "delete_config_file"):
            params = inspect.signature(getattr(self.cls, name)).parameters
            self.assertIn("expected_version", params,
                          f"{name} lost its concurrent-edit guard")

    def test_config_file_can_be_addressed_by_udo_id(self):
        params = inspect.signature(self.cls.config_file).parameters
        self.assertIn("udo_id", params)
        self.assertIn("udo_id", inspect.signature(
            self.cls.put_config_file).parameters)


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
                failures.append(f"{f.relative_to(ROOT)}:\n"
                                f"{body.strip()[:200]}\n  -> "
                                + "; ".join(problems))
        self.assertEqual([], failures, "\n\n".join(failures))

    def test_some_blocks_were_actually_linted(self):
        self.assertGreaterEqual(sum(1 for _ in self._blocks()), 6)


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

    def test_credential_split_is_covered_by_the_suite(self):
        blob = json.dumps(self.suite)
        self.assertIn("S1_HEC_TOKEN", blob)
        self.assertIn("S1_CONSOLE_API_TOKEN", blob)


if __name__ == "__main__":
    unittest.main()
