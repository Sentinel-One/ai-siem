"""Structural tests for the `sdl-api` skill. No network, no tenant.

These pin the facts a careless edit would erase, each of which has a concrete
failure attached:

1. The ingest credential split. Raw log ingest needs an SDL Log Write Key in
   `S1_HEC_TOKEN`; the console token is refused with HTTP 400 "Missing S1-Scope
   header". UAM alert ingest at /v1/alerts is the other path and does use the
   console token with S1-Scope.
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

    def test_console_token_is_documented_as_refused(self):
        self.assertIn("Missing S1-Scope header", self.skill)
        self.assertRegex(
            self.skill, r"(?i)console\s+(?:API\s+)?token[^.]{0,80}refused|"
                        r"refused[^.]{0,80}console",
            "the console-token-is-refused fact is no longer stated")

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
