"""Tests for the offline parser lint (scripts/parser_rules.py, scripts/lint_parser.py).

No network, no tenant. Every rule has a known-bad parser that must fire it and a
known-good parser that must not, and a meta-test fails if a rule is added without
both. The shipped examples and the eval fixture parsers must lint clean in
authoring (`--new`) mode.

Run:
    python3 -m unittest discover -s sdl-log-parser/tests
"""
from __future__ import annotations

import io
import json
import pathlib
import sys
import unittest
from contextlib import redirect_stdout

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))

import lint_parser  # noqa: E402
import parser_rules as pr  # noqa: E402

BASE = '"dataSource.name": "X", "dataSource.vendor": "V", "dataSource.category": "security", "metadata.version": "1.0.0"'


def P(body: str, attrs: str = BASE) -> str:
    """A parser with valid mandatory attributes plus `body`."""
    return "{ attributes: { %s }, %s }" % (attrs, body)


# rule id -> (bad parser text, good parser text). The bad one must fire the
# rule; the good one must not.
CASES: dict[str, tuple[str, str]] = {
    "R00": ("{ formats: [ ", P('formats: [{ format: "$a$" }]')),
    "R01": (P('formats: [{ format: "$_=identifier$=$_=quoteOrSpace$", repeat: true }]'),
            P('formats: [{ format: ".*$_=identifier$=$_=quoteOrSpace$", repeat: true }]')),
    "R02": (P('formats: [{ format: ".*$_=identifier$=$_=quoteOrSpace$" }]'),
            P('formats: [{ format: ".*$_=identifier$=$_=quoteOrSpace$", repeat: true }]')),
    # Live 2026-10-13: v0 constant keyed `output` is rejected by putFile; keyed
    # `field` it deploys and applies.
    "R03": (P('mappings: { version: 0, mappings: [{ predicate: "true", '
              'constants: [{ output: "class_uid", value: 4001, type: "int" }] }] }'),
            P('mappings: { version: 0, mappings: [{ predicate: "true", '
              'constants: [{ field: "class_uid", value: 4001, type: "int" }] }] }')),
    "R04": (P('mappings: { mappings: [{ predicate: "true", transformations: [] }] }'),
            P('mappings: { version: 1, mappings: [{ predicate: "true", transformations: [] }] }')),
    "R05": (P('formats: [{ format: "$severity$ $msg$", attributes: { severity_id: 3 } }]'),
            P('formats: [{ format: "$severity_name$ $msg$", attributes: { severity_id: 3 } }]')),
    "R06": (P('mappings: { version: 1, mappings: [{ predicate: "true", transformations: '
              '[{ rename: { from: "action", to: "action" } }] }] }'),
            P('mappings: { version: 1, mappings: [{ predicate: "true", transformations: '
              '[{ rename: { from: "act", to: "action" } }] }] }')),
    "R07": (P('mappings: { version: 1, mappings: ['
              '{ predicate: "true", transformations: [] },'
              '{ predicate: "a == \'b\'", transformations: [] }] }'),
            P('mappings: { version: 1, mappings: ['
              '{ predicate: "a == \'b\'", transformations: [] },'
              '{ predicate: "true", transformations: [] }] }')),
    "R08": (P('formats: [{ format: "COMMAND=$cmd{regex=.*}$" }]'),
            P('formats: [{ format: "COMMAND=$cmd{regex=[\\\\s\\\\S]+}$" }]')),
    "R09": (P('formats: [{ format: "$_pre{regex=.*?x}$$v$" }]'),
            P('formats: [{ format: "$_pre{regex=[\\\\s\\\\S]*x}$$v$" }]')),
    "R10": (P('formats: [{ format: "$_pre{regex=[\\\\s\\\\S]*?}$$v{regex=/bin/[\\\\s\\\\S]+}$" }]'),
            P('formats: [{ format: "$_pre{regex=[\\\\s\\\\S]*k=}$$v$" }]')),
    "R11": (P('formats: [{ format: "$proc{regex=CRON|CROND}$ $msg$" }]'),
            P('formats: [{ format: "$proc{regex=CROND|CRON}$ $msg$" }]')),
    "R12": (P('discardAttributes: ["_pre"], formats: [{ format: "$_pre{regex=[\\\\s\\\\S]*x}$$v$" }]'),
            P('formats: [{ format: "$_pre{regex=[\\\\s\\\\S]*x}$$v$", discardAttributes: ["_pre"] }]')),
    "R13": (P('mappings: { version: 1, mappings: [{ predicate: "true", transformations: '
              '[{ rename: { from: "unmapped.user\\\\.email", to: "actor.user.email_addr" } }] }] }'),
            P('mappings: { version: 1, mappings: [{ predicate: "true", transformations: '
              '[{ rename: { from: "unmapped.user.email", to: "actor.user.email_addr" } }] }] }')),
    "R14": (P('formats: [{ format: "$a$" }]', attrs='"dataSource.category": "security", "metadata.version": "1.0.0"'),
            P('formats: [{ format: "$a$" }]')),
    "R15": (P('formats: [{ format: "$a$" }]',
              attrs='"dataSource.name": "X", "dataSource.vendor": "V", "dataSource.category": "network", "metadata.version": "1.0.0"'),
            P('formats: [{ format: "$a$" }]')),
    "R16": (P('formats: [{ format: "$a$" }]',
              attrs='"dataSource.name": "X", "dataSource.vendor": "V", "dataSource.category": "security"'),
            P('formats: [{ format: "$a$" }]')),
    "R17": (P('formats: [{ format: "$a$" }]',
              attrs='"dataSource.name": "claude_test_fw", "dataSource.vendor": "V", "dataSource.category": "security", "metadata.version": "1.0.0"'),
            P('formats: [{ format: "$a$" }]')),
    "R18": (P('formats: [{ format: "<$pri{parse=syslogPriority}$>$msg$" }]'),
            P('formats: [{ format: "<$pri{regex=\\\\d+}$>$msg$" }]')),
    # R19-R22: each bad case reproduces a putFile 400 seen live on 2026-10-13.
    "R19": (P('mappings: { version: 1, mappings: [{ predicate: "true", transformations: '
              '[{ _comment: "x", rename: { from: "a", to: "b" } }] }] }'),
            P('mappings: { version: 1, mappings: [{ predicate: "true", transformations: '
              '[ /* x */ { rename: { from: "a", to: "b" } }] }] }')),
    "R20": (P('mappings: { version: 1, mappings: [{ predicate: "true", transformations: '
              '[{ regex: { field: "a", match: "x" } }] }] }'),
            P('mappings: { version: 1, mappings: [{ predicate: "true", transformations: '
              '[{ replace: { field: "a", match: "x", replace: "y" } }] }] }')),
    "R21": (P('patterns: { qs: "\\"[^\\"]*\\"" }, formats: [{ format: "t=$qs{name=t}$" }]'),
            P('patterns: { qs: "\\"[^\\"]*\\"" }, formats: [{ format: "t=$t=qs$" }]')),
    "R22": (P('mappings: { version: 1, mappings: [{ predicate: "rules[].action = *", '
              'transformations: [] }] }'),
            P('mappings: { version: 1, mappings: [{ predicate: "rules[0].action = *", '
              'transformations: [] }] }')),
}


def ids(text: str, **kw) -> set[str]:
    return {f.rule for f in pr.lint_text(text, **kw)}


class EveryRuleIsTested(unittest.TestCase):
    def test_each_rule_has_a_bad_and_good_case(self):
        missing = [r.id for r in pr.RULES if r.id not in CASES]
        self.assertEqual([], missing, "rules with no test case")

    def test_each_rule_cites_the_skill(self):
        for r in pr.RULES:
            self.assertTrue(r.ref.startswith(("SKILL.md", "references/")), r.id)
            self.assertIn(r.severity, pr.SEVERITIES, r.id)


class BadFiresGoodDoesNot(unittest.TestCase):
    def test_bad_cases_fire(self):
        silent = [rid for rid, (bad, _) in CASES.items() if rid not in ids(bad)]
        self.assertEqual([], silent, "bad case did not fire its rule")

    def test_good_cases_stay_silent(self):
        noisy = {rid: sorted(ids(good)) for rid, (_, good) in CASES.items() if ids(good)}
        self.assertEqual({}, noisy, "known-good parser produced findings")


class FalsePositiveGuards(unittest.TestCase):
    """Shapes found in the ai-siem catalog that are deliberate, not traps."""

    def test_positional_identifier_capture_is_not_the_kv_idiom(self):
        t = P('formats: [{ format: "x $_=identifier$=$_=identifier$\\\\|$_=identifier$=$_$" }]')
        self.assertNotIn("R02", ids(t))

    def test_explicit_repeat_false_is_respected(self):
        t = P('formats: [{ format: ".*$_=identifier$=$_=quoteOrSpace$", repeat: false }]')
        self.assertNotIn("R02", ids(t))

    def test_unused_pattern_is_not_flagged(self):
        t = P('patterns: { rt: "(A|AAAA)" }, formats: [{ format: "q=$q$" }]')
        self.assertNotIn("R11", ids(t))
        used = P('patterns: { rt: "(A|AAAA)" }, formats: [{ format: "q=$q=rt$" }]')
        self.assertIn("R11", ids(used))

    def test_rewrite_regex_alternation_backtracks_normally(self):
        t = P('formats: [{ format: "$a$", rewrites: [{ input: "a", output: "a", '
              'match: "(block|blocked)", replace: "x" }] }]')
        self.assertNotIn("R11", ids(t))

    def test_datasource_set_per_format_or_by_mapping_counts(self):
        per_format = P('formats: [{ format: "$a$", attributes: { "dataSource.name": "X", '
                       '"dataSource.vendor": "V", "dataSource.category": "security" } }]',
                       attrs='"metadata.version": "1.0.0"')
        self.assertNotIn("R14", ids(per_format))
        by_mapping = P('formats: [{ format: "$a$" }], mappings: { version: 1, mappings: '
                       '[{ predicate: "true", transformations: [{ constant: { field: '
                       '"dataSource.name", value: "X" } }] }] }',
                       attrs='"dataSource.vendor": "V", "dataSource.category": "security", '
                             '"metadata.version": "1.0.0"')
        self.assertNotIn("R14", ids(by_mapping))

    def test_alias_parser_needs_no_attributes(self):
        self.assertEqual(set(), ids('{ aliasTo: "json" }', new=True))

    def test_v0_same_name_rename_is_not_flagged(self):
        # Live 2026-10-13: a same-name v0 rename keeps the value; only v1 nulls it.
        t = P('mappings: { version: 0, mappings: [{ predicate: "true", renames: '
              '[{ inputs: ["a"], output: "a", type: "string" }] }] }')
        self.assertNotIn("R06", ids(t))

    def test_lazy_prefix_with_a_literal_anchor_is_not_flagged(self):
        # Live 2026-10-13: `[\s\S]*?COMMAND=` captured correctly.
        t = P('formats: [{ format: "$_pre{regex=[\\\\s\\\\S]*?COMMAND=}$$v$", '
              'discardAttributes: ["_pre"] }]')
        self.assertNotIn("R10", ids(t))


class AuthoringModeIsStricter(unittest.TestCase):
    def test_hard_rules_escalate_to_error_with_new(self):
        bad = CASES["R16"][0]
        self.assertEqual({"INFO"}, {f.severity for f in pr.lint_text(bad) if f.rule == "R16"})
        self.assertEqual({"ERROR"}, {f.severity for f in pr.lint_text(bad, new=True) if f.rule == "R16"})


class Reader(unittest.TestCase):
    def test_augmented_json_features(self):
        obj, lines = pr.load_augmented_json(
            '// lead\n{ /* c */ a: "x" + "y", \'b\': [1, 2,], c: true, }\n')
        self.assertEqual({"a": "xy", "b": [1, 2], "c": True}, obj)
        self.assertEqual(2, lines["a"])

    def test_unknown_escapes_survive_for_regex_text(self):
        obj, _ = pr.load_augmented_json('{ f: "\\\\[$a$\\\\]" }')
        self.assertEqual("\\[$a$\\]", obj["f"])

    def test_hash_is_not_a_comment(self):
        with self.assertRaises(pr.ParseError):
            pr.load_augmented_json("# placeholder\n")

    def test_comments_only_file_is_reported(self):
        with self.assertRaisesRegex(pr.ParseError, "comments only"):
            pr.load_augmented_json("// nothing here\n")


class ShippedParsersAreClean(unittest.TestCase):
    def test_examples_and_fixture_parsers_lint_clean_in_authoring_mode(self):
        files = sorted((SKILL_DIR / "examples").glob("*.json"))
        files += sorted((SKILL_DIR / "evals" / "fixtures").rglob("*_parser.json"))
        self.assertGreaterEqual(len(files), 10)
        dirty = {f.name: [(x.rule, x.path) for x in pr.lint_text(f.read_text(), new=True)]
                 for f in files}
        self.assertEqual({}, {k: v for k, v in dirty.items() if v})


class Cli(unittest.TestCase):
    def run_cli(self, *args) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = lint_parser.main(list(args))
        return code, buf.getvalue()

    def test_exit_code_and_disclaimer(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            bad = pathlib.Path(d, "bad.conf")
            bad.write_text(CASES["R01"][0])
            good = pathlib.Path(d, "good.conf")
            good.write_text(CASES["R01"][1])
            code, out = self.run_cli(str(good))
            self.assertEqual(0, code)
            self.assertIn("does not prove the parser parses", out)
            code, out = self.run_cli(str(bad))
            self.assertEqual(1, code)
            self.assertIn("R01", out)
            code, out = self.run_cli("--json", d)
            data = json.loads(out)
            self.assertEqual(2, len(data["files"]))
            self.assertIn("disclaimer", data)

    def test_directory_walk_skips_non_parser_json(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, "query_result.json").write_text('{"row_count": 3}')
            pathlib.Path(d, "p.json").write_text(CASES["R01"][1])
            code, out = self.run_cli(d)
            self.assertIn("1 file(s)", out)


if __name__ == "__main__":
    unittest.main()
