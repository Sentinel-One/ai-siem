"""Offline: run_pq excludes SDL ingest-metering rows (tag='logVolume') by default.

Mirrors s1-secops-mcp/tests/regressions-2026-10-03.test.mjs so the Python and
MCP rewrites stay identical. No network.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import pq  # noqa: E402

CASES = [
    ("| group n=count() by dataSource.name",
     "tag != 'logVolume' | group n=count() by dataSource.name"),
    ("dataSource.name='Okta' | group n=count()",
     "tag != 'logVolume' and (dataSource.name='Okta'\n) | group n=count()"),
    ("a='x' or b='y'", "tag != 'logVolume' and (a='x' or b='y'\n)"),
    ("cmd contains 'a|b' | limit 5",
     "tag != 'logVolume' and (cmd contains 'a|b'\n) | limit 5"),
    ("dataSource.name='X' tag='logVolume' | group n=count()", None),
    ("| datasource alerts | limit 5", None),
    ("| join a=(x=1), b=(y=2) on k", None),
    ("| union (a=1), (b=2)", None),
]


class TestMeteringExclusion(unittest.TestCase):
    def test_rewrite_table(self):
        for src, want in CASES:
            q, applied, _ = pq.exclude_metering(src)
            if want is None:
                self.assertFalse(applied, src)
                self.assertEqual(q, src)
            else:
                self.assertTrue(applied, src)
                self.assertEqual(q, want)


class TestFirstTopLevelPipe(unittest.TestCase):
    """The split point must ignore pipes inside quotes and inside parentheses.

    Regression: a subquery in the initial filter used to be split at its own `|`,
    which sent unbalanced parentheses and got HTTP 400 `Expected ")"`.
    """

    def test_subquery_in_initial_filter(self):
        q = "f in (a='x' | group 1 by f) | group n=count()"
        self.assertEqual(pq._first_top_level_pipe(q), q.index(") |") + 2)
        sent, applied, _ = pq.exclude_metering(q)
        self.assertTrue(applied)
        self.assertEqual(
            sent,
            "tag != 'logVolume' and (f in (a='x' | group 1 by f)\n) | group n=count()")
        self.assertEqual(sent.count("("), sent.count(")"))

    def test_quoted_pipe(self):
        q = "cmd contains 'a|b' and x=\"c|d\" | limit 5"
        self.assertEqual(pq._first_top_level_pipe(q), q.index(" | limit") + 1)

    def test_escaped_quote_inside_string(self):
        q = "cmd contains 'it\\'s | here' | limit 1"
        self.assertEqual(pq._first_top_level_pipe(q), q.index(" | limit") + 1)

    def test_pipe_in_parentheses_in_later_stage_untouched(self):
        q = "a=1 | filter b in (c=2 | group 1 by b) | limit 3"
        self.assertEqual(pq._first_top_level_pipe(q), q.index(" | filter") + 1)
        sent, applied, _ = pq.exclude_metering(q)
        self.assertTrue(applied)
        self.assertEqual(
            sent, "tag != 'logVolume' and (a=1\n) | filter b in (c=2 | group 1 by b) | limit 3")

    def test_no_pipe(self):
        self.assertEqual(pq._first_top_level_pipe("a=1 and (b=2 or c=3)"), -1)


if __name__ == "__main__":
    unittest.main()
