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


if __name__ == "__main__":
    unittest.main()
