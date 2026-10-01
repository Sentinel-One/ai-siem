"""Offline checks for the live PowerQuery regression cases. No network, no tenant.

The live suite (tools/pq_live_regression.py) proves documented behaviour against
a real tenant. These tests keep the case file honest without one:

1. Every case is structurally runnable: unique id, a query, one known expectation.
2. No case carries tenant-identifying data. The cases ship in a public repo, so
   a pasted hostname, user, IP address, email or console URL is a leak.
3. Docs and cases stay in step: every `regression case \\`<id>\\`` the skill's
   markdown cites must exist in the case file, so a renamed or deleted case
   cannot leave a doc pointing at a test that no longer runs.

Run:
    python3 -m unittest discover -s powerquery/tests
"""
from __future__ import annotations

import json
import pathlib
import re
import unittest

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
CASES_FILE = SKILL_DIR / "tests" / "live" / "pq_live_cases.json"
EXPECT_KINDS = {"ok", "error_contains", "min_rows", "max_rows", "exact_rows",
                "columns_include", "first_row", "compare"}
COMPARE_KINDS = {"count_eq", "count_lt", "rows_eq", "rows_lt"}

PII_PATTERNS = {
    "IPv4 address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email address": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
    "console URL": re.compile(r"sentinelone\.net|https?://", re.I),
    "DOMAIN\\user account": re.compile(r"\b[A-Za-z0-9-]{2,}\\+[A-Za-z][\w.$-]{2,}"),
    "Windows host name": re.compile(r"\b(?:DESKTOP|LAPTOP|WIN)-[A-Z0-9]{5,}\b"),
    "long hex id": re.compile(r"\b[0-9a-f]{16,}\b", re.I),
}


# RFC 5737 documentation ranges and RFC 1918 10/8: safe in synthetic fixtures.
SAFE_IP_PREFIXES = ("10.", "192.0.2.", "198.51.100.", "203.0.113.")


def load_cases() -> list[dict]:
    return json.loads(CASES_FILE.read_text())["cases"]


class LiveCaseFile(unittest.TestCase):
    def test_cases_are_runnable(self):
        cases = load_cases()
        self.assertGreater(len(cases), 0)
        ids = [c["id"] for c in cases]
        self.assertEqual(len(ids), len(set(ids)), "duplicate case ids")
        for c in cases:
            with self.subTest(case=c["id"]):
                self.assertTrue(c.get("query", "").strip())
                exp = c["expect"]
                kinds = EXPECT_KINDS & set(exp)
                self.assertEqual(len(kinds), 1, f"exactly one expectation kind, got {sorted(exp)}")
                if "compare" in exp:
                    self.assertIn(exp["compare"], COMPARE_KINDS)
                    self.assertTrue(exp.get("with", "").strip())

    def test_cases_carry_no_tenant_data(self):
        for c in load_cases():
            blob = json.dumps(c)
            for label, pat in PII_PATTERNS.items():
                with self.subTest(case=c["id"], check=label):
                    self.assertIsNone(pat.search(blob), f"{label} in case {c['id']}")

    def test_fixtures_are_synthetic_and_referenced(self):
        data = json.loads(CASES_FILE.read_text())
        paths = {f["path"] for f in data.get("fixtures", [])}
        for f in data.get("fixtures", []):
            with self.subTest(fixture=f["path"]):
                name = f["path"].rsplit("/", 1)[-1]
                self.assertTrue(f["path"].startswith("/datatables/"))
                self.assertTrue(name.startswith(("zz_pqreg_", "zz-pqreg-")),
                                "fixtures must be zz_pqreg_ named so cleanup can find them")
                # Only documentation / private ranges, never a real address.
                for ip in PII_PATTERNS["IPv4 address"].findall(f["content"]):
                    self.assertTrue(ip.startswith(SAFE_IP_PREFIXES), f"non-synthetic IP {ip}")
                for label, pat in PII_PATTERNS.items():
                    if label == "IPv4 address":
                        continue
                    self.assertIsNone(pat.search(f["content"]), f"{label} in {f['path']}")
        for c in data["cases"]:
            for p in c.get("fixtures", []):
                with self.subTest(case=c["id"], fixture=p):
                    self.assertIn(p, paths, "case needs a fixture that is not defined")

    def test_docs_cite_only_existing_cases(self):
        ids = {c["id"] for c in load_cases()}
        cite = re.compile(r"regression cases? ((?:`[^`]+`(?:, | and )?)+)")
        for md in SKILL_DIR.rglob("*.md"):
            for m in cite.finditer(md.read_text()):
                for ref in re.findall(r"`([^`]+)`", m.group(1)):
                    with self.subTest(doc=md.name, ref=ref):
                        if ref.endswith("*"):
                            prefix = ref[:-1]
                            self.assertTrue(any(i.startswith(prefix) for i in ids),
                                            f"{md.name} cites {ref}, no case matches")
                        else:
                            self.assertIn(ref, ids, f"{md.name} cites missing case {ref}")


if __name__ == "__main__":
    unittest.main()
