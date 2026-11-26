"""Tests for the Hyperautomation action library shipped with the skill. No network, no tenant.

1. The library and template files load, their counts match what the docs state, and every
   `public_action_id` is unique.
2. `scripts/find_action.py` ranks a name match first, resolves an older id to the entry derived
   from it, returns exit status 1 when nothing matches, and searches the templates.
3. Every `public_action_id` hard-coded in a shipped workflow template or reference is a current
   library entry. A stale id imports without complaint, so only this test catches it.
4. The usage catalog carries no per-action ids (they come from the library) and no names of
   individual custom integrations.

Run:
    python3 -m unittest discover -s hyperautomation/tests
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import unittest

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
SKILLS_ROOT = SKILL_DIR.parent
ASSETS = SKILL_DIR / "assets"
FIND = SKILL_DIR / "scripts" / "find_action.py"
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _lib():
    return json.loads((ASSETS / "action-library.json").read_text(encoding="utf-8"))


def _templates():
    return json.loads((ASSETS / "marketplace-templates.json").read_text(encoding="utf-8"))


def _find(*args):
    return subprocess.run([sys.executable, str(FIND), *args], capture_output=True, text=True, timeout=60)


class LibraryFilesAreConsistent(unittest.TestCase):
    def test_counts_match_the_entries(self):
        lib = _lib()
        actions = [a for g in lib["integrations"] for a in g["actions"]]
        self.assertEqual(lib["counts"]["actions"], len(actions))
        self.assertEqual(lib["counts"]["integrations"], len(lib["integrations"]))
        self.assertEqual(_templates()["counts"]["templates"], len(_templates()["templates"]))

    def test_public_action_ids_are_unique(self):
        ids = [a["public_action_id"] for g in _lib()["integrations"] for a in g["actions"]]
        self.assertEqual(len(ids), len(set(ids)))
        for i in ids:
            self.assertRegex(i, f"^{UUID}$")

    def test_every_entry_has_what_an_author_needs(self):
        for g in _lib()["integrations"]:
            self.assertRegex(g["integration_id"], f"^{UUID}$")
            for a in g["actions"]:
                self.assertTrue(a["name"], a)
                if a.get("type") == "http_request":
                    self.assertTrue(a.get("method"), a)

    def test_docs_state_the_same_counts(self):
        lib, tpl = _lib(), _templates()
        acts = f"{lib['counts']['actions']:,} packaged actions"
        ints = f"{lib['counts']['integrations']} integrations"
        tpls = f"{tpl['counts']['templates']} "
        expected = {
            SKILL_DIR / "SKILL.md": (acts, ints, tpls),
            SKILL_DIR / "README.md": (acts, ints, tpls),
            SKILL_DIR / "references/action-library-index.md": (acts, ints),
            SKILL_DIR / "references/marketplace-templates.md": (tpls,),
            SKILL_DIR / "references/integration-catalog.md": (f"{lib['counts']['actions']:,} across", ints),
            SKILL_DIR / "references/building-blocks-catalog.md": (acts, ints),
        }
        # Release docs live outside the skill: docs/ and the CHANGELOG in the source repo,
        # plugins/s1-secops-skills/docs/ and mcp/ in ai-siem. Check whichever is present.
        for rel, needles in (("docs/upgrading.md", (acts, ints, tpls)),
                             ("s1-secops-mcp/CHANGELOG.md", (acts, ints, tpls))):
            for base in (SKILLS_ROOT, SKILLS_ROOT.parent, SKILLS_ROOT.parents[2] / "mcp"):
                path = base / rel
                if path.is_file():
                    expected[path] = needles
                    break
        for path, needles in expected.items():
            text = " ".join(path.read_text(encoding="utf-8").split())
            for needle in needles:
                self.assertTrue(needle in text, f"{path.name} should state '{needle.strip()}'")


class FindActionBehaves(unittest.TestCase):
    def test_name_match_ranks_first(self):
        r = _find("--json", "--limit", "1", "slack", "post", "message")
        self.assertEqual(r.returncode, 0, r.stderr)
        top = json.loads(r.stdout)["results"][0]
        self.assertEqual(top["name"], "Post Message")
        self.assertEqual(top["integration"], "Slack")

    def test_an_older_id_resolves_to_the_entry_derived_from_it(self):
        lib = _lib()
        derived = next(a for g in lib["integrations"] for a in g["actions"] if a.get("derived_from"))
        r = _find("--json", "--id", derived["derived_from"][0])
        self.assertEqual(r.returncode, 0, r.stderr)
        got = {x["public_action_id"] for x in json.loads(r.stdout)["results"]}
        self.assertIn(derived["public_action_id"], got)

    def test_no_match_exits_1(self):
        r = _find("zz-no-such-action-anywhere")
        self.assertEqual(r.returncode, 1)

    def test_template_search(self):
        r = _find("--templates", "--json", "sentinelone")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertGreater(json.loads(r.stdout)["total"], 0)


def _ids_in_tables_with_an_id_column(text):
    """UUIDs in markdown table rows under a header that names `public_action_id`."""
    out, in_table = [], False
    for line in text.splitlines():
        if line.startswith("|") and "public_action_id" in line:
            in_table = True
            continue
        if in_table and line.startswith("|"):
            out += re.findall(f"`({UUID})`", line)
        else:
            in_table = False
    return out


class ShippedIdsAreCurrent(unittest.TestCase):
    def test_every_hard_coded_public_action_id_is_in_the_library(self):
        live = {a["public_action_id"] for g in _lib()["integrations"] for a in g["actions"]}
        found = {}
        for path in SKILLS_ROOT.glob("*/**/*"):
            if path.suffix not in (".json", ".md") or "assets/action-library" in str(path) \
                    or "/evals/" in str(path) or "/spec/" in str(path) or not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if "public_action_id" not in text:
                continue
            ids = re.findall(r'public_action_id\\?"?\s*:\s*\\?"(' + UUID + ')', text)
            ids += _ids_in_tables_with_an_id_column(text)
            for i in ids:
                found.setdefault(i, []).append(str(path.relative_to(SKILLS_ROOT)))
        self.assertTrue(found, "expected at least one hard-coded id to check")
        stale = {i: p for i, p in found.items() if i not in live}
        self.assertEqual(stale, {}, "ids not in assets/action-library.json; look them up with "
                                    "scripts/find_action.py --id <id>")


class ScannerNotesStayNarrow(unittest.TestCase):
    def test_every_trufflehog_ignore_sits_on_a_line_with_a_library_id(self):
        # The generator marks only lines whose secret-scan hits are library ids. A marker on
        # any other line, or a flood of them, would hide a real secret from the scan.
        lib = _lib()
        ids = {g["integration_id"] for g in lib["integrations"]}
        ids |= {a["public_action_id"] for g in lib["integrations"] for a in g["actions"]}
        total = 0
        for rel in ("assets/action-library.json", "assets/marketplace-templates.json",
                    "references/action-library-index.md", "references/marketplace-templates.md"):
            for n, line in enumerate((SKILL_DIR / rel).read_text(encoding="utf-8").splitlines(), 1):
                if "trufflehog:ignore" in line:
                    total += 1
                    self.assertTrue(any(i in line for i in ids), f"{rel}:{n} marker without a library id")
        self.assertLess(total, 50, "too many scanner markers; look at the generator output")


class CatalogCarriesNoIdsOrNames(unittest.TestCase):
    def test_no_per_action_id_column(self):
        text = (SKILL_DIR / "references/integration-catalog.md").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"(?m)^\|.*`" + UUID + r"`\s*\|\s*$")
        self.assertNotIn("on this tenant", text)

    def test_custom_integrations_are_summarised_not_listed(self):
        text = (SKILL_DIR / "references/integration-catalog.md").read_text(encoding="utf-8")
        section = text.split("## Custom integrations", 1)[1]
        self.assertNotIn("| Integration | Ad-hoc calls", section)


if __name__ == "__main__":
    unittest.main()
