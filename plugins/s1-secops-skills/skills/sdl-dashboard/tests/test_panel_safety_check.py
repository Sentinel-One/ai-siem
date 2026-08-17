"""
Tests for panel_safety_check, focused on the site-scope rules S01 and S02.

Run: python3 -m unittest discover -s sdl-dashboard/tests -v
     (or) python3 sdl-dashboard/tests/test_panel_safety_check.py

Stdlib only, no tenant and no credentials.

Why S01/S02 exist, measured on usea1-purple 2026-08-17 for site Metacortex
(id 2547662415802335157):

    site.id='2547662415802335157'                    -> 60,410 events
    site.id='...' AND site.name is null              ->    510 events
      of which: ActivityFeed 172, asset 111, (null source) 99,
                SentinelOne 70, Windows Event Logs 48, alert 10

So a `site.name` filter silently drops alert and asset records: exactly the
record types a SOC dashboard leans on. S02 catches that substitution, S01
catches a site-deployed dashboard with no site predicate at all.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import panel_safety_check as psc  # noqa: E402

SITE_ID = "2547662415802335157"
OTHER_SITE_ID = "2175066823985525506"


def dash(*panels):
    """Minimal TABBED dashboard wrapping the given panels."""
    return {"configType": "TABBED", "tabs": [{"tabName": "t", "graphs": list(panels)}]}


def number(query, title="n"):
    return {"graphStyle": "number", "title": title, "query": query,
            "layout": {"x": 0, "y": 0, "w": 15, "h": 10}}


def ids(issues):
    return sorted({rule_id for rule_id, _, _ in issues})


class TestS01SiteScopeMissing(unittest.TestCase):
    def test_no_site_id_given_means_rule_is_off(self):
        d = dash(number("event.time=* | group c=count() | limit 1"))
        self.assertNotIn("S01", ids(psc.check(d, [])))

    def test_flags_panel_with_no_site_predicate(self):
        d = dash(number("event.time=* | group c=count() | limit 1"))
        issues = psc.check(d, [], site_id=SITE_ID)
        self.assertIn("S01", ids(issues))
        self.assertIn(SITE_ID, issues[0][2], "the message must name the target site id")

    def test_passes_when_panel_scopes_to_the_target_site(self):
        d = dash(number(f"site.id='{SITE_ID}' | group c=count() | limit 1"))
        self.assertNotIn("S01", ids(psc.check(d, [], site_id=SITE_ID)))

    def test_flags_panel_scoped_to_a_DIFFERENT_site(self):
        # The cross-boundary case: filters on site.id, but the wrong one. Left
        # unflagged this is the silent-zero-panel defect.
        d = dash(number(f"site.id='{OTHER_SITE_ID}' | group c=count() | limit 1"))
        issues = psc.check(d, [], site_id=SITE_ID)
        self.assertIn("S01", ids(issues))
        self.assertIn("not on the target site id", issues[0][2])

    def test_allow_account_scope_queries_suppresses_S01(self):
        d = dash(number("event.time=* | group c=count() | limit 1"))
        issues = psc.check(d, [], site_id=SITE_ID, allow_account_scope_queries=True)
        self.assertNotIn("S01", ids(issues))

    def test_allow_account_scope_queries_does_not_suppress_other_rules(self):
        # N01: number panel without `| limit 1`.
        d = dash(number("event.time=* | group c=count()"))
        issues = psc.check(d, [], site_id=SITE_ID, allow_account_scope_queries=True)
        self.assertIn("N01", ids(issues))

    def test_markdown_panels_are_exempt(self):
        d = dash({"graphStyle": "markdown", "title": "hdr", "markdown": "text",
                  "layout": {"x": 0, "y": 0, "w": 60, "h": 5}})
        self.assertNotIn("S01", ids(psc.check(d, [], site_id=SITE_ID)))

    def test_panel_without_a_query_is_exempt(self):
        d = dash({"graphStyle": "alerts_table", "title": "a",
                  "layout": {"x": 0, "y": 0, "w": 30, "h": 10}})
        self.assertNotIn("S01", ids(psc.check(d, [], site_id=SITE_ID)))

    def test_S01_is_ignorable(self):
        d = dash(number("event.time=* | group c=count() | limit 1"))
        self.assertNotIn("S01", ids(psc.check(d, ["S01"], site_id=SITE_ID)))

    def test_every_offending_panel_is_reported(self):
        d = dash(
            number("event.time=* | group c=count() | limit 1", "a"),
            number(f"site.id='{SITE_ID}' | group c=count() | limit 1", "b"),
            number("event.type=* | group c=count() | limit 1", "c"),
        )
        s01 = [i for i in psc.check(d, [], site_id=SITE_ID) if i[0] == "S01"]
        self.assertEqual(len(s01), 2, "only the two unscoped panels should flag")


class TestS02SiteNameAsScope(unittest.TestCase):
    def test_flags_site_name_equality_filter(self):
        d = dash(number("site.name='Metacortex' | group c=count() | limit 1"))
        issues = psc.check(d, [])
        self.assertIn("S02", ids(issues))

    def test_message_explains_the_dropped_records(self):
        d = dash(number("site.name='Metacortex' | group c=count() | limit 1"))
        msg = [i[2] for i in psc.check(d, []) if i[0] == "S02"][0]
        self.assertIn("site.id", msg)
        self.assertIn("alert", msg)

    def test_flags_site_name_contains(self):
        d = dash(number("site.name contains:anycase(\"meta\") | group c=count() | limit 1"))
        self.assertIn("S02", ids(psc.check(d, [])))

    def test_not_flagged_when_site_id_is_also_present(self):
        # site.name as a display/grouping column alongside a site.id filter is fine.
        d = dash(number(f"site.id='{SITE_ID}' site.name='Metacortex' | group c=count() | limit 1"))
        self.assertNotIn("S02", ids(psc.check(d, [])))

    def test_grouping_by_site_name_is_not_a_scope_filter(self):
        d = dash(number("event.time=* | group c=count() by site.name | limit 1"))
        self.assertNotIn("S02", ids(psc.check(d, [])))

    def test_S02_fires_independently_of_site_id_argument(self):
        d = dash(number("site.name='Metacortex' | group c=count() | limit 1"))
        self.assertIn("S02", ids(psc.check(d, [], site_id=None)))

    def test_S02_is_ignorable(self):
        d = dash(number("site.name='Metacortex' | group c=count() | limit 1"))
        self.assertNotIn("S02", ids(psc.check(d, ["S02"])))


class TestExistingRulesStillPass(unittest.TestCase):
    """Regression guard: the scope rules must not disturb the existing checks."""

    def test_clean_site_scoped_dashboard_has_no_issues(self):
        d = dash(
            {"graphStyle": "markdown", "title": "hdr", "markdown": "x",
             "layout": {"x": 0, "y": 0, "w": 60, "h": 5}},
            number(f"site.id='{SITE_ID}' | group c=count() | limit 1", "kpi"),
            {"graphStyle": "", "title": "tbl",
             "query": f"site.id='{SITE_ID}' | group c=count() by event.type | sort -c | limit 25",
             "layout": {"x": 0, "y": 15, "w": 30, "h": 16}},
        )
        self.assertEqual(psc.check(d, [], site_id=SITE_ID), [])

    def test_transpose_terminal_rule_still_fires(self):
        d = dash({"graphStyle": "stacked_bar", "title": "t",
                  "query": f"site.id='{SITE_ID}' | group c=count() by timestamp=timebucket(\"1h\"), "
                           "endpoint.name | transpose endpoint.name on timestamp | limit 10",
                  "layout": {"x": 0, "y": 0, "w": 60, "h": 16}})
        self.assertIn("P01", ids(psc.check(d, [], site_id=SITE_ID)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
