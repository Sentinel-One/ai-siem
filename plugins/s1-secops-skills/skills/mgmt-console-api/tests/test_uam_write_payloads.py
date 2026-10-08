#!/usr/bin/env python3
"""Hermetic tests for the UAM write wrappers' request payloads.

Why this file exists: `assign_alerts` sent `{"assignUser": {"userEmail": ...}}`,
which the API rejects with a GraphQL ValidationError ("field name 'userEmail'
that is not defined for input object type 'AssignUserInput'", verified live
2026-10-08). The console sends the numeric user id as a string under `value`,
and `value: null` unassigns. `set_analyst_verdict` documented verdicts
(`TRUE_POSITIVE`, `SUSPICIOUS`) that are not enum values.

No network, no credentials: a fake client records every request and returns
canned responses in the live API's shape.
"""
from __future__ import annotations

import pathlib
import sys
import unittest

SKILL_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_DIR / "scripts"))

import unified_alerts as ua  # noqa: E402

ALERT = "01a07b29-6ff2-703a-b072-3e71ae617b6e"
SCOPE = {"scopeIds": ["1234567890"], "scopeType": "ACCOUNT"}


class FakeClient:
    """Records GET and POST calls; answers like the Mgmt API and UAM GraphQL."""

    def __init__(self, users=None):
        self.users = users or []
        self.gets = []
        self.posts = []

    def get(self, path, params=None):
        self.gets.append((path, dict(params or {})))
        return {"data": list(self.users), "pagination": {"totalItems": len(self.users)}}

    def post(self, path, json_body=None, params=None, allow_retry=False):
        self.posts.append((path, json_body, allow_retry))
        action_id = json_body["variables"]["actions"][0]["id"]
        return {"data": {"alertTriggerActions": {
            "__typename": "ActionsTriggered",
            "actions": [{"actionId": action_id, "success": [{"id": ALERT}],
                         "skip": [], "failure": []}],
        }}}

    def sent_actions(self):
        self.assert_one_post()
        return self.posts[0][1]["variables"]["actions"]

    def assert_one_post(self):
        if len(self.posts) != 1:
            raise AssertionError(f"expected one POST, got {len(self.posts)}")


class AssignAlertsPayload(unittest.TestCase):

    def test_user_id_sent_as_string_value(self):
        c = FakeClient()
        ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT], user_id=2045123456789)
        self.assertEqual(c.sent_actions(), [
            {"id": "S1/alert/assignUser",
             "payload": {"assignUser": {"value": "2045123456789"}}}])
        self.assertEqual(c.gets, [], "a numeric user_id needs no lookup")

    def test_email_resolved_to_id_via_users_endpoint(self):
        c = FakeClient(users=[{"id": "987654321", "email": "Analyst@Example.com"}])
        ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT],
                         user_email="analyst@example.com")
        self.assertEqual(c.gets, [("/web/api/v2.1/users",
                                   {"email": "analyst@example.com", "limit": 10})])
        payload = c.sent_actions()[0]["payload"]
        self.assertEqual(payload, {"assignUser": {"value": "987654321"}})

    def test_user_email_field_is_never_sent(self):
        c = FakeClient(users=[{"id": "987654321", "email": "analyst@example.com"}])
        ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT],
                         user_email="analyst@example.com")
        self.assertNotIn("userEmail", str(c.posts[0][1]))

    def test_unassign_sends_null_value(self):
        c = FakeClient()
        ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT], unassign=True)
        self.assertEqual(c.sent_actions()[0]["payload"], {"assignUser": {"value": None}})
        self.assertEqual(c.gets, [])

    def test_filter_is_the_alert_ids(self):
        c = FakeClient()
        ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT], user_id="42")
        variables = c.posts[0][1]["variables"]
        self.assertEqual(variables["filter"], {"or": [{"and": [
            {"fieldId": "id", "stringIn": {"values": [ALERT]}}]}]})
        self.assertEqual(variables["scope"], SCOPE)

    def test_assign_is_not_auto_retried(self):
        c = FakeClient()
        ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT], user_id="42")
        self.assertFalse(c.posts[0][2], "mutations must never be auto-retried")

    def test_email_with_no_match_refused_before_any_write(self):
        c = FakeClient(users=[])
        with self.assertRaises(ValueError) as cm:
            ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT],
                             user_email="nobody@example.com")
        self.assertIn("found 0", str(cm.exception))
        self.assertEqual(c.posts, [])

    def test_email_with_two_matches_refused(self):
        c = FakeClient(users=[{"id": "1", "email": "a@example.com"},
                              {"id": "2", "email": "A@example.com"}])
        with self.assertRaises(ValueError):
            ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT],
                             user_email="a@example.com")
        self.assertEqual(c.posts, [])

    def test_partial_email_match_is_not_a_match(self):
        """The users endpoint can return near matches; only an exact one counts."""
        c = FakeClient(users=[{"id": "1", "email": "analyst@example.com.au"}])
        with self.assertRaises(ValueError):
            ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT],
                             user_email="analyst@example.com")
        self.assertEqual(c.posts, [])

    def test_non_numeric_user_id_refused(self):
        c = FakeClient()
        with self.assertRaises(ValueError):
            ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT],
                             user_id="analyst@example.com")
        self.assertEqual(c.posts, [])

    def test_exactly_one_target_required(self):
        c = FakeClient()
        for kwargs in ({}, {"user_id": "1", "user_email": "a@example.com"},
                       {"user_id": "1", "unassign": True}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    ua.assign_alerts(c, scope_input=SCOPE, alert_ids=[ALERT], **kwargs)
        self.assertEqual(c.posts, [])


class SetAnalystVerdict(unittest.TestCase):

    def test_enum_has_the_twenty_introspected_values(self):
        self.assertEqual(len(ua.ANALYST_VERDICTS), 20)
        self.assertEqual(len(set(ua.ANALYST_VERDICTS)), 20)
        self.assertIn("UNDEFINED", ua.ANALYST_VERDICTS)
        self.assertEqual(
            sum(v.startswith("TRUE_POSITIVE_") for v in ua.ANALYST_VERDICTS), 14)
        self.assertEqual(
            sum(v.startswith("FALSE_POSITIVE_") for v in ua.ANALYST_VERDICTS), 5)

    def test_enum_matches_the_reference_doc(self):
        ref = (SKILL_DIR / "references" / "UNIFIED_ALERTS.md").read_text()
        self.assertIn("**AnalystVerdict enum** (introspected, 20 values)", ref)
        for suffix in ("MALWARE", "PUA_ADWARE", "EXPLOITATION_TOOLS"):
            self.assertIn(f"TRUE_POSITIVE_{suffix}", ua.ANALYST_VERDICTS)
            self.assertIn(suffix, ref)

    def test_valid_verdict_payload(self):
        c = FakeClient()
        ua.set_analyst_verdict(c, scope_input=SCOPE, alert_ids=[ALERT],
                               verdict="FALSE_POSITIVE_BENIGN")
        self.assertEqual(c.sent_actions(), [
            {"id": "S1/alert/analystVerdictUpdate",
             "payload": {"analystVerdict": {"value": "FALSE_POSITIVE_BENIGN"}}}])

    def test_group_headers_and_suspicious_refused_before_any_request(self):
        c = FakeClient()
        for bad in ("TRUE_POSITIVE", "FALSE_POSITIVE", "SUSPICIOUS",
                    "true_positive_malware"):
            with self.subTest(verdict=bad):
                with self.assertRaises(ValueError):
                    ua.set_analyst_verdict(c, scope_input=SCOPE,
                                           alert_ids=[ALERT], verdict=bad)
        self.assertEqual(c.posts, [])

    def test_docstring_lists_no_invalid_values(self):
        doc = ua.set_analyst_verdict.__doc__ or ""
        self.assertIn("TRUE_POSITIVE_", doc)
        self.assertNotIn("TRUE_POSITIVE, SUSPICIOUS", doc)


class CliExposesTheFixedShape(unittest.TestCase):
    """call_unified_alerts.py must not reintroduce a required --user-email."""

    @classmethod
    def setUpClass(cls):
        import call_unified_alerts as cli  # noqa: E402
        cls.parser = cli.build_parser()

    def _parse(self, *argv):
        return self.parser.parse_args(list(argv))

    def test_unassign(self):
        args = self._parse("assign", "--scope", "1", "--alert-id", ALERT, "--unassign")
        self.assertTrue(args.unassign)
        self.assertIsNone(args.user_id)
        self.assertIsNone(args.user_email)

    def test_user_id(self):
        args = self._parse("assign", "--scope", "1", "--alert-id", ALERT, "--user-id", "42")
        self.assertEqual(args.user_id, "42")
        self.assertFalse(args.unassign)

    def test_one_target_required(self):
        import contextlib
        import io
        for argv in (("assign", "--scope", "1", "--alert-id", ALERT),
                     ("assign", "--scope", "1", "--alert-id", ALERT,
                      "--user-id", "42", "--unassign")):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self._parse(*argv)

    def test_set_verdict_rejects_a_group_header(self):
        import contextlib
        import io
        # The verdict goes before the nargs="+" flags, which would swallow it.
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit):
                self._parse("set-verdict", "TRUE_POSITIVE", "--scope", "1",
                            "--alert-id", ALERT)
        self.assertIn("invalid choice", err.getvalue())
        args = self._parse("set-verdict", "TRUE_POSITIVE_MALWARE", "--scope", "1",
                           "--alert-id", ALERT)
        self.assertEqual(args.verdict, "TRUE_POSITIVE_MALWARE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
