#!/usr/bin/env python3
"""Hermetic tests for `unified_alerts.action_outcome`.

Why this file exists: `alertTriggerActions` answers a refused write with the
same `ActionsTriggered` __typename it uses for a successful one, putting the
alert id under `actions[].failure[]`. Three separate callers in this repo read
that as success, and one of them reported "CLEANUP ok" on an alert whose status
never moved off NEW. `action_outcome` is the single place that decision now
lives, so it is the place that needs tests that can fail.

No network, no credentials: every payload below is a verbatim shape returned by
the live API (the permission refusal is the exact response measured on this
tenant for statusUpdate).
"""
from __future__ import annotations

import pathlib
import sys
import unittest

SKILL_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_DIR / "scripts"))

import unified_alerts as ua  # noqa: E402

ALERT = "01a07b29-6ff2-703a-b072-3e71ae617b6e"


def _triggered(actions):
    return {"__typename": "ActionsTriggered", "actions": actions}


class TestActionOutcome(unittest.TestCase):

    def test_success_is_applied(self):
        oc = ua.action_outcome(_triggered([
            {"actionId": "S1/alert/addNote",
             "success": [{"id": ALERT}], "skip": [], "failure": []},
        ]))
        self.assertTrue(oc["applied"])
        self.assertEqual(oc["errors"], [])
        self.assertEqual(oc["actions"][0]["ok"], [ALERT])

    def test_permission_refusal_is_not_applied(self):
        """The measured refusal: ActionsTriggered, id under failure."""
        oc = ua.action_outcome(_triggered([
            {"actionId": "S1/alert/statusUpdate", "success": [], "skip": [],
             "failure": [{"id": ALERT,
                          "errorMessage": "Missing UAM manage permissions"}]},
        ]))
        self.assertFalse(oc["applied"], "a refused write must not read as applied")
        self.assertEqual(len(oc["errors"]), 1)
        self.assertIn("Missing UAM manage permissions", oc["errors"][0])
        self.assertIn(ALERT, oc["errors"][0])

    def test_partial_batch_is_not_applied(self):
        """One id applied, one refused: not a success."""
        oc = ua.action_outcome(_triggered([
            {"actionId": "S1/alert/statusUpdate",
             "success": [{"id": "a"}], "skip": [],
             "failure": [{"id": "b", "errorMessage": "nope"}]},
        ]))
        self.assertFalse(oc["applied"])

    def test_all_actions_must_apply(self):
        """A two-action call where only the first landed is not applied."""
        oc = ua.action_outcome(_triggered([
            {"actionId": "S1/alert/addNote",
             "success": [{"id": ALERT}], "skip": [], "failure": []},
            {"actionId": "S1/alert/statusUpdate", "success": [], "skip": [],
             "failure": [{"id": ALERT,
                          "errorMessage": "Missing UAM manage permissions"}]},
        ]))
        self.assertFalse(oc["applied"])
        self.assertEqual(len(oc["actions"]), 2)

    def test_skip_only_is_not_applied(self):
        """Skipped means the backend matched nothing to change."""
        oc = ua.action_outcome(_triggered([
            {"actionId": "S1/alert/statusUpdate",
             "success": [], "skip": [{"id": ALERT}], "failure": []},
        ]))
        self.assertFalse(oc["applied"])

    def test_empty_actions_is_not_applied(self):
        """An empty actions list must not vacuously pass the all() check."""
        oc = ua.action_outcome(_triggered([]))
        self.assertFalse(oc["applied"])

    def test_trigger_actions_error(self):
        oc = ua.action_outcome({
            "__typename": "TriggerActionsError",
            "errors": [{"errorMessage": "bad filter"}],
        })
        self.assertFalse(oc["applied"])
        self.assertEqual(oc["errors"], ["bad filter"])

    def test_scheduled_is_not_yet_applied(self):
        """A bulk job has not written anything yet; the caller must poll."""
        oc = ua.action_outcome({
            "__typename": "TriggerActionsScheduled",
            "bulkActionTriggerId": "bulk-123",
        })
        self.assertFalse(oc["applied"])
        self.assertIn("bulk-123", oc["errors"][0])

    def test_missing_error_message_still_reports(self):
        """errorMessage absent (older payload) must not crash the reducer."""
        oc = ua.action_outcome(_triggered([
            {"actionId": "S1/alert/statusUpdate", "success": [], "skip": [],
             "failure": [{"id": ALERT}]},
        ]))
        self.assertFalse(oc["applied"])
        self.assertIn(ALERT, oc["errors"][0])
        self.assertIn("unknown error", oc["errors"][0])

    def test_error_type_used_when_message_absent(self):
        """Mirrors the MCP: errorType is the fallback when there is no message."""
        oc = ua.action_outcome(_triggered([
            {"actionId": "S1/alert/statusUpdate", "success": [], "skip": [],
             "failure": [{"id": ALERT, "errorType": "PERMISSION_DENIED"}]},
        ]))
        self.assertFalse(oc["applied"])
        self.assertIn("PERMISSION_DENIED", oc["errors"][0])


class TestFailureDiagnosis(unittest.TestCase):
    """The guard against the error this suite was written after.

    `Missing UAM manage permissions` was read as a token-scope limit and
    written into the skill docs as one. It is also what a not-offered action
    returns. `explain_action_failure` is the correction, and `action_outcome`
    must surface its verdict so the misleading string never travels alone.
    """

    def _diag(self, available, isDisabled=False, reason=None):
        """Fake an available_actions payload without a client."""
        data = []
        for aid in available:
            data.append({"id": aid, "isDisabled": isDisabled,
                         "disabledReason": reason})

        class _FakeClient:
            pass

        orig = ua.available_actions
        ua.available_actions = lambda *a, **k: {"data": data, "errors": []}
        try:
            return ua.explain_action_failure(
                _FakeClient(), scope_input={}, filter_input={},
                action_ids=["S1/alert/statusUpdate"])
        finally:
            ua.available_actions = orig

    def test_not_offered_is_named(self):
        """The measured ingested-alert case: only addNote and eventSearch."""
        d = self._diag(["S1/alert/addNote", "S1/alert/eventSearch"])
        self.assertEqual(d["S1/alert/statusUpdate"]["state"], "not_offered")
        self.assertEqual(d["available"],
                         ["S1/alert/addNote", "S1/alert/eventSearch"])

    def test_disabled_carries_the_api_reason(self):
        """The measured scope case: incident actions under ACCOUNT scope."""
        d = self._diag(["S1/alert/statusUpdate"], isDisabled=True,
                       reason="INCIDENT_ACTIONS_ONLY_AVAILABLE_FROM_SITE_VIEW")
        self.assertEqual(d["S1/alert/statusUpdate"]["state"], "disabled")
        self.assertIn("SITE_VIEW", d["S1/alert/statusUpdate"]["reason"])

    def test_offered_means_escalate(self):
        """Available here, so the mutation error is the real cause."""
        d = self._diag(["S1/alert/statusUpdate", "S1/alert/addNote"])
        self.assertEqual(d["S1/alert/statusUpdate"]["state"], "offered")

    def test_outcome_appends_the_diagnosis(self):
        """A caller logging oc['errors'] must see the real cause."""
        resp = _triggered([
            {"actionId": "S1/alert/statusUpdate", "success": [], "skip": [],
             "failure": [{"id": ALERT,
                          "errorMessage": "Missing UAM manage permissions"}]},
        ])
        resp["diagnosis"] = {
            "available": ["S1/alert/addNote"],
            "S1/alert/statusUpdate": {"state": "not_offered",
                                      "reason": "this caller may not trigger it here"},
        }
        oc = ua.action_outcome(resp)
        self.assertFalse(oc["applied"])
        self.assertIn("not_offered", oc["errors"][0])
        self.assertIn("alertAvailableActions", oc["errors"][0])

    def test_outcome_without_diagnosis_still_works(self):
        """diagnose_failures=False, or the diagnosis query itself failing."""
        oc = ua.action_outcome(_triggered([
            {"actionId": "S1/alert/statusUpdate", "success": [], "skip": [],
             "failure": [{"id": ALERT, "errorMessage": "nope"}]},
        ]))
        self.assertFalse(oc["applied"])
        self.assertNotIn("alertAvailableActions", oc["errors"][0])


class TestTriggerActionsQuery(unittest.TestCase):
    """The reducer is only as good as what the query asks for."""

    def test_failure_selection_requests_error_message(self):
        src = (SKILL_DIR / "scripts" / "unified_alerts.py").read_text()
        self.assertIn("failure { id errorMessage errorType __typename }", src,
                      "trigger_actions must select errorMessage on failure, "
                      "or the refusal reason is discarded before any caller "
                      "can report it")

    def test_trigger_actions_diagnoses_by_default(self):
        """The guard must be on unless a caller opts out."""
        src = (SKILL_DIR / "scripts" / "unified_alerts.py").read_text()
        self.assertIn("diagnose_failures: bool = True", src)

    def test_docs_state_availability_depends_on_caller_and_type(self):
        """Availability is filtered by the caller's permissions AND the alert
        type. Neither factor alone is the rule, and `not_offered` never means
        impossible: a console user session performs writes a service-user token
        is refused."""
        ref = (SKILL_DIR / "references" / "UNIFIED_ALERTS.md").read_text()
        self.assertIn("filtered by the caller's permissions AND the alert type",
                      ref)
        self.assertIn("console user session", ref)
        for wrong in ("capability limit of the alert",
                      "no token change helps",
                      "Write permission is per-action, not per-alert"):
            self.assertNotIn(wrong, ref)


class FailureDiagnosisIsScopedToTheFailedAlerts(unittest.TestCase):
    """`alertAvailableActions` is filtered by alert type as well as by the
    caller's permissions. Diagnosing a failure against the ORIGINAL filter, when
    that filter matches a mix of alert types, explains one alert's refusal with
    another alert's capabilities. The mutation already returns the failing ids.
    """

    OTHER = "02b18c3a-7ff3-814b-c183-4f82bf728c7f"

    def test_collects_failed_ids_in_order_without_duplicates(self):
        resp = _triggered([
            {"actionId": "S1/alert/statusUpdate",
             "success": [{"id": self.OTHER}],
             "failure": [{"id": ALERT, "errorMessage": "Missing UAM manage permissions"}]},
            {"actionId": "S1/alert/addNote",
             "failure": [{"id": ALERT, "errorMessage": "Missing UAM manage permissions"}]},
        ])
        self.assertEqual([ALERT], ua._failed_alert_ids(resp))

    def test_succeeding_alert_is_not_diagnosed(self):
        resp = _triggered([
            {"actionId": "S1/alert/statusUpdate",
             "success": [{"id": self.OTHER}],
             "failure": [{"id": ALERT}]},
        ])
        self.assertNotIn(self.OTHER, ua._failed_alert_ids(resp))

    def test_no_ids_present_yields_empty_so_the_caller_can_fall_back(self):
        self.assertEqual([], ua._failed_alert_ids(
            _triggered([{"actionId": "x", "failure": [{"errorMessage": "e"}]}])))
        self.assertEqual([], ua._failed_alert_ids(
            {"__typename": "TriggerActionsError", "errors": [{"errorMessage": "e"}]}))

    def test_trigger_actions_narrows_the_diagnosis_filter(self):
        src = (SKILL_DIR / "scripts" / "unified_alerts.py").read_text()
        self.assertIn("_failed_alert_ids(resp)", src,
                      "the diagnosis must be scoped to the alerts that actually "
                      "failed, not to the original filter")
        self.assertIn("filter_input=diag_filter", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
