"""Unit tests for SDLClient's GraphQL config-file layer.

These stub `requests.request`, so they need no tenant and no credentials.
`smoke_test.py` covers the live path; this file covers the branches that only
appear when the server misbehaves, which is where every defect in this module
has actually been found.

Run: python3 -m pytest sdl-api/tests/test_client.py -q
  or: python3 sdl-api/tests/test_client.py
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

os.environ.setdefault("S1_CONSOLE_URL", "https://tenant.sentinelone.net")
os.environ.setdefault("S1_CONSOLE_API_TOKEN", "test-token")

from sdl_client import SDLClient, SDLAPIError  # noqa: E402

# Fail loudly rather than silently reaching a real tenant if a stub ever misses.
os.environ["S1_CONSOLE_URL"] = "https://unit-test.invalid"


class FakeResponse:
    """Mimics the requests.Response surface the client actually touches:
    status_code, headers, text, content and json()."""

    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.headers = headers or {}
        self.text = self._body if isinstance(self._body, str) else json.dumps(self._body)
        self.content = self.text.encode()

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


def client_with(responses):
    """Return (client, calls). `responses` is consumed in order."""
    calls = []
    c = SDLClient()

    def fake_request(method, url, **kw):
        calls.append({"method": method, "url": url, "json": kw.get("json"),
                      "headers": kw.get("headers", {})})
        if not responses:
            raise AssertionError("ran out of queued responses")
        return responses.pop(0)

    # The client issues every call through self.session.request, so that is the
    # only seam. Patching anything else silently lets the tests hit a live tenant.
    c.session = mock.Mock()
    c.session.request = fake_request
    return c, calls


def gql(data):
    return FakeResponse(200, {"data": data})


def gql_err(message):
    return FakeResponse(200, {"errors": [{"message": message}]})


class AbsenceHandling(unittest.TestCase):
    def test_explicit_not_found_returns_none(self):
        c, _ = client_with([gql_err("Config file with name /lookups/x.csv not found.")])
        self.assertIsNone(c.config_file(name="/lookups/x.csv"))

    def test_generic_error_disambiguated_by_listing(self):
        # A deleted udoId returns the generic message, which a version conflict
        # also returns. Absent from the listing means genuinely gone.
        c, _ = client_with([
            gql_err("Something went wrong. Please try again and if the issue persists contact Support."),
            gql({"configFiles": [{"udoId": "999", "name": "/dashboards/Other", "version": 1}]}),
        ])
        self.assertIsNone(c.config_file(udo_id="5"))

    def test_generic_error_rethrows_when_file_still_present(self):
        c, _ = client_with([
            gql_err("Something went wrong. Please try again."),
            gql({"configFiles": [{"udoId": "5", "name": "/dashboards/Here", "version": 1}]}),
        ])
        with self.assertRaises(SDLAPIError):
            c.config_file(udo_id="5")

    def test_transport_error_is_not_treated_as_absence(self):
        # A 404 page whose body contains "not found" must not be read as
        # "the file does not exist"; that would let a delete confirm itself.
        c, _ = client_with([FakeResponse(404, {"error": "not found"})])
        with self.assertRaises(SDLAPIError):
            c.config_file(name="/lookups/x.csv")

    def test_non_json_200_raises(self):
        c, _ = client_with([FakeResponse(200, "<html>SSO interstitial</html>")])
        with self.assertRaises(SDLAPIError):
            c.config_files()


class RetryPolicy(unittest.TestCase):
    def test_mutations_are_not_retried_on_5xx(self):
        # A retried addConfigFile(name:) against /dashboards/ creates a duplicate.
        c, calls = client_with([
            gql({"configFiles": [{"udoId": "1", "name": "/dashboards/Other", "version": 1}]}),
            FakeResponse(502, "bad gateway"),
        ])
        with self.assertRaises(SDLAPIError):
            c.put_config_file(name="/dashboards/New", content="{}")
        mutations = [k for k in calls if "mutation" in (k["json"] or {}).get("query", "")]
        self.assertEqual(len(mutations), 1, "the mutation must be sent exactly once")

    def test_read_only_queries_are_retried(self):
        c, calls = client_with([
            FakeResponse(503, "unavailable"),
            gql({"configFiles": [{"udoId": None, "name": "/lookups/a.csv", "version": 1}]}),
        ])
        with mock.patch("time.sleep"):
            files = c.config_files()
        self.assertEqual(len(files), 1)
        self.assertEqual(len(calls), 2, "the query should have been retried once")

    def test_retry_after_is_capped(self):
        c, _ = client_with([
            FakeResponse(429, "slow down", headers={"Retry-After": "3600"}),
            gql({"configFiles": []}),
        ])
        with mock.patch("time.sleep") as slept:
            c.config_files()
        self.assertLessEqual(slept.call_args[0][0], 30,
                             "an unbounded Retry-After would park the process")


class DuplicateGuard(unittest.TestCase):
    def test_blocks_name_write_to_existing_dashboard(self):
        c, _ = client_with([
            gql({"configFiles": [{"udoId": "777", "name": "/dashboards/AI Usage", "version": 1}]}),
        ])
        with self.assertRaises(ValueError) as ctx:
            c.put_config_file(name="/dashboards/AI Usage", content="{}")
        self.assertIn("777", str(ctx.exception))

    def test_case_variant_path_does_not_bypass_the_guard(self):
        c, _ = client_with([
            gql({"configFiles": [{"udoId": "777", "name": "/dashboards/AI Usage", "version": 1}]}),
        ])
        with self.assertRaises(ValueError):
            c.put_config_file(name="/Dashboards/AI Usage", content="{}")

    def test_fails_closed_on_empty_listing(self):
        c, _ = client_with([gql({"configFiles": []})])
        with self.assertRaises(ValueError) as ctx:
            c.put_config_file(name="/dashboards/Anything", content="{}")
        self.assertIn("empty", str(ctx.exception))

    def test_create_of_a_new_dashboard_is_allowed(self):
        c, _ = client_with([
            gql({"configFiles": [{"udoId": "1", "name": "/dashboards/Other", "version": 1}]}),
            gql({"addConfigFile": {"udoId": "888", "name": "/dashboards/New", "version": 1}}),
        ])
        self.assertEqual(c.put_config_file(name="/dashboards/New", content="{}")["udoId"], "888")

    def test_non_dashboard_namespaces_are_not_guarded(self):
        c, calls = client_with([
            gql({"addConfigFile": {"udoId": None, "name": "/lookups/a.csv", "version": 2}}),
        ])
        c.put_config_file(name="/lookups/a.csv", content="k,v\n")
        self.assertEqual(len(calls), 1, "no listing should be fetched for a non-dashboard write")


class ExpectedVersion(unittest.TestCase):
    def test_sent_on_name_addressed_writes(self):
        c, calls = client_with([
            gql({"addConfigFile": {"udoId": None, "name": "/logParsers/P", "version": 2}}),
        ])
        c.put_config_file(name="/logParsers/P", content="x", expected_version=1168977232)
        sent = calls[0]["json"]
        self.assertIn("$expectedVersion: Long", sent["query"])
        self.assertEqual(sent["variables"]["expectedVersion"], 1168977232)

    def test_sent_on_udoid_addressed_writes(self):
        c, calls = client_with([
            gql({"addConfigFile": {"udoId": "5", "name": "/dashboards/D", "version": 2}}),
        ])
        c.put_config_file(udo_id="5", content="x", expected_version=99)
        self.assertEqual(calls[0]["json"]["variables"]["expectedVersion"], 99)


class DeleteVerification(unittest.TestCase):
    def test_throws_when_the_file_survives(self):
        c, _ = client_with([
            gql({"deleteConfigFile": None}),
            gql({"configFile": {"udoId": "5", "name": "/dashboards/D", "version": 9}}),
        ])
        with self.assertRaises(SDLAPIError) as ctx:
            c.delete_config_file(udo_id="5")
        self.assertIn("still exists", str(ctx.exception))

    def test_success_once_absent(self):
        c, _ = client_with([
            gql({"deleteConfigFile": None}),
            gql_err("Config file with name /lookups/x.csv not found."),
        ])
        res = c.delete_config_file(name="/lookups/x.csv")
        self.assertEqual(res["status"], "success")

    def test_transport_error_does_not_produce_a_false_success(self):
        c, _ = client_with([
            gql({"deleteConfigFile": None}),
            FakeResponse(404, "nginx: not found"),
        ])
        with self.assertRaises(SDLAPIError):
            c.delete_config_file(name="/lookups/x.csv")


class Injection(unittest.TestCase):
    def test_caller_values_travel_in_variables_not_the_document(self):
        c, calls = client_with([gql({"configFile": None})])
        hostile = '/lookups/a"}) { evil }'
        c.config_file(name=hostile)
        self.assertNotIn("evil", calls[0]["json"]["query"])
        self.assertEqual(calls[0]["json"]["variables"]["id"], hostile)


if __name__ == "__main__":
    unittest.main(verbosity=2)
