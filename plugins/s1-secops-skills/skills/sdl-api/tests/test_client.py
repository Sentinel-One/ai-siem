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


# ═══════════════════════════════════════════════════════════════════════════
# S1-Scope plumbing and the dashboardsV2 lifecycle (added 1.3.4)
#
# Live evidence these encode (<console> 2026-08-17): the console sends
# `s1-scope` on all 23 SDL GraphQL operations, and `getConfigurationFiles`
# returned 113 files at account scope versus 4 at a site scope. A dashboard created at
# site scope is invisible to an account-scoped listing, so a dropped header is
# not a harmless default: it changes which objects appear to exist.
# ═══════════════════════════════════════════════════════════════════════════

ACCOUNT = "2046190533732727925"
SITE = "2547662415802335157"
SITE_SCOPE = f"{ACCOUNT}:{SITE}"


class ScopeHeader(unittest.TestCase):
    def test_scope_is_sent_as_the_s1_scope_header(self):
        c, calls = client_with([gql({"configFiles": []})])
        c.config_files(scope=SITE_SCOPE)
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), SITE_SCOPE)

    def test_omitted_scope_inherits_the_client_default(self):
        c, calls = client_with([gql({"configFiles": []})])
        c.s1_scope = ACCOUNT
        c.config_files()
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), ACCOUNT)

    def test_explicit_none_suppresses_the_client_default(self):
        # Distinct from omitting: this is how an unscoped, token-default listing
        # stays requestable once a default is configured.
        c, calls = client_with([gql({"configFiles": []})])
        c.s1_scope = ACCOUNT
        c.config_files(scope=None)
        self.assertIsNone(calls[0]["headers"].get("S1-Scope"))

    def test_account_only_scope_is_valid(self):
        c, calls = client_with([gql({"configFiles": []})])
        c.config_files(scope=ACCOUNT)
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), ACCOUNT)

    def test_malformed_scope_is_rejected_before_any_request(self):
        c, calls = client_with([gql({"configFiles": []})])
        with self.assertRaises(ValueError):
            c.config_files(scope="Metacortex")
        self.assertEqual(calls, [], "nothing may go out with a bad scope")

    def test_non_string_scope_is_rejected(self):
        c, _ = client_with([])
        with self.assertRaises(ValueError):
            c.config_files(scope=12345)

    def test_writes_carry_the_scope_too(self):
        c, calls = client_with([gql({"addConfigFile": {"udoId": "1", "name": "/lookups/x", "version": 2}})])
        c.put_config_file(name="/lookups/x", content="a,b", scope=SITE_SCOPE)
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), SITE_SCOPE)


class ScopeConsistency(unittest.TestCase):
    """The scope-sensitive call sites must all use the SAME scope, or a live
    site-scoped file reads as deleted."""

    def test_duplicate_guard_lists_at_the_scope_of_the_write(self):
        c, calls = client_with([
            gql({"configFiles": [{"udoId": "9", "name": "/dashboards/Other", "version": 1}]}),
            gql({"addConfigFile": {"udoId": "10", "name": "/dashboards/New", "version": 1}}),
        ])
        c.put_config_file(name="/dashboards/New", content="{}", scope=SITE_SCOPE)
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), SITE_SCOPE)
        self.assertEqual(calls[1]["headers"].get("S1-Scope"), SITE_SCOPE)

    def test_absence_disambiguation_relists_at_the_same_scope(self):
        c, calls = client_with([
            gql_err("Something went wrong. Please try again"),
            gql({"configFiles": []}),
        ])
        self.assertIsNone(c.config_file(udo_id="6994516145065984", scope=SITE_SCOPE))
        self.assertEqual(calls[1]["headers"].get("S1-Scope"), SITE_SCOPE)

    def test_delete_verification_rereads_at_the_same_scope(self):
        c, calls = client_with([
            gql({"deleteConfigFile": None}),
            gql_err("Config file with name /lookups/x not found."),
        ])
        res = c.delete_config_file(name="/lookups/x", scope=SITE_SCOPE)
        self.assertEqual(res["status"], "success")
        self.assertEqual(calls[1]["headers"].get("S1-Scope"), SITE_SCOPE)


class CreateDashboard(unittest.TestCase):
    def test_posts_config_verbatim_and_returns_the_id(self):
        cfg = json.dumps({"configType": "TABBED", "tabs": []})
        c, calls = client_with([gql({"createDashboardV2": {"id": "6999396433133568", "name": "meta1 - Copy"}})])
        res = c.create_dashboard(name="meta1 - Copy", config=cfg, scope=SITE_SCOPE)
        self.assertEqual(res["id"], "6999396433133568")
        self.assertEqual(calls[0]["json"]["variables"]["config"], cfg)
        self.assertEqual(calls[0]["json"]["variables"]["public"], True)
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), SITE_SCOPE)

    def test_rejects_the_console_stub_append_shape(self):
        c, calls = client_with([])
        with self.assertRaises(ValueError) as ctx:
            c.create_dashboard(name="x", config='{\n  graphs: []\n}{"configType":"TABBED"}')
        self.assertIn("not valid JSON", str(ctx.exception))
        self.assertEqual(calls, [])

    def test_raises_when_no_id_comes_back(self):
        c, _ = client_with([gql({"createDashboardV2": None})])
        with self.assertRaises(SDLAPIError):
            c.create_dashboard(name="x", config="{}")

    def test_duplicate_names_allowed_by_default(self):
        c, _ = client_with([gql({"createDashboardV2": {"id": "1", "name": "dupe"}})])
        self.assertEqual(c.create_dashboard(name="dupe", config="{}")["id"], "1")

    def test_fail_if_name_exists_refuses(self):
        c, _ = client_with([gql({"dashboardsV2": [{"id": "77", "name": "dupe"}]})])
        with self.assertRaises(ValueError):
            c.create_dashboard(name="dupe", config="{}", fail_if_name_exists=True)

    def test_empty_config_is_rejected(self):
        c, _ = client_with([])
        with self.assertRaises(ValueError):
            c.create_dashboard(name="x", config="   ")


class ShareDashboard(unittest.TestCase):
    def test_sends_the_scope_target_array(self):
        c, calls = client_with([gql({"shareResource": {"id": 6999150597128192, "name": "meta2"}})])
        res = c.share_dashboard(dashboard_id="6999150597128192",
                                scopes=[{"scopeType": "site", "scopeId": SITE, "operation": "ADD"}])
        self.assertEqual(res["status"], "success")
        self.assertEqual(calls[0]["json"]["variables"]["scopes"],
                         [{"scopeType": "site", "scopeId": SITE, "operation": "ADD"}])
        self.assertEqual(calls[0]["json"]["variables"]["users"], [])

    def test_defaults_operation_to_add_and_lowercases_type(self):
        c, calls = client_with([gql({"shareResource": {"id": 1, "name": "x"}})])
        c.share_dashboard(dashboard_id="1", scopes=[{"scopeType": "Site", "scopeId": SITE}])
        self.assertEqual(calls[0]["json"]["variables"]["scopes"],
                         [{"scopeType": "site", "scopeId": SITE, "operation": "ADD"}])

    def test_rejects_malformed_targets_before_sending(self):
        for bad in (
            [{"scopeType": "group", "scopeId": SITE}],
            [{"scopeType": "site", "scopeId": "Metacortex"}],
            [{"scopeType": "site", "scopeId": SITE, "operation": "GRANT"}],
        ):
            c, calls = client_with([])
            with self.assertRaises(ValueError):
                c.share_dashboard(dashboard_id="1", scopes=bad)
            self.assertEqual(calls, [], f"validation must precede the request for {bad}")

    def test_no_targets_is_rejected_as_a_noop(self):
        c, _ = client_with([])
        with self.assertRaises(ValueError):
            c.share_dashboard(dashboard_id="1")

    def test_global_scope_needs_no_scope_id(self):
        c, calls = client_with([gql({"shareResource": {"id": 1, "name": "x"}})])
        c.share_dashboard(dashboard_id="1", scopes=[{"scopeType": "global"}])
        self.assertEqual(calls[0]["json"]["variables"]["scopes"][0]["scopeType"], "global")

    def test_raises_when_nothing_was_shared(self):
        c, _ = client_with([gql({"shareResource": None})])
        with self.assertRaises(SDLAPIError):
            c.share_dashboard(dashboard_id="1", scopes=[{"scopeType": "site", "scopeId": SITE}])


class GetDashboardAbsence(unittest.TestCase):
    """Guards the 1.3.2 defect class: absence-as-error made every successful
    delete report failure."""

    def test_graphql_error_is_absence_when_the_listing_agrees(self):
        c, _ = client_with([
            gql_err("Something went wrong. Please try again"),
            gql({"dashboardsV2": []}),
        ])
        self.assertIsNone(c.get_dashboard(dashboard_id="123"))

    def test_rethrows_when_the_listing_shows_it_present(self):
        c, _ = client_with([
            gql_err("Something went wrong. Please try again"),
            gql({"dashboardsV2": [{"id": "123", "name": "still here"}]}),
        ])
        with self.assertRaises(SDLAPIError):
            c.get_dashboard(dashboard_id="123")

    def test_transport_failure_is_never_absence(self):
        c, _ = client_with([FakeResponse(404, "<html>not found</html>")])
        with self.assertRaises(SDLAPIError):
            c.get_dashboard(dashboard_id="123")

    def test_null_data_is_absence(self):
        c, _ = client_with([gql({"getDashboardV2": None})])
        self.assertIsNone(c.get_dashboard(dashboard_id="123"))


class DeleteDashboard(unittest.TestCase):
    def test_confirms_removal_by_rereading_not_from_the_boolean(self):
        c, calls = client_with([
            gql({"deleteDashboard": True}),
            gql({"getDashboardV2": None}),
        ])
        res = c.delete_dashboard(dashboard_id="6999150597128192", scope=SITE_SCOPE)
        self.assertEqual(res["status"], "success")
        self.assertEqual(len(calls), 2, "the mutation response alone is not proof")
        self.assertEqual(calls[1]["headers"].get("S1-Scope"), SITE_SCOPE)

    def test_fails_loudly_when_the_dashboard_survives(self):
        c, _ = client_with([
            gql({"deleteDashboard": True}),
            gql({"getDashboardV2": {"id": "1", "name": "survivor"}}),
        ])
        with self.assertRaises(SDLAPIError):
            c.delete_dashboard(dashboard_id="1")


class SaveDashboardLayout(unittest.TestCase):
    def test_requires_the_graphs_wrapper_key(self):
        c, calls = client_with([])
        with self.assertRaises(ValueError):
            c.save_dashboard_layout(graphs="[]", tab_name="t", dashboard_id="1")
        self.assertEqual(calls, [])

    def test_passes_the_wrapped_graphs_and_tab_name(self):
        graphs = json.dumps({"graphs": [{"title": "p"}]})
        c, calls = client_with([gql({"saveDashboardLayout": {"graphs": "[]", "options": "{}"}})])
        c.save_dashboard_layout(graphs=graphs, tab_name="2. Metacortex operations", dashboard_id="1")
        self.assertEqual(calls[0]["json"]["variables"]["graphs"], graphs)
        self.assertEqual(calls[0]["json"]["variables"]["tabName"], "2. Metacortex operations")


class ListDashboards(unittest.TestCase):
    def test_returns_dashboards_with_access_metadata(self):
        c, _ = client_with([gql({"dashboardsV2": [
            {"id": "1", "name": "a", "access": {"public": True, "owner": "p@x"}}]})])
        res = c.list_dashboards(scope=SITE_SCOPE)
        self.assertEqual(res[0]["access"]["owner"], "p@x")

    def test_empty_listing_is_an_empty_list_not_none(self):
        c, _ = client_with([gql({"dashboardsV2": None})])
        self.assertEqual(c.list_dashboards(), [])


class QueryMethodsScope(unittest.TestCase):
    """Log reads are scope-filtered by the same header as config reads.

    1.3.4 shipped scope on the config-file and dashboard methods but not on the
    query methods, so a hunt run without the intended scope silently answered for
    the token default. Fixed in 1.3.5; these lock it.
    """

    def test_power_query_sends_the_scope_header(self):
        c, calls = client_with([FakeResponse(200, {"values": [], "columns": []})])
        c.power_query("event.time=* | group c=count()", scope=SITE_SCOPE)
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), SITE_SCOPE)

    def test_query_sends_the_scope_header(self):
        c, calls = client_with([FakeResponse(200, {"matches": []})])
        c.query(filter="dataSource.name=='X'", scope=SITE_SCOPE)
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), SITE_SCOPE)

    def test_facet_query_sends_the_scope_header(self):
        c, calls = client_with([FakeResponse(200, {"values": []})])
        c.facet_query(filter="event.time=*", field="event.type", scope=SITE_SCOPE)
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), SITE_SCOPE)

    def test_numeric_query_sends_the_scope_header(self):
        c, calls = client_with([FakeResponse(200, {"values": []})])
        c.numeric_query(filter="event.time=*", function="count", scope=SITE_SCOPE)
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), SITE_SCOPE)

    def test_timeseries_query_sends_the_scope_header(self):
        c, calls = client_with([FakeResponse(200, {"results": []})])
        c.timeseries_query([{"filter": "event.time=*", "function": "count"}], scope=SITE_SCOPE)
        self.assertEqual(calls[0]["headers"].get("S1-Scope"), SITE_SCOPE)

    def test_query_omits_the_header_when_unscoped(self):
        c, calls = client_with([FakeResponse(200, {"matches": []})])
        c.query(filter="x")
        self.assertIsNone(calls[0]["headers"].get("S1-Scope"))

    def test_query_rejects_a_malformed_scope_before_sending(self):
        c, calls = client_with([])
        with self.assertRaises(ValueError):
            c.power_query("event.time=*", scope="<site>")
        self.assertEqual(calls, [], "nothing may go out with a bad scope")

    def test_explicit_none_suppresses_the_default_on_queries_too(self):
        c, calls = client_with([FakeResponse(200, {"matches": []})])
        c.s1_scope = ACCOUNT
        c.query(filter="x", scope=None)
        self.assertIsNone(calls[0]["headers"].get("S1-Scope"))


class PublicDefault(unittest.TestCase):
    """public defaults True: a private service-user dashboard is invisible in the
    console to a human at any scope, which looks exactly like a failed deploy."""

    def test_defaults_to_true(self):
        c, calls = client_with([gql({"createDashboardV2": {"id": "1", "name": "d"}})])
        c.create_dashboard(name="d", config="{}")
        self.assertIs(calls[0]["json"]["variables"]["public"], True)

    def test_explicit_false_still_honoured(self):
        c, calls = client_with([gql({"createDashboardV2": {"id": "2", "name": "p"}})])
        c.create_dashboard(name="p", config="{}", public=False)
        self.assertIs(calls[0]["json"]["variables"]["public"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
