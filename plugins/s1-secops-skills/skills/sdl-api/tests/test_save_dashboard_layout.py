"""Hermetic: save_dashboard_layout is layout-only, matched by index (live-verified
2026-10-03), so the client refuses a panel-count change before sending the mutation.
No network: every call goes through a stubbed session.
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



class SaveDashboardLayout(unittest.TestCase):
    def test_requires_the_graphs_wrapper_key(self):
        c, calls = client_with([])
        with self.assertRaises(ValueError):
            c.save_dashboard_layout(graphs="[]", tab_name="t", dashboard_id="1")
        self.assertEqual(calls, [])

    def test_passes_the_wrapped_graphs_and_tab_name(self):
        graphs = json.dumps({"graphs": [{"title": "p"}]})
        current = gql({"getDashboardV2": {"id": "1", "tabs": [
            {"tabName": "2. Metacortex operations", "graphs": json.dumps([{"title": "p"}])}]}})
        c, calls = client_with([current, gql({"saveDashboardLayout": {"graphs": "[]", "options": "{}"}})])
        c.save_dashboard_layout(graphs=graphs, tab_name="2. Metacortex operations", dashboard_id="1")
        self.assertEqual(calls[1]["json"]["variables"]["graphs"], graphs)
        self.assertEqual(calls[1]["json"]["variables"]["tabName"], "2. Metacortex operations")

    def test_refuses_a_panel_count_change(self):
        current = gql({"getDashboardV2": {"id": "1", "tabs": [
            {"tabName": "t", "graphs": json.dumps([{"title": "a"}, {"title": "b"}])}]}})
        for n in (1, 3):
            c, calls = client_with([current])
            with self.assertRaises(ValueError):
                c.save_dashboard_layout(graphs=json.dumps({"graphs": [{"title": "x"}] * n}),
                                        tab_name="t", dashboard_id="1")
            self.assertEqual(len(calls), 1, "read only, no mutation")



if __name__ == "__main__":
    unittest.main()
