"""S1Client and the UAM ingest helper resolve credentials from the environment,
then the OS keychain, and never from a file.

Hermetic: no network and no real keychain (S1_KEYCHAIN=off, or subprocess.run
mocked). The "no file" tests plant valid-looking decoy credentials.json files in
every location the old loaders searched; if any were read, the client would
construct successfully instead of raising "not configured".
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import s1_keystore  # noqa: E402
import s1_client  # noqa: E402

try:
    import requests  # noqa: F401
    HAVE_REQUESTS = True
except ImportError:  # S1Client() builds a requests.Session
    HAVE_REQUESTS = False

_ALL_ENV = sorted({v for names in s1_keystore.ENV_ALIASES.values() for v in names}
                  | {"S1_PROFILE", "S1_KEYCHAIN", "S1_KEYCHAIN_BACKEND", "COWORK_WORKSPACE",
                     "CLAUDE_CONFIG_DIR", "S1_CREDS_FILE", "S1_VERIFY_TLS", "S1_CACHE_TTL"})

DECOY = {
    "S1_CONSOLE_URL": "https://decoy.example",
    "S1_CONSOLE_API_TOKEN": "decoy-token",
    "S1_HEC_INGEST_URL": "https://decoy-ingest.example",
}


class _Env(unittest.TestCase):
    def setUp(self) -> None:
        env = {k: v for k, v in os.environ.items() if k not in _ALL_ENV}
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        s1_keystore.clear_cache()
        self.addCleanup(s1_keystore.clear_cache)


@unittest.skipUnless(HAVE_REQUESTS, "S1Client needs requests")
class S1ClientResolution(_Env):
    def test_env_only(self):
        os.environ.update({"S1_KEYCHAIN": "off", "S1_CONSOLE_URL": "https://t.example/",
                           "S1_CONSOLE_API_TOKEN": "tok"})
        c = s1_client.S1Client()
        self.assertEqual(c.base_url, "https://t.example")
        self.assertEqual(c.api_token, "tok")
        self.assertEqual(c.session.headers["Authorization"], "ApiToken tok")

    def test_env_aliases(self):
        os.environ.update({"S1_KEYCHAIN": "off", "S1_BASE_URL": "https://alias.example",
                           "SDL_CONSOLE_API_TOKEN": "legacy-tok"})
        c = s1_client.S1Client()
        self.assertEqual((c.base_url, c.api_token), ("https://alias.example", "legacy-tok"))

    def test_one_token_and_explicit_override(self):
        os.environ.update({"S1_KEYCHAIN": "off", "S1_CONSOLE_URL": "https://t.example",
                           "S1_CONSOLE_API_TOKEN": "configured"})
        self.assertEqual(s1_client.S1Client().api_token, "configured")
        self.assertEqual(s1_client.S1Client(api_token="explicit").api_token, "explicit")
        import inspect
        params = set(inspect.signature(s1_client.S1Client).parameters)
        self.assertEqual({p for p in params if "token" in p}, {"api_token"})  # one token, no selector

    def test_profile_selects_keychain_items(self):
        # A single-account token lives in its own profile; S1_PROFILE picks it.
        os.environ["S1_PROFILE"] = "acct1"
        held = {"acct1:S1_CONSOLE_URL": "https://kc.example",
                "acct1:S1_CONSOLE_API_TOKEN": "acct1-token"}

        def fake_run(argv, **kw):
            acct = argv[argv.index("-a") + 1]
            if acct in held:
                return subprocess.CompletedProcess(argv, 0, held[acct] + "\n", "")
            return subprocess.CompletedProcess(argv, 44, "", "not found")

        with mock.patch.object(s1_keystore, "_backend", return_value=("macos", True, "")), \
                mock.patch.object(s1_keystore.subprocess, "run", side_effect=fake_run):
            c = s1_client.S1Client()
        self.assertEqual(c.api_token, "acct1-token")

    def test_keychain_fallback(self):
        held = {"default:S1_CONSOLE_URL": "https://kc.example",
                "default:S1_CONSOLE_API_TOKEN": "kc-token"}

        def fake_run(argv, **kw):
            acct = argv[argv.index("-a") + 1]
            if acct in held:
                return subprocess.CompletedProcess(argv, 0, held[acct] + "\n", "")
            return subprocess.CompletedProcess(argv, 44, "", "not found")

        with mock.patch.object(s1_keystore, "_backend", return_value=("macos", True, "")), \
                mock.patch.object(s1_keystore.subprocess, "run", side_effect=fake_run):
            c = s1_client.S1Client()
        self.assertEqual((c.base_url, c.api_token), ("https://kc.example", "kc-token"))

    def test_env_overrides_keychain_per_value(self):
        os.environ["S1_CONSOLE_URL"] = "https://env.example"

        def fake_run(argv, **kw):
            acct = argv[argv.index("-a") + 1]
            self.assertNotEqual(acct, "default:S1_CONSOLE_URL", "env value must short-circuit")
            if acct == "default:S1_CONSOLE_API_TOKEN":
                return subprocess.CompletedProcess(argv, 0, "kc-token\n", "")
            return subprocess.CompletedProcess(argv, 44, "", "")

        with mock.patch.object(s1_keystore, "_backend", return_value=("macos", True, "")), \
                mock.patch.object(s1_keystore.subprocess, "run", side_effect=fake_run):
            c = s1_client.S1Client()
        self.assertEqual((c.base_url, c.api_token), ("https://env.example", "kc-token"))

    def test_decoy_files_are_never_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, work, cfgdir = root / "home", root / "work", root / "claudecfg"
            for d in (home / ".config" / "sentinelone", home / ".claude" / "sentinelone",
                      home / "mnt" / "proj", work / ".sentinelone", cfgdir / "sentinelone"):
                d.mkdir(parents=True)
                (d / "credentials.json").write_text(json.dumps(DECOY))
            (work / "credentials.json").write_text(json.dumps(DECOY))
            (home / "mnt" / "proj" / "credentials.json").write_text(json.dumps(DECOY))
            os.environ.update({"HOME": str(home), "COWORK_WORKSPACE": str(work),
                               "CLAUDE_CONFIG_DIR": str(cfgdir),
                               "S1_CREDS_FILE": str(work / "credentials.json"),
                               "S1_KEYCHAIN": "off"})
            cwd = os.getcwd()
            os.chdir(work)
            try:
                with self.assertRaises(RuntimeError) as cm:
                    s1_client.S1Client()
            finally:
                os.chdir(cwd)
        msg = str(cm.exception)
        self.assertIn("not configured", msg)
        self.assertIn("S1_CONSOLE_URL", msg)
        self.assertIn("s1-secops-mcp setup", msg)
        self.assertIn("S1_KEYCHAIN=off", msg)
        self.assertNotIn("decoy", msg)

    def test_missing_token_message(self):
        os.environ.update({"S1_KEYCHAIN": "off", "S1_CONSOLE_URL": "https://t.example"})
        with self.assertRaises(RuntimeError) as cm:
            s1_client.S1Client()
        self.assertIn("S1_CONSOLE_API_TOKEN", str(cm.exception))
        self.assertIn("environment variable", str(cm.exception))

    def test_no_file_layer_symbols_remain(self):
        for gone in ("HOME_CREDS_PATH", "DOTCLAUDE_CREDS_PATH", "PLUGIN_CREDS_PATH", "CONFIG_PATH",
                     "_walk_up_for_workspace_creds", "_WORKSPACE_CREDS_RELS", "_apply_s1_keys"):
            self.assertFalse(hasattr(s1_client, gone), gone)


class UamIngestUrl(_Env):
    def setUp(self) -> None:
        super().setUp()
        import uam_alert_interface
        self.uam = uam_alert_interface

    def test_env_then_alias(self):
        os.environ["S1_KEYCHAIN"] = "off"
        os.environ["S1_UAM_ALERT_INTERFACE_URL"] = "https://alias-ingest.example/"
        self.assertEqual(self.uam._configured_url(), "https://alias-ingest.example")
        os.environ["S1_HEC_INGEST_URL"] = "https://canon-ingest.example"
        self.assertEqual(self.uam._configured_url(), "https://canon-ingest.example")

    def test_keychain(self):
        def fake_run(argv, **kw):
            self.assertIn("default:S1_HEC_INGEST_URL", argv)
            return subprocess.CompletedProcess(argv, 0, "https://kc-ingest.example\n", "")

        with mock.patch.object(s1_keystore, "_backend", return_value=("macos", True, "")), \
                mock.patch.object(s1_keystore.subprocess, "run", side_effect=fake_run):
            c = self.uam.UAMAlertInterfaceClient(bearer_token="t")
        self.assertEqual(c.base_url, "https://kc-ingest.example")

    def test_default_host_when_unset(self):
        os.environ["S1_KEYCHAIN"] = "off"
        with mock.patch("sys.stderr"):
            c = self.uam.UAMAlertInterfaceClient(bearer_token="t")
        self.assertEqual(c.base_url, self.uam._DEFAULT_PROD_HOST)

    def test_explicit_argument_wins(self):
        os.environ["S1_HEC_INGEST_URL"] = "https://env.example"
        c = self.uam.UAMAlertInterfaceClient(bearer_token="t", base_url="https://arg.example/")
        self.assertEqual(c.base_url, "https://arg.example")

    def test_no_file_walk(self):
        self.assertFalse(hasattr(self.uam, "_load_config_url"))
        self.assertFalse(hasattr(self.uam, "_walk_up_for_workspace_creds"))


if __name__ == "__main__":
    unittest.main()
