"""SDLClient resolves credentials from the environment, then the OS keychain,
and never from a file.

Hermetic: no network and no real keychain (S1_KEYCHAIN=off, or subprocess.run
mocked). The "no file" test plants valid-looking decoy credentials.json files
in every location the old loader searched; if any were read, the client would
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
import sdl_client  # noqa: E402

_ALL_ENV = sorted({v for names in s1_keystore.ENV_ALIASES.values() for v in names}
                  | {"S1_PROFILE", "S1_KEYCHAIN", "S1_KEYCHAIN_BACKEND", "COWORK_WORKSPACE",
                     "CLAUDE_CONFIG_DIR", "S1_CREDS_FILE", "SDL_VERIFY_TLS"})

DECOY = {"S1_CONSOLE_URL": "https://decoy.example", "S1_CONSOLE_API_TOKEN": "decoy-token",
         "SDL_S1_SCOPE": "1:2"}


class SDLClientResolution(unittest.TestCase):
    def setUp(self) -> None:
        env = {k: v for k, v in os.environ.items() if k not in _ALL_ENV}
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        s1_keystore.clear_cache()
        self.addCleanup(s1_keystore.clear_cache)

    def test_env_only(self):
        os.environ.update({"S1_KEYCHAIN": "off", "S1_CONSOLE_URL": "https://t.example/",
                           "S1_CONSOLE_API_TOKEN": "tok", "S1_SCOPE": "11:22"})
        c = sdl_client.SDLClient()
        self.assertEqual(c.base_url, "https://t.example/sdl")
        self.assertEqual(c.token, "tok")
        self.assertEqual(c.s1_scope, "11:22")
        self.assertEqual(c._auth_headers()["Authorization"], "Bearer tok")

    def test_scope_alias_and_token_alias(self):
        os.environ.update({"S1_KEYCHAIN": "off", "S1_CONSOLE_URL": "https://t.example",
                           "S1_API_TOKEN": "alias-tok", "SDL_S1_SCOPE": "33"})
        c = sdl_client.SDLClient()
        self.assertEqual((c.token, c.s1_scope), ("alias-tok", "33"))

    def test_overrides_still_apply(self):
        os.environ.update({"S1_KEYCHAIN": "off", "S1_CONSOLE_URL": "https://t.example",
                           "S1_CONSOLE_API_TOKEN": "tok"})
        c = sdl_client.SDLClient(console_api_token="override", s1_scope="9")
        self.assertEqual((c.token, c.s1_scope), ("override", "9"))

    def test_keychain_fallback(self):
        held = {"default:S1_CONSOLE_URL": "https://kc.example",
                "default:S1_CONSOLE_API_TOKEN": "kc-token",
                "default:S1_SCOPE": "44:55"}

        def fake_run(argv, **kw):
            acct = argv[argv.index("-a") + 1]
            if acct in held:
                return subprocess.CompletedProcess(argv, 0, held[acct] + "\n", "")
            return subprocess.CompletedProcess(argv, 44, "", "")

        with mock.patch.object(s1_keystore, "_backend", return_value=("macos", True, "")), \
                mock.patch.object(s1_keystore.subprocess, "run", side_effect=fake_run):
            c = sdl_client.SDLClient()
        self.assertEqual((c.base_url, c.token, c.s1_scope),
                         ("https://kc.example/sdl", "kc-token", "44:55"))

    def test_decoy_files_are_never_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, work, cfgdir = root / "home", root / "work", root / "claudecfg"
            for d in (home / ".config" / "sentinelone", home / ".claude" / "sentinelone",
                      home / "mnt" / "proj", work / ".sentinelone", cfgdir / "sentinelone"):
                d.mkdir(parents=True)
                (d / "credentials.json").write_text(json.dumps(DECOY))
            (work / "credentials.json").write_text(json.dumps(DECOY))
            os.environ.update({"HOME": str(home), "COWORK_WORKSPACE": str(work),
                               "CLAUDE_CONFIG_DIR": str(cfgdir), "S1_KEYCHAIN": "off"})
            cwd = os.getcwd()
            os.chdir(work)
            try:
                with self.assertRaises(RuntimeError) as cm:
                    sdl_client.SDLClient()
            finally:
                os.chdir(cwd)
        msg = str(cm.exception)
        self.assertIn("not configured", msg)
        self.assertIn("s1-secops-mcp setup", msg)
        self.assertIn("S1_KEYCHAIN=off", msg)
        self.assertNotIn("decoy", msg)

    def test_no_file_layer_symbols_remain(self):
        for gone in ("HOME_CREDS_PATH", "DOTCLAUDE_CREDS_PATH", "PLUGIN_CREDS_PATH", "CONFIG_PATH",
                     "_walk_up_for_workspace_creds", "_WORKSPACE_CREDS_RELS", "_apply_sdl_keys"):
            self.assertFalse(hasattr(sdl_client, gone), gone)


if __name__ == "__main__":
    unittest.main()
