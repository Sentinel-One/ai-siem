"""Unit tests for scripts/s1_keystore.py (environment, then OS keychain).

Hermetic: no network, no tenant, and no real keychain. Every keychain call goes
through subprocess.run, which is mocked here; the backend probe is pinned so the
same tests run on macOS and on a Linux CI runner.

An identical copy lives in mgmt-console-api/tests and sdl-api/tests because the
two skills ship s1_keystore.py independently.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
_spec = importlib.util.spec_from_file_location("s1_keystore_under_test", SCRIPTS / "s1_keystore.py")
ks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ks)

# Every variable the module reads, cleared for each test.
_ALL_ENV = sorted({v for names in ks.ENV_ALIASES.values() for v in names}
                  | {"S1_PROFILE", "S1_KEYCHAIN", "S1_KEYCHAIN_BACKEND"})


def _cp(rc: int, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=out, stderr=err)


class _Base(unittest.TestCase):
    backend = ("macos", True, "")

    def setUp(self) -> None:
        env = {k: v for k, v in os.environ.items() if k not in _ALL_ENV}
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        if self.backend is not None:
            b = mock.patch.object(ks, "_backend", return_value=self.backend)
            b.start()
            self.addCleanup(b.stop)
        self.run_mock = mock.MagicMock(side_effect=AssertionError("keychain must not be called"))
        r = mock.patch.object(ks.subprocess, "run", self.run_mock)
        r.start()
        self.addCleanup(r.stop)
        ks.clear_cache()
        self.addCleanup(ks.clear_cache)


class EnvPrecedence(_Base):
    def test_env_wins_and_keychain_is_not_called(self):
        os.environ["S1_CONSOLE_API_TOKEN"] = "env-token-value"
        self.assertEqual(ks.get("S1_CONSOLE_API_TOKEN"), "env-token-value")
        v, src, err = ks.resolve("S1_CONSOLE_API_TOKEN")
        self.assertEqual(src, "env:S1_CONSOLE_API_TOKEN")
        self.run_mock.assert_not_called()

    def test_aliases(self):
        os.environ["S1_API_TOKEN"] = "alias-token"
        os.environ["SDL_S1_SCOPE"] = "123:456"
        os.environ["S1_BASE_URL"] = "https://x.example"
        os.environ["S1_UAM_ALERT_INTERFACE_URL"] = "https://ingest.example"
        self.assertEqual(ks.get("S1_CONSOLE_API_TOKEN"), "alias-token")
        self.assertEqual(ks.get("S1_SCOPE"), "123:456")
        self.assertEqual(ks.get("S1_CONSOLE_URL"), "https://x.example")
        self.assertEqual(ks.get("S1_HEC_INGEST_URL"), "https://ingest.example")
        self.run_mock.assert_not_called()

    def test_canonical_beats_alias(self):
        os.environ["S1_CONSOLE_API_TOKEN"] = "canonical"
        os.environ["SDL_CONSOLE_API_TOKEN"] = "legacy"
        self.assertEqual(ks.get("S1_CONSOLE_API_TOKEN"), "canonical")

    def test_env_beats_keychain(self):
        os.environ["S1_CONSOLE_URL"] = "https://env.example"
        self.run_mock.side_effect = None
        self.run_mock.return_value = _cp(0, "https://keychain.example\n")
        self.assertEqual(ks.get("S1_CONSOLE_URL"), "https://env.example")
        self.run_mock.assert_not_called()

    def test_unknown_name_rejected(self):
        with self.assertRaises(ValueError):
            ks.get("NOT_A_NAME")


class KeychainOff(_Base):
    backend = None  # exercise the real probe

    def test_off_disables_lookup(self):
        os.environ["S1_KEYCHAIN"] = "off"
        self.assertEqual(ks.available(), (False, "disabled by S1_KEYCHAIN=off"))
        self.assertIsNone(ks.get("S1_CONSOLE_API_TOKEN"))
        self.run_mock.assert_not_called()
        msg = ks.not_configured_message("S1_CONSOLE_API_TOKEN")
        self.assertIn("S1_KEYCHAIN=off", msg)
        self.assertIn("s1-secops-mcp setup", msg)
        self.assertIn("environment variable", msg)
        self.assertIn("default:S1_CONSOLE_API_TOKEN", msg)
        self.assertNotIn("credentials.json", msg)

    def test_off_still_honours_env(self):
        os.environ["S1_KEYCHAIN"] = "OFF"
        os.environ["S1_CONSOLE_URL"] = "https://env.example"
        self.assertEqual(ks.get("S1_CONSOLE_URL"), "https://env.example")


class MacBackend(_Base):
    def test_found(self):
        self.run_mock.side_effect = None
        self.run_mock.return_value = _cp(0, "kc-token\n")
        self.assertEqual(ks.get("S1_CONSOLE_API_TOKEN"), "kc-token")
        argv = self.run_mock.call_args[0][0]
        self.assertEqual(argv, ["/usr/bin/security", "find-generic-password", "-s", "sentinelone-mcp",
                                "-a", "default:S1_CONSOLE_API_TOKEN", "-w"])
        self.assertEqual(ks.resolve("S1_CONSOLE_API_TOKEN")[1], "keychain:macos")

    def test_profile_selects_account(self):
        os.environ["S1_PROFILE"] = "work.prod-1"
        self.run_mock.side_effect = None
        self.run_mock.return_value = _cp(0, "v\n")
        ks.get("S1_HEC_TOKEN")
        self.assertIn("work.prod-1:S1_HEC_TOKEN", self.run_mock.call_args[0][0])

    def test_not_found_is_none_without_error(self):
        self.run_mock.side_effect = None
        self.run_mock.return_value = _cp(44, "", "security: SecKeychainSearchCopyNext: not found")
        v, src, err = ks.resolve("S1_CONSOLE_API_TOKEN")
        self.assertEqual((v, src, err), (None, None, None))
        self.assertIsNone(ks.keychain_error())

    def test_other_failure_is_reported_not_raised(self):
        self.run_mock.side_effect = None
        self.run_mock.return_value = _cp(36, "", "User interaction is not allowed.")
        self.assertIsNone(ks.get("S1_CONSOLE_API_TOKEN"))
        msg = ks.not_configured_message("S1_CONSOLE_API_TOKEN")
        self.assertIn("User interaction is not allowed.", msg)
        self.assertIn("s1-secops-mcp setup", msg)

    def test_timeout_does_not_crash(self):
        self.run_mock.side_effect = subprocess.TimeoutExpired(cmd="security", timeout=15)
        self.assertIsNone(ks.get("S1_CONSOLE_URL"))
        self.assertIn("timed out", ks.keychain_error())

    def test_missing_binary_does_not_crash(self):
        self.run_mock.side_effect = FileNotFoundError("no such file")
        self.assertIsNone(ks.get("S1_CONSOLE_URL"))
        self.assertIn("could not run", ks.keychain_error())

    def test_cached_per_process(self):
        self.run_mock.side_effect = None
        self.run_mock.return_value = _cp(0, "x\n")
        ks.get("S1_SCOPE")
        ks.get("S1_SCOPE")
        self.assertEqual(self.run_mock.call_count, 1)


class BadProfile(_Base):
    def test_bad_profile(self):
        os.environ["S1_PROFILE"] = "bad profile!"
        self.assertIsNone(ks.get("S1_CONSOLE_API_TOKEN"))
        self.run_mock.assert_not_called()
        with self.assertRaises(ValueError):
            ks.keychain_get("S1_CONSOLE_API_TOKEN")
        self.assertIn("Invalid S1_PROFILE", ks.not_configured_message("S1_CONSOLE_API_TOKEN"))

    def test_profile_too_long(self):
        with self.assertRaises(ValueError):
            ks.current_profile("a" * 65)
        self.assertEqual(ks.current_profile("a" * 64), "a" * 64)

    def test_bad_profile_env_still_works(self):
        os.environ["S1_PROFILE"] = "../etc"
        os.environ["S1_CONSOLE_URL"] = "https://env.example"
        self.assertEqual(ks.get("S1_CONSOLE_URL"), "https://env.example")


class LinuxBackend(_Base):
    backend = ("linux", True, "")

    def test_lookup_argv_and_found(self):
        self.run_mock.side_effect = None
        self.run_mock.return_value = _cp(0, "secret\n")
        self.assertEqual(ks.get("S1_HEC_TOKEN"), "secret")
        self.assertEqual(self.run_mock.call_args[0][0],
                         ["secret-tool", "lookup", "service", "sentinelone-mcp",
                          "username", "default:S1_HEC_TOKEN"])

    def test_not_found(self):
        self.run_mock.side_effect = None
        self.run_mock.return_value = _cp(1, "", "")
        self.assertEqual(ks.resolve("S1_HEC_TOKEN"), (None, None, None))

    def test_dbus_unavailable(self):
        self.run_mock.side_effect = None
        self.run_mock.return_value = _cp(1, "", "Cannot autolaunch D-Bus without X11 $DISPLAY")
        v, src, err = ks.resolve("S1_HEC_TOKEN")
        self.assertIsNone(v)
        self.assertIn("Linux keyring unavailable", err)
        self.assertIn("environment variables", err)


class Writes(_Base):
    def test_mac_write_uses_stdin_not_argv(self):
        calls = []

        def fake(argv, input=None, **kw):
            calls.append((argv, input))
            if argv[1:2] == ["-i"]:
                return _cp(0)
            return _cp(0, "the-secret\n")

        self.run_mock.side_effect = fake
        ks.keychain_set("S1_CONSOLE_API_TOKEN", "the-secret")
        write_argv, write_stdin = calls[0]
        self.assertEqual(write_argv, ["/usr/bin/security", "-i"])
        self.assertNotIn("the-secret", " ".join(write_argv))
        self.assertIn('-a "default:S1_CONSOLE_API_TOKEN"', write_stdin)
        self.assertIn('-w "the-secret"', write_stdin)

    def test_mac_rejects_unquotable_values(self):
        for bad in ('a"b', "a\\b", "a\nb"):
            with self.assertRaises(ValueError):
                ks.keychain_set("S1_CONSOLE_API_TOKEN", bad)
        self.run_mock.assert_not_called()

    def test_scope_with_group_part_rejected(self):
        # The SDL clients only accept <accountId> or <accountId>:<siteId>.
        for bad in ("123:456:789", "abc", "123:"):
            with self.assertRaises(ValueError):
                ks.keychain_set("S1_SCOPE", bad)
        self.run_mock.assert_not_called()

    def test_readback_mismatch_fails(self):
        def fake(argv, input=None, **kw):
            return _cp(0) if argv[1:2] == ["-i"] else _cp(0, "different\n")
        self.run_mock.side_effect = fake
        with self.assertRaises(ks.KeychainUnavailableError):
            ks.keychain_set("S1_HEC_TOKEN", "value")


class StatusCli(_Base):
    def test_status_never_prints_values(self):
        os.environ["S1_CONSOLE_API_TOKEN"] = "super-secret-token-value"
        os.environ["S1_CONSOLE_URL"] = "https://tenant.example"
        self.run_mock.side_effect = None
        self.run_mock.return_value = _cp(0, "keychain-held-secret\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ks.main(["status"])
        out = buf.getvalue()
        self.assertNotIn("super-secret-token-value", out)
        self.assertNotIn("keychain-held-secret", out)
        self.assertNotIn("tenant.example", out)
        self.assertIn("env:S1_CONSOLE_API_TOKEN", out)
        self.assertIn("keychain:macos", out)


if __name__ == "__main__":
    unittest.main()
