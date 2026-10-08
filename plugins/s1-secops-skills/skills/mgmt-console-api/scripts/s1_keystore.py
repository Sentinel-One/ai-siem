#!/usr/bin/env python3
"""
SentinelOne credential lookup: environment variables, then the OS keychain.

Stdlib only. Mirrors s1-secops-mcp/lib/keystore.js and lib/credentials.js so
the MCP server, the Docker launcher and these Python clients all read the same
keychain items.

Resolution per value (first hit wins):
  1. Environment variables (canonical name, then its aliases)
  2. OS keychain item  service="sentinelone-mcp"  account="<profile>:<NAME>"
     profile = $S1_PROFILE (default "default", ^[A-Za-z0-9_.-]{1,64}$)

There is deliberately NO file fallback: no credentials.json, no config.json.

Backends:
  macOS    /usr/bin/security find-generic-password -s sentinelone-mcp -a <account> -w
           (exit 44 = item not found)
  Linux    secret-tool lookup service sentinelone-mcp username <account>
           (exit 1 with empty stderr = not found; D-Bus / locked = unavailable)
  Windows  Credential Manager via ctypes (same items as the Node server)
Disable with S1_KEYCHAIN=off (CI, containers, tests). Force a backend with
S1_KEYCHAIN_BACKEND=macos|linux|native.

Keychain errors never raise out of get(); they are recorded and surface in
not_configured_message().

CLI:
  python3 s1_keystore.py status            source of every value, never the value
  python3 s1_keystore.py setup [NAME ...]  prompt (no echo for secrets) and store
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

SERVICE = "sentinelone-mcp"

KEY_NAMES: Tuple[str, ...] = (
    "S1_CONSOLE_URL",
    "S1_CONSOLE_API_TOKEN",
    "S1_HEC_INGEST_URL",
    "S1_HEC_TOKEN",
    "S1_SCOPE",
    "VIRUSTOTAL_API_KEY",
)

SECRET_NAMES = frozenset({
    "S1_CONSOLE_API_TOKEN",
    "S1_HEC_TOKEN",
    "VIRUSTOTAL_API_KEY",
})

# Environment variables checked for each name, in order.
ENV_ALIASES: Dict[str, Tuple[str, ...]] = {
    "S1_CONSOLE_URL": ("S1_CONSOLE_URL", "S1_BASE_URL"),
    "S1_CONSOLE_API_TOKEN": ("S1_CONSOLE_API_TOKEN", "S1_API_TOKEN", "SDL_CONSOLE_API_TOKEN"),
    "S1_HEC_INGEST_URL": ("S1_HEC_INGEST_URL", "S1_UAM_ALERT_INTERFACE_URL"),
    "S1_HEC_TOKEN": ("S1_HEC_TOKEN",),
    "S1_SCOPE": ("S1_SCOPE", "SDL_S1_SCOPE"),
    "VIRUSTOTAL_API_KEY": ("VIRUSTOTAL_API_KEY", "VT_API_KEY"),
}

_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SECURITY = "/usr/bin/security"
_MAC_NOT_FOUND = 44
_TIMEOUT_S = max(1.0, float(os.environ.get("S1_KEYCHAIN_TIMEOUT_MS") or 15000) / 1000)
_LINUX_UNAVAILABLE_RE = re.compile(
    r"D-Bus|DBUS|autolaunch|org\.freedesktop\.secrets|locked collection|"
    r"No such secret collection|ServiceUnknown", re.IGNORECASE)

SETUP_HINT = ("store it with `s1-secops-mcp setup` (or `python3 <skill>/scripts/s1_keystore.py setup`) "
              "or pass it as an environment variable")


class KeychainUnavailableError(RuntimeError):
    """The OS keychain cannot be read (disabled, missing tool, locked, no D-Bus)."""


# Keychain values are cached per process; environment variables are read live
# so they always win and tests can change them at runtime.
_cache: Dict[Tuple[str, str], Optional[str]] = {}
_last_error: Optional[str] = None
# Set after the first KeychainUnavailableError so later lookups return at once
# instead of paying the timeout again for every value (was 105 s for status on
# a hung keyring). Reset by clear_cache().
_unavailable: Optional[str] = None
_linux_locked: Optional[bool] = None


def clear_cache() -> None:
    global _last_error, _unavailable, _linux_locked
    _unavailable = None
    _linux_locked = None
    _cache.clear()
    _last_error = None


def current_profile(profile: Optional[str] = None) -> str:
    p = (profile if profile is not None else os.environ.get("S1_PROFILE") or "default").strip()
    if not _PROFILE_RE.match(p):
        raise ValueError(f'Invalid S1_PROFILE "{p}": use 1 to 64 letters, digits, dot, dash or underscore.')
    return p


def account_for(name: str, profile: Optional[str] = None) -> str:
    return f"{current_profile(profile)}:{name}"


def _check_name(name: str) -> None:
    if name not in KEY_NAMES:
        raise ValueError(f'Unknown credential name "{name}". Valid: {", ".join(KEY_NAMES)}')


# ─── Windows Credential Manager (ctypes) ────────────────────────────────────
# Same item layout as the Node server (@napi-rs/keyring / keyring-rs) and the
# PowerShell launcher: Generic credential, TargetName "<account>.<service>",
# UserName "<account>", UTF-16LE blob, CRED_PERSIST_ENTERPRISE. The Python
# `keyring` package uses a different TargetName, so it would not see these items.

def _win_cred_api():
    import ctypes
    from ctypes import wintypes

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class _CREDENTIAL(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
                    ("Comment", wintypes.LPWSTR), ("LastWritten", _FILETIME),
                    ("CredentialBlobSize", wintypes.DWORD), ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                    ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
                    ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]

    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(_CREDENTIAL))]
    adv.CredReadW.restype = wintypes.BOOL
    adv.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIAL), wintypes.DWORD]
    adv.CredWriteW.restype = wintypes.BOOL
    adv.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    adv.CredDeleteW.restype = wintypes.BOOL
    adv.CredFree.argtypes = [ctypes.c_void_p]
    return ctypes, adv, _CREDENTIAL


_WIN_NOT_FOUND = 1168  # ERROR_NOT_FOUND


def _win_read(target):
    ctypes, adv, CRED = _win_cred_api()
    p = ctypes.POINTER(CRED)()
    if not adv.CredReadW(target, 1, 0, ctypes.byref(p)):
        err = ctypes.get_last_error()
        if err == _WIN_NOT_FOUND:
            return None
        raise OSError(err, "CredReadW failed")
    try:
        c = p.contents
        raw = ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize) if c.CredentialBlobSize else b""
        try:
            return raw.decode("utf-16-le") or None
        except UnicodeDecodeError:
            # A foreign tool wrote this item in another encoding; treat it as absent
            # rather than marking the whole keychain unavailable.
            return None
    finally:
        adv.CredFree(p)


def _win_write(target, user, value):
    ctypes, adv, CRED = _win_cred_api()
    blob = value.encode("utf-16-le")
    buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    c = CRED()
    c.Type = 1
    c.TargetName = target
    c.UserName = user
    c.Persist = 3
    c.CredentialBlobSize = len(blob)
    c.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
    if not adv.CredWriteW(ctypes.byref(c), 0):
        raise OSError(ctypes.get_last_error(), "CredWriteW failed")



def _backend() -> Tuple[str, bool, str]:
    """(backend name, available, reason). Never raises."""
    if (os.environ.get("S1_KEYCHAIN") or "").strip().lower() == "off":
        return "none", False, "disabled by S1_KEYCHAIN=off"
    forced = (os.environ.get("S1_KEYCHAIN_BACKEND") or "").strip().lower()
    plat = sys.platform
    want = forced or ("macos" if plat == "darwin" else "linux" if plat.startswith("linux")
                      else "native" if plat in ("win32", "cygwin") else "none")
    if want == "macos":
        if plat == "darwin" and os.path.exists(_SECURITY):
            return "macos", True, ""
        return "macos", False, "/usr/bin/security not found (macOS only)"
    if want == "linux":
        if shutil.which("secret-tool"):
            return "linux", True, ""
        return "linux", False, ("secret-tool not found. Install libsecret-tools (Debian/Ubuntu) or "
                                "libsecret (Fedora/Arch), or pass credentials as environment variables.")
    if want == "native":
        if plat == "win32":
            return "native", True, ""  # Credential Manager through ctypes, no package needed
        try:
            import keyring  # noqa: F401
            return "native", True, ""
        except Exception:
            return "native", False, ("the Python `keyring` package is not installed (pip install keyring), "
                                     "or pass credentials as environment variables.")
    return "none", False, f"no keychain backend for platform {plat}"


def available() -> Tuple[bool, str]:
    """(True, backend name) when a keychain backend can be used, else (False, reason)."""
    name, ok, reason = _backend()
    return (True, name) if ok else (False, reason)


def _run(argv: List[str], stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise KeychainUnavailableError(f"{argv[0]} timed out after {_TIMEOUT_S}s (keychain locked or prompting?)")
    except OSError as e:
        raise KeychainUnavailableError(f"could not run {argv[0]}: {e}")


def _strip_nl(s: str) -> str:
    return s[:-2] if s.endswith("\r\n") else s[:-1] if s.endswith("\n") else s


def _linux_error(stderr: str, code: int, op: str) -> KeychainUnavailableError:
    s = (stderr or "").strip()
    if _LINUX_UNAVAILABLE_RE.search(s):
        return KeychainUnavailableError(
            f"Linux keyring unavailable ({op}): {s}. secret-tool needs a D-Bus session with an unlocked "
            "Secret Service (gnome-keyring or KeePassXC). On a headless host pass credentials as "
            "environment variables instead.")
    return KeychainUnavailableError(f"Linux keyring {op} failed: {s or 'exit ' + str(code)}")


def _linux_is_locked() -> bool:
    global _linux_locked
    if _linux_locked is None:
        r = _run(["secret-tool", "search", "--all", "service", SERVICE])
        _linux_locked = bool(re.search(r"locked", r.stderr or "", re.IGNORECASE))
    return _linux_locked


def keychain_get(name: str, profile: Optional[str] = None) -> Optional[str]:
    """Read one value from the keychain only. None when absent.

    Raises KeychainUnavailableError when the keychain cannot be read and
    ValueError for an unknown name or an invalid profile.
    """
    _check_name(name)
    backend, ok, reason = _backend()
    if not ok:
        raise KeychainUnavailableError(f"OS keychain unavailable: {reason}")
    acct = account_for(name, profile)
    if backend == "macos":
        r = _run([_SECURITY, "find-generic-password", "-s", SERVICE, "-a", acct, "-w"])
        if r.returncode == 0:
            return _strip_nl(r.stdout) or None
        if r.returncode == _MAC_NOT_FOUND:
            return None
        raise KeychainUnavailableError(
            f"macOS keychain read failed: {(r.stderr or '').strip() or 'exit ' + str(r.returncode)}")
    if backend == "linux":
        r = _run(["secret-tool", "lookup", "service", SERVICE, "username", acct])
        if r.returncode == 0:
            return _strip_nl(r.stdout) or None
        if r.returncode == 1 and not (r.stderr or "").strip():
            # A LOCKED collection also answers exit 1 with empty stderr; `search`
            # says so. Probe once per process so "locked" is not shown as "unset".
            if _linux_is_locked():
                raise KeychainUnavailableError(
                    "Linux keyring is locked. Unlock it (log in to the desktop session, or "
                    "`gnome-keyring-daemon --unlock`), or pass credentials as environment variables.")
            return None
        raise _linux_error(r.stderr, r.returncode, "read")
    if sys.platform == "win32":
        try:
            return _win_read(f"{acct}.{SERVICE}")
        except Exception as e:
            raise KeychainUnavailableError(f"Windows Credential Manager read failed: {e}")
    try:
        import keyring
        return keyring.get_password(SERVICE, acct) or None
    except Exception as e:
        raise KeychainUnavailableError(f"OS keychain read failed (keyring): {e}")


def from_env(name: str) -> Optional[Tuple[str, str]]:
    """(value, env var name) from the environment, or None."""
    for k in ENV_ALIASES.get(name, (name,)):
        v = os.environ.get(k)
        if v:
            return v, k
    return None


def resolve(name: str, profile: Optional[str] = None) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(value, source, keychain_error). Never raises except for an unknown name.

    source is "env:<VAR>", "keychain:<backend>" or None.
    """
    global _last_error, _unavailable
    _check_name(name)
    hit = from_env(name)
    if hit:
        return hit[0], f"env:{hit[1]}", None
    if _unavailable:
        return None, None, _unavailable
    try:
        prof = current_profile(profile)
    except ValueError as e:
        _last_error = str(e)
        return None, None, _last_error
    key = (prof, name)
    if key in _cache:
        v = _cache[key]
        return v, (f"keychain:{_backend()[0]}" if v else None), None
    try:
        v = keychain_get(name, prof)
    except KeychainUnavailableError as e:
        _last_error = _unavailable = str(e)
        return None, None, _last_error
    except ValueError as e:
        _last_error = str(e)
        return None, None, _last_error
    except Exception as e:  # never crash a client over the keychain
        _last_error = f"OS keychain read failed: {type(e).__name__}: {e}"
        return None, None, _last_error
    _cache[key] = v
    return v, (f"keychain:{_backend()[0]}" if v else None), None


def get(name: str, profile: Optional[str] = None) -> Optional[str]:
    """Value from the environment, else the OS keychain, else None. Never raises on keychain errors."""
    return resolve(name, profile)[0]


def keychain_error() -> Optional[str]:
    """The last keychain problem seen in this process, or the reason none is available."""
    if _last_error:
        return _last_error
    ok, reason = available()
    return None if ok else f"OS keychain unavailable: {reason}"


def not_configured_message(name: str, what: Optional[str] = None) -> str:
    """Clear "not configured" message for a missing value, with the keychain reason."""
    envs = ENV_ALIASES.get(name, (name,))[0]
    try:
        prof = current_profile()
    except ValueError:
        prof = os.environ.get("S1_PROFILE", "default")
    kc = keychain_error()
    tail = f" ({kc})" if kc else ""
    return (f"{what or name} is not configured. Looked in the environment ({envs}) and the OS keychain "
            f"(service {SERVICE}, account {prof}:{name}). To fix: {SETUP_HINT}{tail}.")


# ─── write path (setup) ──────────────────────────────────────────────────────

def _mac_quote(v: str, what: str) -> str:
    if re.search(r'["\\\r\n]', v):
        raise ValueError(f"{what} contains a quote, backslash or newline, which the macOS keychain CLI "
                         "cannot take safely.")
    return f'"{v}"'


def keychain_set(name: str, value: str, profile: Optional[str] = None) -> None:
    """Store one value, then read it back to prove the write landed."""
    _check_name(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Empty value for {name}")
    # Same shape the SDL clients accept for S1-Scope; a group part breaks every SDL call.
    if name == "S1_SCOPE" and not re.fullmatch(r"\d+(:\d+)?", value):
        raise ValueError("S1_SCOPE must be <accountId> or <accountId>:<siteId> (numeric ids)")
    backend, ok, reason = _backend()
    if not ok:
        raise KeychainUnavailableError(f"OS keychain unavailable: {reason}")
    prof = current_profile(profile)
    acct = account_for(name, prof)
    label = f"SentinelOne MCP {prof} {name}"
    if backend == "macos":
        # `security -i` reads the command on stdin, so the secret never appears in argv.
        cmd = (f"add-generic-password -U -s {_mac_quote(SERVICE, 'service')} -a {_mac_quote(acct, 'account')} "
               f"-l {_mac_quote(label, 'label')} -w {_mac_quote(value, 'value')}\n")
        r = _run([_SECURITY, "-i"], stdin=cmd)
        if r.returncode != 0 or re.search(r"error|could not", r.stderr or "", re.IGNORECASE):
            raise KeychainUnavailableError(
                f"macOS keychain write failed: {(r.stderr or '').strip() or 'exit ' + str(r.returncode)}")
    elif backend == "linux":
        r = _run(["secret-tool", "store", "--label", label, "service", SERVICE, "username", acct], stdin=value)
        if r.returncode != 0:
            raise _linux_error(r.stderr, r.returncode, "write")
    else:
        try:
            if sys.platform == "win32":
                _win_write(f"{acct}.{SERVICE}", acct, value)
            else:
                import keyring
                keyring.set_password(SERVICE, acct, value)
        except Exception as e:
            raise KeychainUnavailableError(f"OS keychain write failed (keyring): {e}")
    _cache.pop((prof, name), None)
    if keychain_get(name, prof) != value:
        raise KeychainUnavailableError(f"Keychain write for {name} did not read back correctly.")
    _cache[(prof, name)] = value


# ─── CLI ─────────────────────────────────────────────────────────────────────

def _status() -> int:
    ok, info = available()
    try:
        prof = current_profile()
    except ValueError as e:
        print(f"profile: INVALID ({e})")
        prof = None
    print(f"profile: {prof}")
    width = max(len(n) for n in KEY_NAMES)
    rows = [(name,) + resolve(name) for name in KEY_NAMES]
    # A backend can be installed but unusable (no D-Bus, locked, hung): report
    # the keychain itself as unavailable instead of every row as "missing".
    if ok and _unavailable:
        ok, info = False, _unavailable
    print(f"keychain: {'available (' + info + ')' if ok else 'unavailable: ' + info}")
    for name, v, src, err in rows:
        if v:
            # UTF-16 code units, matching the Node CLI and the PowerShell launcher.
            print(f"  {name:<{width}}  set ({len(v.encode('utf-16-le')) // 2} chars)  from {src}")
        elif not ok:
            print(f"  {name:<{width}}  unavailable")
        else:
            print(f"  {name:<{width}}  missing")
    return 0 if ok else 2


def _setup(names: List[str]) -> int:
    import getpass
    ok, info = available()
    if not ok:
        print(f"OS keychain unavailable: {info}", file=sys.stderr)
        return 2
    prof = current_profile()
    todo = names or list(KEY_NAMES)
    for n in todo:
        _check_name(n)
    print(f"Storing values in the OS keychain ({info}), service {SERVICE}, profile {prof}.")
    print("Press Enter to leave a value unchanged. Secrets are read without echo.")
    for n in todo:
        prompt = f"{n}: "
        try:
            val = getpass.getpass(prompt) if n in SECRET_NAMES else input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        val = val.strip()
        if not val:
            continue
        try:
            keychain_set(n, val, prof)
            print(f"  stored {n} ({len(val.encode('utf-16-le')) // 2} chars), read back OK")
        except (KeychainUnavailableError, ValueError) as e:
            print(f"  {n} NOT stored: {e}", file=sys.stderr)
            return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="SentinelOne credentials: environment, then OS keychain.")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("status", help="show where each value comes from (never prints values)")
    sp = sub.add_parser("setup", help="prompt for values and store them in the OS keychain")
    sp.add_argument("names", nargs="*", help=f"subset of: {', '.join(KEY_NAMES)}")
    a = ap.parse_args(argv)
    if a.cmd == "setup":
        return _setup(a.names)
    return _status()


if __name__ == "__main__":
    sys.exit(main())
