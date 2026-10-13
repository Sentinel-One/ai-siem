#!/usr/bin/env python3
"""
RBA Console - zero-dependency local proxy + static UI server.

Reads S1_CONSOLE_URL and S1_CONSOLE_API_TOKEN at runtime from the environment,
else the OS keychain (service "sentinelone-mcp", account "<S1_PROFILE>:<NAME>",
the items `s1-secops-mcp setup` writes). Nothing is hard-coded and no config
file is read. Injects Bearer, talks to the SDL host, and serves the 4-tab RBA
demo UI at http://localhost:8787

Run:  python3 server.py
Then open http://localhost:8787 in your browser.
"""
import json, os, re, secrets, shutil, subprocess, urllib.request, urllib.error, http.server, socketserver, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
PORT = int(os.environ.get("RBA_PORT", "8787"))
# CSRF guard: only requests from this server's own UI origin may hit the proxy.
# The proxy injects a credentialed SDL Bearer, so a wildcard CORS policy would let any
# site open in the browser drive SDL writes. Same-origin only; no cross-origin exposure.
ALLOWED_ORIGINS = {f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}"}
# Second guard: the origin check alone still admits Origin-less requests (curl,
# any local process), which could otherwise drive /api/putFile with the
# console API token. A per-session token is minted at startup, injected into the
# served HTML, and must be echoed back by the frontend as the X-RBA-Token
# header on every /api/ POST.
SESSION_TOKEN = secrets.token_hex(16)

_ENV_ALIASES = {
    "S1_CONSOLE_URL": ("S1_CONSOLE_URL", "S1_BASE_URL"),
    "S1_CONSOLE_API_TOKEN": ("S1_CONSOLE_API_TOKEN", "S1_API_TOKEN", "SDL_CONSOLE_API_TOKEN"),
}


def _keychain_get(name):
    """(value, error) from the OS keychain; mirrors mgmt-console-api/scripts/s1_keystore.py. Never raises."""
    if (os.environ.get("S1_KEYCHAIN") or "").strip().lower() == "off":
        return None, "disabled by S1_KEYCHAIN=off"
    prof = (os.environ.get("S1_PROFILE") or "default").strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,64}$", prof):
        return None, 'invalid S1_PROFILE "%s"' % prof
    acct = "%s:%s" % (prof, name)
    try:
        if sys.platform == "darwin" and os.path.exists("/usr/bin/security"):
            r = subprocess.run(["/usr/bin/security", "find-generic-password", "-s", "sentinelone-mcp",
                                "-a", acct, "-w"], capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                return r.stdout.rstrip("\r\n") or None, None
            if r.returncode == 44:
                return None, None
            return None, "macOS keychain read failed: " + (r.stderr.strip() or "exit %d" % r.returncode)
        if sys.platform.startswith("linux"):
            if not shutil.which("secret-tool"):
                return None, "secret-tool not found"
            r = subprocess.run(["secret-tool", "lookup", "service", "sentinelone-mcp", "username", acct],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                return r.stdout.rstrip("\r\n") or None, None
            if r.returncode == 1 and not r.stderr.strip():
                return None, None
            return None, "Linux keyring unavailable: " + (r.stderr.strip() or "exit %d" % r.returncode)
        if sys.platform == "win32":
            # Same Credential Manager item as the Node server and the PowerShell
            # launcher: TargetName "<account>.sentinelone-mcp", UTF-16LE blob.
            import ctypes
            from ctypes import wintypes
            class _CRED(ctypes.Structure):
                _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
                            ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.DWORD * 2),
                            ("CredentialBlobSize", wintypes.DWORD), ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                            ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
                            ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]
            adv = ctypes.WinDLL("advapi32", use_last_error=True)
            p = ctypes.POINTER(_CRED)()
            if not adv.CredReadW(acct + ".sentinelone-mcp", 1, 0, ctypes.byref(p)):
                err = ctypes.get_last_error()
                return (None, None) if err == 1168 else (None, "Windows Credential Manager read failed: %d" % err)
            try:
                c = p.contents
                return ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize).decode("utf-16-le") or None, None
            finally:
                adv.CredFree(p)
        try:
            import keyring
        except Exception:
            return None, "no keychain backend (install the Python keyring package)"
        return keyring.get_password("sentinelone-mcp", acct) or None, None
    except Exception as e:
        return None, "OS keychain read failed: %s" % e


def _cred(name):
    """Environment first (canonical name, then aliases), then the OS keychain. Exits with a clear message."""
    for k in _ENV_ALIASES[name]:
        if os.environ.get(k):
            return os.environ[k]
    v, err = _keychain_get(name)
    if not v:
        sys.exit("%s not configured (looked in the environment and the OS keychain). Store it with "
                 "`s1-secops-mcp setup` or pass it as an environment variable%s."
                 % (name, " (OS keychain: %s)" % err if err else ""))
    return v


XDR = _cred("S1_CONSOLE_URL").rstrip("/") + "/sdl"
# Fail fast with a clear message rather than crashing on `"Bearer " + None` at
# request time when no token is configured.
TOKEN = _cred("S1_CONSOLE_API_TOKEN")


def sdl(ep, body, key):
    req = urllib.request.Request(
        XDR + ep,
        data=json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return _sdl_status(r.status, r.read())
    except urllib.error.HTTPError as e:
        return _sdl_status(e.code, e.read())
    except Exception as e:
        return 502, json.dumps({"error": str(e)}).encode()


def _sdl_status(http_status, raw):
    """Map an SDL response onto an honest HTTP status for the browser.

    SDL signals failure as HTTP 200 with a body carrying status "error/...".
    Proxying the transport status alone renders a rejected putFile as a
    successful save in the editor, which is silent data loss. sdl_client.py
    applies the same rule: a body status starting with "error/" is a failure
    whatever the HTTP code says.
    """
    try:
        parsed = json.loads(raw) if raw else {}
    except (ValueError, TypeError):
        return http_status, raw
    sdl_state = parsed.get("status") if isinstance(parsed, dict) else None
    if http_status < 400 and isinstance(sdl_state, str) and sdl_state.startswith("error/"):
        # The UI reads `error` first, so surface SDL's own wording rather than
        # leaving it to render a bare "HTTP 502".
        out = dict(parsed)
        out.setdefault("error", parsed.get("message") or sdl_state)
        return 502, json.dumps(out).encode()
    return http_status, raw


class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            try:
                html = (HERE / "index.html").read_text(encoding="utf-8")
                # Inject the per-session API token so the frontend can echo it
                # back as X-RBA-Token on /api/ POSTs (see do_POST).
                html = html.replace("__RBA_SESSION_TOKEN__", SESSION_TOKEN)
                self._send(200, html, "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, f"cannot read index.html: {e}", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        origin = self.headers.get("Origin")
        if origin and origin not in ALLOWED_ORIGINS:
            self._send(403, json.dumps({"error": "cross-origin request rejected"}))
            return
        # Per-session token check on every /api/ POST: rejects Origin-less
        # local clients that never loaded the UI. compare_digest keeps the
        # comparison constant-time.
        if self.path.startswith("/api/"):
            token = self.headers.get("X-RBA-Token") or ""
            if not secrets.compare_digest(token, SESSION_TOKEN):
                self._send(403, json.dumps({"error": "missing or invalid X-RBA-Token"}))
                return
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except Exception as e:
            self._send(400, json.dumps({"error": f"invalid JSON body: {e}"}))
            return
        if self.path == "/api/powerQuery":
            code, out = sdl("/api/powerQuery",
                            {"query": data.get("query", ""), "startTime": data.get("startTime", "24h")},
                            TOKEN)
        elif self.path == "/api/getFile":
            code, out = sdl("/api/getFile", {"path": data.get("path", "")}, TOKEN)
        elif self.path == "/api/putFile":
            body = {"path": data.get("path", ""), "content": data.get("content", "")}
            # Optimistic concurrency: forward the version captured at getFile time so a
            # concurrent editor's save fails loudly instead of being silently overwritten.
            if data.get("expectedVersion") is not None:
                body["expectedVersion"] = data["expectedVersion"]
            code, out = sdl("/api/putFile", body, TOKEN)
        else:
            code, out = 404, b'{"error":"unknown endpoint"}'
        self._send(code, out)

    def log_message(self, *a):
        pass


socketserver.TCPServer.allow_reuse_address = True
if __name__ == "__main__":
    with socketserver.TCPServer(("127.0.0.1", PORT), H) as httpd:
        print(f"RBA console  ->  http://localhost:{PORT}")
        print(f"SDL host     ->  {XDR}")
        print("Ctrl-C to stop.")
        httpd.serve_forever()
