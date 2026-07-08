#!/usr/bin/env python3
"""
RBA Console - zero-dependency local proxy + static UI server.

Reads SentinelOne SDL creds from the Claude Desktop config at runtime
(nothing hard-coded), injects Bearer + talks to the SDL xdr host, and
serves the 4-tab RBA demo UI at http://localhost:8787

Run:  python3 server.py
Then open http://localhost:8787 in your browser.
"""
import json, os, urllib.request, urllib.error, http.server, socketserver, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
CONFIG = os.path.expanduser("~/Library/Application Support/Claude/claude_desktop_config.json")
PORT = int(os.environ.get("RBA_PORT", "8787"))

try:
    env = json.load(open(CONFIG))["mcpServers"]["sentinelone-mcp"]["env"]
except Exception as e:
    sys.exit(f"Could not read sentinelone-mcp creds from {CONFIG}: {e}")

XDR = env["SDL_XDR_URL"].rstrip("/")
K_LOG_READ   = env.get("SDL_LOG_READ_KEY")    or env.get("S1_CONSOLE_API_TOKEN")
K_CFG_READ   = env.get("SDL_CONFIG_READ_KEY") or K_LOG_READ
K_CFG_WRITE  = env.get("SDL_CONFIG_WRITE_KEY") or K_CFG_READ


def sdl(ep, body, key):
    req = urllib.request.Request(
        XDR + ep,
        data=json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 502, json.dumps({"error": str(e)}).encode()


class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            try:
                self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, f"cannot read index.html: {e}", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except Exception:
            data = {}
        if self.path == "/api/powerQuery":
            code, out = sdl("/api/powerQuery",
                            {"query": data.get("query", ""), "startTime": data.get("startTime", "24h")},
                            K_LOG_READ)
        elif self.path == "/api/getFile":
            code, out = sdl("/api/getFile", {"path": data.get("path", "")}, K_CFG_READ)
        elif self.path == "/api/putFile":
            body = {"path": data.get("path", ""), "content": data.get("content", "")}
            code, out = sdl("/api/putFile", body, K_CFG_WRITE)
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
