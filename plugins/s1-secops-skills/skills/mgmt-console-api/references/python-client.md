## Using the client in Python: full examples

The Python client is host-only. Run it from Claude Code or a terminal on the user's machine; it cannot reach `*.sentinelone.net` from the Cowork sandbox, where the `s1_api_*` MCP tools are the path. It reads each credential from the environment first, then from the OS keychain (service `sentinelone-mcp`, account `<profile>:<NAME>`, profile from `S1_PROFILE`), the same entries `s1-secops-mcp setup` writes. On Windows, keychain reads need the Python `keyring` package. There is no credentials file.

```python
import sys
sys.path.insert(0, "scripts")  # or set PYTHONPATH
from s1_client import S1Client, S1APIError

c = S1Client(cache_ttl=60)   # optional 60s cache for accounts/sites/groups/system-info

# single page
r = c.get("/web/api/v2.1/threats", params={"limit": 100, "resolved": False})

# full iteration
for threat in c.iter_items("/web/api/v2.1/threats", params={"limit": 200}):
    ...

# parallel fan-out: independent GETs over pooled connections (~3× faster)
results = c.get_many([
    ("/web/api/v2.1/accounts", {"limit": 1}),
    ("/web/api/v2.1/sites",    {"limit": 1}),
    ("/web/api/v2.1/groups",   {"limit": 1}),
    ("/web/api/v2.1/system/info", None),
], max_workers=8)
# -> [{"path":..., "ok":True, "status":200, "data":..., "elapsed_ms":...}, ...]

# action endpoint
c.post("/web/api/v2.1/agents/actions/disconnect", json_body={"filter": {"ids": ["AGENT_ID"]}})
```
