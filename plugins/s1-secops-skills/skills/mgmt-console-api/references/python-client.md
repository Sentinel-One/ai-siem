## Using the client in Python: full examples

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
