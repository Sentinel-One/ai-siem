# monitors/

Python monitors for the Dataset Agent. See the root [README](../README.md#monitors-installation-guide)
for installation.

| File | Purpose |
| ---- | ------- |
| `log_gen.py` | Generate test logs for supported vendor formats |
| `maxmind.py` | MaxMind GeoIP enrichment |
| `powerquerymonitor.py` | PowerQuery monitoring |

Dependencies are declared in `requirements.in` and pinned with hashes in
`requirements.txt`. Regenerate after changing them:

```bash
pip-compile --generate-hashes --output-file requirements.txt requirements.in
```
