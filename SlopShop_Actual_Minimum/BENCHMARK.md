# SlopShop_Actual_Minimum (evaluator-only)

> Remove `BENCHMARK.md` and `tools/` before pointing a scanner here. What remains —
> `README.md`, `services/`, `infra/` — is an ordinary app. The answer key lives outside
> this dir at `VulnerabilityKeys/SlopShop_Actual_Minimum.vulnerability_key.json`.

80 real CVEs, advisories AND fix commits after 2025-12-01, each self-contained in one
file so an LLM scanner is not overloaded with module context or file count. Built by
selecting single-file fixes from SlopShop_Actual (see `tools/build_min.py`).

## Scoring (from the suite root)

```
python scoring/score.py --bench minimum --sarif your_run.sarif
```
