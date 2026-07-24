# Finding SVP-01 — CORS `Access-Control-Allow-Origin: *` on pre-bridge `/api/health`

**Severity:** 🟢 Info / Low
**Component:** pre-bridge.svpstars.com (legacy/standby bridge frontend)
**Type:** Misconfiguration (CORS)
**Auditor:** Nalreee | Date: 2026-07-22

## Why
`/api/health` and 404 responses return `Access-Control-Allow-Origin: *`. Data-bearing endpoints
do NOT send the header.

## Impact
Info-only: `/api/health` returns `{"result":"ok"}` (no sensitive data). Practical risk minimal.

## How to check
```bash
curl -s -D - -o /dev/null -H "Origin: https://evil.example.com" \
  https://pre-bridge.svpstars.com/api/health
# -> Access-Control-Allow-Origin: *
```

## Proof
See `FINDINGS.md` (live curl output). PoC: `poc_*` (n/a — config only).

## Fix
Remove CORS `*` from health/404 or scope to known origins.
