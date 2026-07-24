# Finding SVP-06 — MCP Agent Auth-Gate Verified Solid (No IDOR / Auth Bypass)

**Severity:** 🟢 Info (PASS — documented as evidence of hardening)
**Component:** svpchain-agent MCP server (indexer.svpchain.com/mcp)
**Type:** Authorization gate (verified)
**Auditor:** Nalreee | Date: 2026-07-23

## Why / what was tested
Recovered the public `sign_challenge` spec, obtained a **legitimate** bearer token, then ran a
full attempt matrix: fake bearer, empty/garbage `auth_verify`, cross-tenant
`get_subaccount(target=B)` under A's session.

## Result
All forged/mismatched/cross-tenant attempts rejected. Session strictly scoped to owner.
**No IDOR / auth bypass.** Documented as proof the gate holds (not a vulnerability).

## How to check
`mcp_auth_probe.py` (from superagent-bugbounty skill) + `mcp_idor.py`, `exploit_idor.py`.

## Note
Keep as evidence of hardening; not a finding to fix.
