# Finding SVP-05 — Staging `pre-*` Subdomains Serve Production-Identical Apps

**Severity:** 🟢 Low
**Component:** pre-bridge.svpstars.com, pre-*.svpstars.com
**Type:** Infra misconfiguration
**Auditor:** Nalreee | Date: 2026-07-23

## Why
Staging/standby subdomains serve apps identical to production (including any future
vulnerability). If a staging app ever connects to a prod-like backend or shares a wallet
session, it becomes an attack surface.

## Impact
Low: no direct exploit observed; expands attack surface + can leak config if staging differs.

## How to check
Compare HTML/JS hashes of `bridge.svpstars.com` vs `pre-bridge.svpstars.com`.

## Fix
Isolate staging (separate backend, non-prod RPC, watermark "STAGING").
