# Finding SVP-T04 — RPC web3_clientVersion Leaks Build Info

**Severity:** 🟢 Low / Info
**Component:** svp-dataseed1-testnet.svpchain.org (testnet RPC)
**Type:** Information disclosure
**Auditor:** Nalreee | Date: 2026-07-24 | Scope: "Infrastructure"

---

## Why the bug exists

The public RPC responds to `web3_clientVersion` with a verbose build string including the
Go toolchain version and (attempted) compile info. Admin/debug/txpool namespaces are correctly
disabled, but version disclosure aids fingerprinting.

## Impact

Low: helps an attacker profile the node (Go version → known CVEs). No direct exploit.

## How to check

```bash
curl -s -X POST https://svp-dataseed1-testnet.svpchain.org \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'
# -> "Version dev () Compiled at  using Go go1.26.1 (amd64)"
```

## Recommendation

Return a generic client version in production, or disable `web3_clientVersion` for public RPC.
