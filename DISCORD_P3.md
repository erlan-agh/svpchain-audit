🛡️ **SVP Chain — Authorized Audit (Testnet) — Full Submission [3/3]**
**By Nalreee**

**#5 Staging `pre-*` = prod-identical — Low**
`pre-lendora/pre-swap/pre-staking/pre-rewards/pre-bridge` serve same apps + contract addrs as prod. Pivot risk if staging has weaker auth/test keys. Fix: restrict staging to VPN/IP allowlist; use separate test contracts.

**#6 MCP agent auth gate — SOLID (pass)**
Replicated handshake from public `svpchain-agent` source: `sig=ethsecp256k1.Sign(keccak256("svpchain-mcp-auth-v1:<chain_id>:<nonce>:<expires_at>"))` 65-byte, base64. Got a **real bearer** from `auth_verify` (legit session). Matrix:
- fake/garbage/random `auth_verify` → `nonce not found or already used`
- tenant tools w/o bearer → `authentication required`
- cross-tenant `get_subaccount(B)` under A → **`owner B not allowed for tenant`**
→ No IDOR / auth bypass. PoC: `mcp_idor.py`, `mcp_auth_probe.py`.

📝 Summary: all findings = hardening/liveness/transparency, NOT theft. No Critical/High withheld. Mainnet (2518) not live — re-scan on launch. Authorized-only (no DoS, no cracking, read-only).
**By Nalreee** — full report + PoC: github.com/erlan-agh/svpchain-audit
