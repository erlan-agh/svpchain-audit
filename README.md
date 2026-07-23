# SVP Chain — Authorized Security Audit

> **By Nalreee** — authorized testnet + mainnet bug-bounty hunt against SVP Chain public surface
> (repos `svpchain/evm`, `svpchain/oracle`, `svpchain-mcp`, `svpchain-agent`,
> bridge UIs, SVPBridge / Lendora / oracle contracts, and the `svpchain-agent` MCP server).
> Tooling: superagent-bugbounty v7.1 — full 6-phase hunt (scope → recon → analyze → verify → exploit → report).

---

## Result (honest)

**No Critical / High fund-theft path found.** All core contracts (SVPBridge, OffChainAggregator,
FeedRegistry, ReporterRegistry, USDCBank, VanToken, COMP) and the `svpchain-agent` MCP auth gate
are well-hardened. Lower-severity issues + unauditable-scope gaps are documented below.

| # | Finding | Severity | Surface |
|---|---------|----------|---------|
| 1 | CORS `*` on `/api/health` (no sensitive data) | Info / Low | Web |
| 2 | SVPBridge signature-loop order-dependent false-negative (liveness/DoS) | Low / Med | Contract |
| 3 | **Undocumented Telegram-themed admin function in Lendora prod contract** (`watch_tg_invmru_ae5c248`, access-controlled) | Medium | Contract |
| 4 | Lendora / NovaSwap contracts UNVERIFIED on explorer → unauditable $50K scope | Medium (program gap) | Contract |
| 5 | Staging `pre-*` subdomains serve production-identical apps | Low | Infra |
| 6 | MCP agent auth gate — legit session obtained, strict tenant isolation holds (no IDOR) | Info (pass) | Web3/API |

---

## Reports

- **[`SVP_BUG_REPORT.md`](SVP_BUG_REPORT.md)** — *Master consolidated report* (all 6 findings, Lendora bytecode reverse-engineering, MCP auth-gate evidence, 700-contract inventory). **Start here.**
- **[`FINDINGS.md`](FINDINGS.md)** — Detailed write-ups + live evidence for Findings #1 & #2 (CORS, signature-loop PoC).
- **[`SVPBRIDGE_MAINNET_AUDIT.md`](SVPBRIDGE_MAINNET_AUDIT.md)** — SVPBridge mainnet source audit (Low/Info only, well-hardened).

## PoC / Probes

- `poc_signature_loop.py` — reproduces Finding #2 (signature-loop order-dependent false-negative). Run: `python3 poc_signature_loop.py`
- `exploit_idor.py` — authorized MCP cross-tenant / IDOR attempt matrix (result: gate holds).
- `mcp_auth_probe.py` — *(from superagent-bugbounty skill)* live MCP auth-gate probe: obtains a legit session, then tests forged/fake/cross-tenant access. Run with the operator venv that has `eth_account`, `cryptography`, `eth_keys`, `eth_utils`, `bech32`.

---

## Scope notes

- Mainnet (`chainId 2518`) was not live at first audit; a watcher alerts on launch. Re-test there at H2-2026.
- Lendora (`0xeaDc8D73734DEa581572d812Fa4C26e865c3F8c2`) and NovaSwap perps are **unverified** (Cosmos-EVM bridge; EVM storage empty, view fns revert). Request source verification from the program to close the highest-value scope.
- Authorized-only. No DoS, no high-volume scanning, no private-key cracking. All probes are single-request read-only.

**By Nalreee**
