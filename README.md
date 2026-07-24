# SVP Chain — Authorized Security Audit

> **By Nalreee** — authorized testnet + mainnet bug-bounty hunt against SVP Chain public surface
> (repos `svpchain/evm`, `svpchain/oracle`, `svpchain-mcp`, `svpchain-agent`, bridge UIs,
> SVPBridge / Lendora / oracle contracts, and the `svpchain-agent` MCP server).
> Tooling: superagent-bugbounty v7.1 — full 6-phase hunt (scope → recon → analyze → verify → exploit → report).

---

## Current Status (2026-07-24)

- **Testnet 2517:** audited — 11 findings (1 Critical-on-mainnet, 2 Medium, 8 Low/Info). No live Critical/High on testnet (no trading core deployed).
- **Mainnet 2518:** **NOT LIVE**. A watcher alerts on launch; re-test there immediately (trading core = highest-value scope).
- **Reward path:** testnet findings are architectural; **mainnet-impact findings → submit to SVP bounty (#1507572109596164177)**. Wallet: `0x38d77eB4099cebBC676038172005520017a53095`.

---

## All Findings (11)

| ID | Finding | Sev | Surface |
|----|---------|-----|---------|
| SVP-T01 | **Oracle price feeds controlled by single EOA (no multisig)** | 🔴 Critical (mainnet) / 🟡 Med | Contract |
| SVP-T02 | Missing CSP / X-Frame-Options on SVP web | 🟡 Medium | Web |
| SVP-T03 | WSVP9 Solidity 0.6.6 + raw transfer (outdated) | 🟢 Low | Contract |
| SVP-T04 | RPC web3_clientVersion leaks build info | 🟢 Low/Info | Infra |
| SVP-T05 | Faucet operator can claim to arbitrary `user` | 🟢 Low/Info | Contract |
| SVP-01 | CORS `*` on pre-bridge `/api/health` (no data) | 🟢 Info/Low | Web |
| SVP-02 | SVPBridge sig-loop order-dependent false-negative (DoS) | 🟡 Low/Med | Contract |
| SVP-03 | Undocumented Telegram admin fn in Lendora prod | 🟡 Medium | Contract |
| SVP-04 | Lendora/NovaSwap UNVERIFIED → unauditable $50K scope | 🟡 Medium (gap) | Contract |
| SVP-05 | Staging `pre-*` subdomains serve prod-identical apps | 🟢 Low | Infra |
| SVP-06 | MCP agent auth-gate verified solid (no IDOR) | 🟢 Info (PASS) | Web3/API |

**No Critical/High fund-theft found on testnet.** All core contracts (SVPBridge, OffChainAggregator, FeedRegistry, ReporterRegistry, USDCBank, VanToken, COMP) and the MCP auth gate are well-hardened.

---

## Reports (detailed, per-finding)

`reports/` — each contains: why the bug exists, impact, how to check (reproduce), PoC, fix.
- `SVP-T01_oracle_single_owner.md` — **the Critical-on-mainnet one** + `SVP-T01_dev_draft.txt` (ready-to-send dev report, 3 parts)
- `SVP-T02_missing_security_headers.md` … `SVP-T05_faucet_operator.md` (new testnet findings)
- `SVP-01_cors_health.md` … `SVP-06_mcp_auth_pass.md` (prior findings, consolidated)
- `SVP_TESTNET_FINDINGS.md` — consolidated testnet summary

## PoC / Probes (`poc/`)
- `poc_signature_loop.py` — SVP-02 (bridge sig-loop false-negative)
- `poc_lendora_hidden_fns.py` — SVP-03 (Lendora hidden fn)
- `mcp_auth_probe.py`, `mcp_idor.py`, `exploit_idor.py` — SVP-06 (MCP auth gate, PASS)

## Contract Sources (`contracts/`)
Reverse-engineered / downloaded verified sources: SVPBridge (x2), USDCBank, VanToken, OffChainAggregator, FeedRegistry, ReporterRegistry, ManualPriceOracle, Faucet, WSVP9, ERC1967Proxy.

---

## How to Reproduce (quick)

```bash
# T01 — oracle single-owner (Critical on mainnet)
RPC=https://svp-dataseed1-testnet.svpchain.org
curl -s -X POST $RPC -H 'Content-Type: application/json' \
 -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xfb6C039aE2c14A80af6EAf89dacAdC603e5342E0","data":"0x8da5cb5b"},"latest"],"id":1}'
# -> 0x...5d41dd7fb5dbea6e07321eca896700cc6f02b856  (single EOA, not multisig)

# T04 — RPC version leak
curl -s -X POST https://svp-dataseed1-testnet.svpchain.org -H 'Content-Type: application/json' \
 -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'
```

## Scope Notes
- Mainnet (2518) not live at audit; **watcher alerts on launch → re-test trading core (matching/settlement/margin/custody/staking)**.
- Lendora/NovaSwap unverified (Cosmos-EVM bridge; EVM storage empty). Request source verification to close highest-value scope.
- Authorized-only. No DoS, no high-volume scanning, no private-key cracking. All probes single-request read-only.

**By Nalreee**
