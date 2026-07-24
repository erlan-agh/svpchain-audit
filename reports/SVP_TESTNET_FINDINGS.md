# SVP Chain — Testnet (2517) Security Findings — by Nalreee

Tested: 2026-07-24 | Scope: SVP Bug Bounty (contracts, web apps, infra)
Method: Static RE of 51 verified contracts + web/infra probe. No mainnet (not live).
Note: findings below are testnet-observable. Reward eligibility per program = mainnet impact.

## 🔴 F1 — Oracle price feeds controlled by single EOA (no multisig) [Critical on mainnet]
- ReporterRegistry (0xfb6C...): addReporter/removeReporter onlyOwner → owner = 0x5d41... (team EOA)
- ManualPriceOracle (0x0713...): setPrice onlyOwner → owner = 0xe787... (team EOA)
- OffChainAggregator: reporters gated by ReporterRegistry (same owner).
Impact: If these oracles feed the trading core (matching/settlement/margin) on mainnet,
compromise of the owner EOA = arbitrary price manipulation = fund theft (Critical).
Recommendation: migrate oracle admin to multisig / timelock; use aggregated feeds, not manual.
Verify on mainnet: re-check owner; if still EOA → submit as Critical.

## 🟡 F2 — Missing CSP / X-Frame-Options on SVP web properties [Medium]
- svpchain.org: only `x-content-type-options: nosniff`. No CSP, no X-Frame-Options.
- svpstars.com / lendora / bridge / swap / rewards: no security headers.
Impact: clickjacking; unmitigated if any XSS exists. Scope: "Websites & Applications".
Fix: add CSP (block inline), X-Frame-Options: DENY.

## 🟢 F3 — WSVP9 uses Solidity 0.6.6 + raw transfer (not SafeERC20) [Low]
- 0x771a... Wrapped SVP, pragma 0.6.6, `transfer`/withdraw use raw `.transfer`, no reentrancy guard
  (checks-effects-interactions is correct, so not exploitable, but outdated pattern).
Fix: upgrade to modern pragma + SafeERC20.

## 🟢 F4 — RPC web3_clientVersion leaks build info [Low/Info]
- svp-dataseed1-testnet returns Go version + build flags via web3_clientVersion.
Fix: suppress verbose version in production RPC.

## 🟢 F5 — Faucet operator can claim to arbitrary `user` [Low/Info]
- Faucet.claim(token, user) onlyOperator; operator may direct funds to any address.
By-design (faucet bot), but operator key compromise = directed drain.
Fix: restrict claimable user = msg.sender, or log+monitor.

## ✅ Verified SAFE (no issue)
- SVPBridge: double-spend guard (one-way order status), nonReentrant, replay guard (usedMessages),
  validator cold-quorum on all sensitive ops, emergency-lock threshold governance.
- USDCBank: mint onlyOwner, burn own only.
- VanToken: roles (MINTER/PAUSER/UPGRADER/FREEZER/BLACKLIST) + EIP-3009 sig verify + nonce used.
- OffChainAggregator: reporter-gated transmit, median aggregation.
- No tx.origin / delegatecall / selfdestruct / assembly / ecrecover misuse across all contracts.

## Not yet auditable (absent on testnet)
- Matching / Settlement / Margin / Custody / Staking contracts (trading core) — deploy on mainnet.
- Mainnet 2518 chain — not live. Hunt these on mainnet launch.

By Nalreee
