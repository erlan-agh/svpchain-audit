# Finding SVP-T01 — Oracle Price Feeds Controlled by Single EOA (No Multisig)

**Severity:** 🔴 Critical (on mainnet if oracles feed trading core) / 🟡 Medium (testnet, architectural risk)
**Component:** `ReporterRegistry` (0xfb6C039aE2c14A80af6EAf89dacAdC603e5342E0), `ManualPriceOracle` (0x0713d943cbcC01fbd582f833fdD7037535A0d002), `OffChainAggregator` (0x070c3783C296806465261963E403EDB0933C7110)
**Type:** Centralization / Access-Control (oracle manipulation)
**Auditor:** Nalreee | Date: 2026-07-24 | Chain: testnet 2517

---

## Why the bug exists (root cause)

The entire price-oracle stack is admin-gated by a **single externally-owned account (EOA)**,
not a multisig or timelock:

- `ReporterRegistry.addReporter / removeReporter / setReporterActive` → `onlyOwner`.
  On-chain `owner()` = `0x5d41dd7fb5dbea6e07321eca896700cc6f02b856` (team EOA).
- `ManualPriceOracle.setPrice(asset, price)` → `onlyOwner`.
  On-chain `owner()` = `0xe78797d30ca777f7ef8dafc5e5b1a03fd53874e0` (team EOA).
- `OffChainAggregator.transmit` → only reporters from `ReporterRegistry` (same single owner).

There is **no multisig, no timelock, no threshold** on price-feed administration.
Whoever controls that one EOA controls every price the chain trusts.

## Impact

If these oracles feed the trading core (matching / settlement / margin / custody) on mainnet:
- Compromise of the owner EOA → **arbitrary price manipulation** →
  bad fills, liquidation theft, minting against inflated collateral = **direct fund theft (Critical)**.
- Even without compromise, a single point of failure contradicts "decentralized AI trading L1"
  security posture and is a program-disqualifying centralization risk.

On testnet 2517 there is no trading core deployed, so the impact is **architectural only**
(no live funds). The risk realizes at mainnet.

## How to check (reproduce)

```bash
RPC=https://svp-dataseed1-testnet.svpchain.org
# ReporterRegistry owner (0x8da5cb5b = owner())
curl -s -X POST $RPC -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xfb6C039aE2c14A80af6EAf89dacAdC603e5342E0","data":"0x8da5cb5b"},"latest"],"id":1}'
# -> 0x0000...5d41dd7fb5dbea6e07321eca896700cc6f02b856  (single EOA)

# ManualPriceOracle owner
curl -s -X POST $RPC -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x0713d943cbcC01fbd582f833fdD7037535A0d002","data":"0x8da5cb5b"},"latest"],"id":1}'
# -> 0x0000...e78797d30ca777f7ef8dafc5e5b1a03fd53874e0  (different single EOA)
```

Source confirm: `ReporterRegistry.sol` line 18 `addReporter ... external onlyOwner`;
`ManualPriceOracle.sol` line 15 `setPrice ... external onlyOwner`.

## Proof of Concept

No exploit needed — the administrative centralization is visible in source + on-chain state.
A malicious/compromised owner could call:
```solidity
reporterRegistry.addReporter(ATTACKER);          // become price reporter
manualPriceOracle.setPrice(SVP, 0);              // or any manipulated price
```
and immediately corrupt every dependent price feed.

## Recommendation

- Move oracle admin (addReporter / setPrice / registry changes) to a **multisig** (e.g. 3-of-5)
  or **timelock** with on-chain notice.
- Prefer **aggregated, attested feeds** over a single manually-set price.
- Add monitoring + alerting on owner changes and anomalous price deltas.

**Verify on mainnet (2518) at launch:** re-run the `owner()` calls above. If still a single EOA
AND oracles feed trading → submit as **Critical** per SVP bounty tiers.
