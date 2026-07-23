# SVPBridge Mainnet — Source Audit (Authorized, Read-Only)

**Date:** 2026-07-22
**Auditor:** Hermes (on behalf of @erlan_agh, authorized hunter)
**Target:** `SVPBridge` @ `0x7F69Eb47b61781d61Ff6E399A71f866b2D19314F` (SVP Chain mainnet, chainId 2517)
**Source:** Verified on explorer.svpchain.com (Blockscout), compiler v0.8.24, optimized 200 runs
**Scope:** Full source (1004 lines SVPBridge.sol + Signature.sol + OZ deps)

## Executive Summary
The SVPBridge contract is **well-engineered and defense-in-depth**. No Critical/High
findings. The validator-multisig withdrawal model, nonce scheme, and KYC gating are
correctly implemented. Two **Low/Info** observations are noted for hardening.

## Architecture (as built)
- **Deposit:** `deposit()` / `depositNative()` custody funds under a `DepositOrder`
  in `Pending`, emit `PreDeposit`. A `kyacOperator` later calls `processKYAC(orderId)`
  → `Approved` (emits real `Deposit`) or `Rejected` (refundable).
- **Withdrawal:** backend collects hot-validator quorum sigs → `batchedRequestWithdrawals`
  (checks source-chain whitelist + inbound token pair + 2/3 power). After dispute period,
  a `finalizer` calls `batchedFinalizeWithdrawals` → `_transferOut`.
- **Governance:** all route/token/validator changes require **cold-key** quorum sigs
  (`coldValidatorSetHash`). Inbound+outbound pair whitelists bound the blast radius of a
  hot-key compromise.

## Findings

### Finding 1 — CORS `*` on pre-bridge API (INFO / LOW)  [WEB, not contract]
- **Location:** `https://pre-bridge.svpstars.com/api/*` (`/api/health`, `/api/bridge/paths`,
  `/api/chains` all return `Access-Control-Allow-Origin: *`).
- **Impact:** Any website can read bridge config (chain IDs, bridge contract addresses,
  token routes) from a victim's browser. No auth/sensitive PII is exposed via these
  read-only endpoints, so impact is **low** (info disclosure of public config only).
- **Notable:** The **production** bridge frontend (`bridge.svpstars.com`) is hardcoded to
  point at `https://pre-bridge.svpstars.com` (see `HV="https://pre-bridge.svpstars.com"`
  in the shipped JS bundle). This means prod UI talks to a **staging** API. Should be
  switched to a production API endpoint before mainnet traffic scales.
- **Recommendation:** Set `ACAO` to the specific origin(s); point prod frontend at prod API.

### Finding 2 — Quorum liveness edge (INFO)
- **Code:** `_checkValidatorSignatures` requires `3 * cumPower > 2 * totalValidatorPower`.
  With 4 equal-power validators (observed on-chain: `nValidators` and equal powers), this
  needs **3/4** signers — correct (Byzantine fault tolerance for n=4, f=1). If validator
  powers are ever set **unevenly** such that no subset cleanly clears `2/3`, withdrawals
  could stall. This is a config concern, not a code bug.
- **Recommendation:** Document that validator powers must be chosen so a clear 2/3 supermajority
  is always achievable; monitor `totalValidatorPower` vs per-validator power.

## Checks Performed (No Issue)
| Check | Result |
|-------|--------|
| Reentrancy (deposit/withdraw/refund) | Safe — `nonReentrant` + checks-effects-interactions |
| Double-spend refund | Safe — `OrderStatus` one-way guard (Pending→Approved/Rejected→Refunded) |
| Withdrawal replay | Safe — `usedMessages` + `finalizedWithdrawals` + `requestedWithdrawals[message].requestedTime != 0` |
| Validator sig forgery | Safe — EIP-712 `recoverSigner`, domain separator bound to `block.chainid` + verifying contract; `vsHash` checkpoint match enforced |
| Cross-chain replay | Safe — `sourceChainId` + `sourceToken` + `targetToken` folded into message hash |
| Cold-key governance bypass | Safe — all sensitive ops require `coldValidatorSetHash` quorum |
| KYC bypass | Safe — `processKYAC` gated to `kyacOperators[msg.sender]` (cold-governed) |
| Emergency pause | Safe — locker multisig `voteEmergencyLock` + cold `emergencyUnlock` |
| Native transfer | Safe — `.call{value}` with `require(sent)`; `nonReentrant` wraps finalize |
| Self-transfer / zero addr | Safe — `destination != address(0)`, `targetChainId != self` |

## Note on chainId
The explorer RPC (`explorer.svpchain.com/api/eth-rpc`) returns `eth_chainId = 0x539`
(1337). This is the default Anvil/dev chainId. If mainnet is intended to be a distinct
production network, confirm the deployed chainId matches the published spec (the bridge
source uses `block.chainid` only for the EIP-712 domain — a dev chainId in production
would weaken domain separation if testnet shares validator keys). **Verify with the SVP
team** whether 1337 is intentional for this deployment.

## Submission
- Severity: **Low / Info only**. No Critical/High withheld.
- Channel: Discord `#1507572109596164177`.
- Recommend the two hardening items above as defensive improvements.
