# Finding SVP-T05 — Faucet Operator Can Claim to Arbitrary `user`

**Severity:** 🟢 Low / Info
**Component:** Faucet (0x8b52753dCbad46925821F02B7B7d90BAd8804bfE)
**Type:** Access-control design (by-design, but single-operator risk)
**Auditor:** Nalreee | Date: 2026-07-24

---

## Why the bug exists

`Faucet.claim(token, user)` is `onlyOperator` and transfers `amountAllowed` to **any** `user`
address supplied (not restricted to `msg.sender`). This is intended for a faucet bot, but it
means the operator key has undirected send authority over all faucet funds.

```solidity
function claim(address token, address user) external onlyOperator {
    require(user != address(0), "invalid user address");
    ...
    IERC20(token).safeTransfer(user, amount);
```

## Impact

Low: by-design for automation. But if the operator key is compromised, an attacker can drain the
faucet to any address of their choosing (no per-caller rate limit in the contract itself).

## How to check

Source: `Faucet.sol` line 70 `claim(address token, address user) external onlyOperator`.

## Recommendation

- Restrict `user` to `msg.sender` (user claims for themselves), or
- Add on-chain per-address cooldown + cap, and monitor operator key with multisig/hardware wallet.
