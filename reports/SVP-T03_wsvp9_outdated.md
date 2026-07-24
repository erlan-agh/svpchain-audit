# Finding SVP-T03 — WSVP9 Uses Solidity 0.6.6 + Raw transfer (Outdated Pattern)

**Severity:** 🟢 Low
**Component:** WSVP9 (0x771a0a63D8198b7dbea4a16910ff68AB38006531) — "Wrapped SVP"
**Type:** Outdated compiler / code-quality
**Auditor:** Nalreee | Date: 2026-07-24

---

## Why the bug exists

`WSVP9.sol` declares `pragma solidity =0.6.6;` and uses raw `msg.sender.transfer(wad)` in
`withdraw()` plus a hand-rolled `transferFrom` without SafeERC20. The checks-effects-interactions
order is correct (`balanceOf -= wad` before transfer), so it is **not directly exploitable**,
but the pattern is 4+ years outdated and deviates from the project's otherwise modern (0.8.x)
contracts.

## Impact

- Low: no direct fund loss. But outdated pragma + non-standard ERC20 increases audit surface and
  future-maintenance / interoperability risk (e.g. with tokens that revert on transfer).
- Inconsistent with the rest of the SVP contract suite (0.8.22+).

## How to check

```bash
curl -s https://explorer.svpchain.com/api/v2/smart-contracts/0x771a0a63D8198b7dbea4a16910ff68AB38006531 \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['source_code'][:200])"
# -> pragma solidity =0.6.6;
```

## Recommendation

Upgrade to `^0.8.x`, use OpenZeppelin `SafeERC20` / `ERC20Wrapper`, and add a reentrancy guard
on `withdraw` for defense-in-depth.
