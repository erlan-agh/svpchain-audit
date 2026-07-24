# Finding SVP-02 — SVPBridge Validator-Signature Loop: Order-Dependent False-Negative (Liveness/DoS)

**Severity:** 🟡 Low / Medium
**Component:** SVPBridge (withdrawal signature verification loop)
**Type:** Logic / liveness (DoS on valid withdrawals)
**Auditor:** Nalreee | Date: 2026-07-22

## Why
The signature-verification loop over the validator set can mis-order or short-circuit when
validator powers/signatures arrive in a non-sorted sequence, causing a valid quorum to be
reported as failed (false-negative) → legitimate withdrawal never finalizes.

## Impact
Medium: a constructed/edge-case validator ordering could stall a valid withdrawal batch
(liveness DoS) until re-submitted in canonical order. No fund theft, but availability risk.

## How to check
Logic simulation in `poc_signature_loop.py` (reproduces order-dependent false-negative).

## Proof
`poc_signature_loop.py` — run `python3 poc_signature_loop.py`.

## Fix
Sort validator set deterministically before verification; use a quorum threshold over total
power, not positional assumptions.
