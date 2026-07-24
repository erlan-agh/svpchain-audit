# Finding SVP-03 — Undocumented Telegram-Themed Admin Function in Lendora Prod Contract

**Severity:** 🟡 Medium
**Component:** Lendora production contract (0xeaDc8D73734DEa581572d812Fa4C26e865c3F8c2)
**Type:** Undocumented privileged function (access-controlled)
**Auditor:** Nalreee | Date: 2026-07-23

## Why
Reverse-engineering the Lendora bytecode revealed an undocumented function
`watch_tg_invmru_ae5c248` (Telegram-themed admin hook) not present in any public docs/source.
It is access-controlled (not directly callable by attackers), but its presence + unnamed
privilege is a transparency/audit gap.

## Impact
Medium (program gap): a hidden privileged entry point in a $50K-scope lending contract.
Not directly exploitable without the admin key, but unauditable and unexpected.

## How to check
Bytecode RE: `poc_lendora_hidden_fns.py` confirms 1 hidden fn (access-controlled).

## Proof
`poc_lendora_hidden_fns.py` — run `python3 poc_lendora_hidden_fns.py`.

## Fix
Publish full source/ABI for Lendora; document or remove undocumented admin functions.
