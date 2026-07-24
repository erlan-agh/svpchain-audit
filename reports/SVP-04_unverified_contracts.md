# Finding SVP-04 — Lendora / NovaSwap Contracts UNVERIFIED on Explorer (Unauditable $50K Scope)

**Severity:** 🟡 Medium (program gap)
**Component:** Lendora (0xeaDc8D73734DEa581572d812Fa4C26e865c3F8c2), NovaSwap perps
**Type:** Transparency / scope gap
**Auditor:** Nalreee | Date: 2026-07-23

## Why
Both lending (Lendora) and perps (NovaSwap) contracts are **unverified** on the explorer.
EVM storage is empty (Cosmos-EVM bridge; state lives in the x/evm module), so view functions
revert and no storage can be read. The highest-value scope ($50K lending/perps) cannot be
audited from on-chain source.

## Impact
Medium (program gap): a hunter cannot fulfill "Smart Contracts" scope for the most valuable
targets. Either source must be published or a private review environment provided.

## How to check
`curl https://explorer.svpchain.com/api/v2/smart-contracts/0xeaDc8D73734DEa581572d812Fa4C26e865c3F8c2`
→ no verified source; `getCode` returns runtime bytecode only.

## Fix
Verify Lendora/NovaSwap source on explorer, or grant hunters read access to the private repo /
a fork with the contracts.
