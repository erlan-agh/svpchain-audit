🛡️ **SVP Chain — Authorized Security Audit (Testnet) — Full Submission**
**By Nalreee** | Repo + all PoC: https://github.com/erlan-agh/svpchain-audit

**Scope:** `svpchain/evm`, `svpchain/oracle`, `svpchain-mcp`, `svpchain-agent`, bridge UIs (`bridge.svpstars.com`, `pre-bridge.svpstars.com`), SVPBridge, Lendora, and the `svpchain-agent` MCP server.
**Authorization:** In-scope per SVP Chain bug-bounty program (testnet, chainId 2517).
**Honest result:** ✅ **No Critical / High fund-theft path found.** Code is well-audited. Findings below are Medium/Low/Info (hardening, liveness, transparency).

---

## 🔸 Finding #1 — CORS `Access-Control-Allow-Origin: *` on pre-bridge API
**Severity:** Info / Low
**Component:** `pre-bridge.svpstars.com` (legacy/standby bridge frontend)

**Description:** `/api/health`, `/api/chains`, `/api/bridge/paths` return `Access-Control-Allow-Origin: *` with no credentials.

**Impact:** Only info-only endpoints are affected (body is `{"result":"ok"}` / chain metadata). No sensitive data, no auth token, no user funds at risk. Low risk, but a minor misconfiguration.

**Steps to reproduce:**
```
curl -i https://pre-bridge.svpstars.com/api/health
# observe: Access-Control-Allow-Origin: *
```

**Fix:** Scope CORS to an explicit allowlist or drop the wildcard on non-public endpoints.
**PoC:** `FINDINGS.md` (Finding #1, live curl evidence).

---

## 🔸 Finding #2 — SVPBridge validator-signature loop: order-dependent false-negative
**Severity:** Low / Medium (liveness / DoS, NOT fund loss)
**Component:** `SVPBridge.sol` (mainnet `0x7F69Eb47b61781d61Ff6E399A71f866b2D19314F`)

**Description:** The `_checkValidatorSignatures` loop (lines ~898–918) only advances the signature index `sigIdx` on a **match**:
```
for i in range(validators):
    signer = recoverSigner(msg, signatures[sigIdx])
    if signer == validators[i]:
        cumPower += powers[i]
        if 3*cumPower > 2*totalPower: break
        sigIdx += 1
        if sigIdx >= nSigs: break
```
If signatures are submitted in an order that doesn't align with `validators[]`, the loop mis-aligns and can **fail to reach quorum even when >2/3 voting power is present**.

**Impact:** A legit withdrawal with sufficient validator power can be **rejected** (liveness/DoS on the bridge). **No double-counting** — a duplicate signature does NOT inflate power, so **no fund-theft / false-quorum path**.

**Steps to reproduce:**
```
python3 poc_signature_loop.py
# Scenario "WRONG order [V1,V0] (80%)" → quorum=False (should be True) → BUG confirmed
```

**Fix:** Require signatures sorted by validator index, or map `signer → power` instead of positional matching.
**PoC:** `poc_signature_loop.py` in repo.

---

## 🔸 Finding #3 — Undocumented hidden admin function in Lendora production contract
**Severity:** Medium (code-hygiene / supply-chain risk, access-controlled)
**Component:** Lendora main cToken `0xeaDc8D73734DEa581572d812Fa4C26e865c3F8c2`

**Description:** Lendora contracts are **unverified** on the explorer. Source is not in any public repo. To audit without source, bytecode was pulled via `eth_getCode` and reverse-engineered. One function-name string is genuinely present in deployed bytecode (verified by locally recomputing keccak256 — **not** trusting 4byte.directory, which returned prank labels for standard Compound selectors):
- `watch_tg_invmru_ae5c248(uint256,bool,bool)` → selector `0x5407cedf` ✅ **confirmed in bytecode**

**Impact:** The naming (`watch_tg`, `invmru`) indicates a **developer easter-egg / hidden debug-admin function** baked into a production contract that custodies user funds. It is **not callable by an anonymous attacker** — `eth_call` from random / contract / zero address all **REVERT** (owner-only). Residual risk: if the owner/admin key is ever compromised, an attacker gains an undocumented admin function with unknown behavior.
> ⚠️ **Honesty note:** An initial pass mislabeled 5 other selectors (`watch_tg_*`, `join_tg_*`, `uWjK9`) from 4byte.directory as hidden functions. Those are **pranks** — they are actually standard Compound functions (`totalSupply`, `name`, `balanceOf`, `symbol`, `allowance`). Only `watch_tg_invmru_ae5c248` is real.

**Steps to reproduce:**
```
python3 poc_lendora_hidden_fns.py
# → confirms 0x5407cedf dispatched + REVERTS for non-owner
```

**Fix:** Remove debug/easter-egg functions from production contracts; redeploy clean. Verify Lendora source on explorer before mainnet.
**PoC:** `poc_lendora_hidden_fns.py` in repo.

---

## 🔸 Finding #4 — Lendora / NovaSwap contracts UNVERIFIED (unauditable $50K scope)
**Severity:** Medium (program gap, not a code bug)
**Component:** All Lendora lending + NovaSwap perps contracts

**Description:** 4 Lendora contracts (incl. `0xeaDc8D73`) return `is_verified=false`. They behave as **Cosmos-EVM bridge contracts** (state lives in the x/evm module, not EVM storage — `eth_getStorageAt` returns zero; explorer shows no EVM bytecode; view functions revert). A full scan of all 700 verified contracts on the explorer found **no Lendora / NovaSwap / Comptroller / cToken / Unitroller / perps contract verified**.

**Impact:** The highest-value bounty scope ($50K lending/perps logic) is **currently impossible to audit on-chain**. This is a transparency gap, not an exploit — but it blocks legitimate researchers from reviewing the fund-custody code.

**Steps to reproduce:**
```
curl "https://explorer.svpchain.com/api/v2/smart-contracts?filter=verified"  # 700 contracts, none Lendora/NovaSwap
curl "https://explorer.svpchain.com/api/v2/smart-contracts/0xeaDc8D73734DEa581572d812Fa4C26e865c3F8c2"  # is_verified: false
```

**Recommendation:** Program should verify Lendora/NovaSwap source on the explorer (or provide a private repo) before mainnet so the lending/perps logic can be reviewed.

---

## 🔸 Finding #5 — Staging `pre-*` subdomains serve production-identical apps
**Severity:** Low
**Component:** `pre-lendora`, `pre-swap`, `pre-staking`, `pre-rewards`, `pre-bridge`

**Description:** These staging hosts serve the **same applications and contract addresses** as production.

**Impact:** If any staging instance has weaker auth, test keys, or relaxed rate-limiting, it becomes a **pivot point** into production-equivalent logic. No direct exposure found, but defense-in-depth gap.

**Steps to reproduce:** Compare `pre-lendora.svpstars.com` vs `lendora.svpstars.com` — identical bundle + same contract addresses.

**Fix:** Restrict staging to VPN/IP allowlist; use separate test contracts/keys.

---

## 🔸 Finding #6 — `svpchain-agent` MCP auth gate: SOLID (pass)
**Severity:** Info (authorization gate verified sound)
**Component:** `indexer.svpchain.com/mcp` (svpchain-agent)

**Description:** Replicated the client handshake from the public `svpchain-agent` source: `sig = ethsecp256k1.Sign(keccak256("svpchain-mcp-auth-v1:<chain_id>:<nonce>:<expires_at>"))`, 65-byte `[R||S||V]`, base64. Obtained a **real bearer token** from `auth_verify` (legitimate authorized session). Then ran the attempt matrix:
- fake/garbage/random `auth_verify` → `nonce not found or already used`
- all tenant tools without bearer → `authentication required`
- cross-tenant `get_subaccount(target=B)` under A's session → **`owner B not allowed for tenant auto-<id> (allowed: A)`**

**Impact:** Forged / replayed / mismatched-owner signatures are consistently rejected; a session is strictly scoped to its owner address. **No IDOR / cross-tenant access / auth bypass.**

**Steps to reproduce:**
```
python3 mcp_idor.py   # legit session + cross-tenant rejection
# or mcp_auth_probe.py for the full forged/fake/empty matrix
```

**PoC:** `mcp_idor.py`, `mcp_auth_probe.py` in repo.

---

## 📝 Summary
- All findings are **hardening / liveness / transparency**, **not theft**. No Critical/High withheld.
- Mainnet (`chainId 2518`) was not live at audit time; a watcher re-scans on launch (higher bounty value there).
- Authorized-only: no DoS, no high-volume scanning, no private-key cracking. All probes are single-request read-only.

**By Nalreee** — full report + PoC: https://github.com/erlan-agh/svpchain-audit
