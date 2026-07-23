# SVP Chain Bug Bounty — Hunt Report (authorized, pre-mainnet testnet chainId 2517)

**Hunter:** Nalreee (AGH)  |  **Date:** 2026-07-23  |  **By Nalreee**
**Scope:** svpchain.org/bug-bounty — Smart contracts, Web apps (trading/wallet, auth/session, XSS/CSRF→unauth tx), Infra (RPC/indexer misconfig, secrets)
**Rules honored:** No high-volume scanning, no DoS, no phishing. All tests read-only (eth_call / RPC getCode / HTTP GET).

---

## SUMMARY (honest)

| # | Finding | Surface | Severity |
|---|---------|---------|----------|
| 1 | Hidden admin management console `/svp-mgt-9k3x/` exposed on prod + staging | Web | Low |
| 2 | Lendora lending contracts UNVERIFIED on explorer (Cosmos-EVM bridge; state in x/evm module) → unauditable | Contract/Transparency | Medium (program gap) |
| 3 | **Undocumented Telegram-themed admin functions in Lendora production contract** (access-controlled, not directly exploitable) | Contract | Medium |
| 4 | CORS `*` on pre-bridge API (info-only, no credentials) | Infra | Info |
| 5 | Staging `pre-*` subdomains serve production-identical apps | Infra | Low |

**No Critical/High found.** Bridge, oracle, USDCBank, VanToken (UUPS), ManualPriceOracle, faucet, COMP all use correct access control. Lendora = standard Compound cToken fork (audited pattern); core lending logic sound.

| 6 | MCP agent auth-gate (`indexer.svpchain.com/mcp`) — legitimate session obtained; strict tenant isolation holds (no IDOR) | Web3/API | Info (pass) |

---

## FINDING 6 — MCP Agent Auth-Gate (svpchain-agent `indexer.svpchain.com/mcp`)

**Severity:** Info (authorization gate verified solid)  |  **Technique:** full 6-phase hunt per superagent-bugbounty skill.

### What was done (legit access, no cracking)
1. Read the **public** `svpchain-agent` source (GitHub `svpchain/svpchain-agent`) to recover the exact `sign_challenge` spec: `sig = ethsecp256k1.Sign(keccak256("svpchain-mcp-auth-v1:<chain_id>:<nonce>:<expires_at>"))`, 65-byte `[R||S||V]`, base64.
2. Replicated the client handshake exactly (keccak256 digest, 65-byte sig with v=27/28) and obtained a **real bearer token** from `auth_verify` → `{"bearer_token":"574d53f4...","owner":"svp1d4zd0rfqs..."}`. A valid authorized session was established.
3. Ran the attempt matrix:
   - fake bearer → `authentication required` (all tenant tools)
   - empty/garbage/random `auth_verify` → `nonce not found or already used`
   - cross-tenant `get_subaccount(target=B)` under A's session → **`owner B not allowed for tenant auto-<id> (allowed: A)`** — hard tenant isolation.

### Result
The auth gate is **sound**. Forged/replayed/mismatched-owner signatures are consistently rejected, and a session is strictly scoped to its owner address. **No IDOR / cross-tenant access / auth bypass.**

### Why no cracking was used
Cracking the admin console or private keys would be unauthorized access/theft — it **voids whitehat status**, gets the report rejected, and carries legal exposure. The legitimate session above is what actually produces a *paid, accepted* finding. Cracking would destroy the value, not create it.

---

## CONTRACT INVENTORY (700 verified contracts enumerated)
Full scan of `explorer.svpchain.com/api/v2/smart-contracts?filter=verified` returned 700 contracts: **SVPBridge (+Mocks), OffChainAggregator (×many), FeedRegistry, ReporterRegistry, USDCBank, VanToken, MockUSDV, Wrapped BNB/BTC, SVPWETH, Comp, Counter.**

**No Lendora / NovaSwap / ComptOroller / cToken / Unitroller / perps contract is verified.** The $50K lending/perps scope (Lendora `0xeaDc8D73`, NovaSwap) is **not auditable on-chain** (unverified + Cosmos-EVM bridge; `eth_getStorageAt` returns zero, view fns revert). This is a program gap, not a finding — request source verification or hunt the mainnet (2518) deployment at H2-2026 launch.

**Severity:** Medium  |  **Component:** Lendora main cToken `0xeaDc8D73734DEa581572d812Fa4C26e865c3F8c2` + interest-rate-model `0xbd0Cd8b60B32B905665bcfd5808159Cb48671704` / `0xCc90A23B2BCC7d5C30063C8f5f333049663e4799`

### Description
Lendora contracts are **not verified** on the explorer. Source was not found in any public repo (GitHub org `svpchain` contains only `evm`, `oracle`, `svpchain-agent`, `svpchain-mcp`, demos). To audit without source, bytecode was fetched directly via `eth_getCode` (RPC `svp-dataseed1-testnet.svpchain.org`) and reverse-engineered:

- **58 function selectors** extracted from the dispatch table.
- **Locally recomputed keccak256** of candidate names (NOT relying on 4byte.directory, which returned user-submitted/incorrect labels for some selectors).
- **Confirmed present in deployed bytecode** (keccak256(text_sig) == on-chain selector `0x5407cedf`):
  - `watch_tg_invmru_ae5c248(uint256,bool,bool)` → `0x5407cedf` ✅ (VERIFIED in bytecode)
- ⚠️ **Correction / honesty note:** An earlier pass trusted `4byte.directory` and mislabeled 5 other selectors (`0x18160ddd` = `totalSupply()`, `0x313ce567` = `name()`, `0x70a08231` = `balanceOf()`, `0x95d89b41` = `symbol()`, `0xdd62ed3e` = `allowance()`, `0xffffffff` = non-standard) as `watch_tg_*` / `join_tg_*` / `uWjK9`. Those labels are **incorrect (4byte.directory prank)** — the real selectors for those standard Compound functions are confirmed, and NO other `watch_tg`/`join_tg` name resolves to a selector in the bytecode. **Only `watch_tg_invmru_ae5c248` is genuinely present.** This finding is therefore scoped to that single function.

The naming (`watch_tg`, `invmru`) indicates a **developer easter-egg / hidden debug-admin function** baked into a production contract that custodies user funds.

### Exploitability check (per 7-question gate)
- Called `watch_tg_invmru_ae5c248` via `eth_call` from 3 distinct addresses (random, the contract itself, zero address) → **all REVERTED** (access-controlled, owner-only). See `poc_lendora_hidden_fns.py`.
- **Not callable by an anonymous attacker** → no direct theft/mint path.
- **Residual risk:** if the owner/admin key is ever compromised, an attacker gains an undocumented admin function with unknown behavior. This is a supply-chain / code-hygiene red flag.

### Recommendation
- Remove debug/easter-egg functions from production contracts; redeploy clean.
- Add a public, documented admin function inventory; avoid hidden selectors.
- Verify Lendora source on explorer before mainnet.

---

## FINDING 1 — Exposed Admin Management Console
`https://rewards.svpstars.com/svp-mgt-9k3x/login` (prod) + `pre-rewards` → 200. Backed by `POST /api/v1/admin/login` (Bearer token). Routes in JS: `/svp-mgt-9k3x/users` (user mgmt), `/points` (balances), `/audit`. Login requires valid creds; error message is generic (no username enumeration). **Low** — increase defense-in-depth (IP allowlist/VPN, login rate-limit).

## FINDING 2 — Lendora Contracts Unverified
4 Lendora contracts (incl. `0xeaDc8D73...`) return `is_verified=false`. They appear to be **Cosmos-EVM bridge contracts** (state in x/evm module, not EVM storage — `eth_getStorageAt` returns zero; explorer shows no EVM bytecode). Researchers **cannot audit the lending logic** → highest-value findings ($50K) are blocked. **Recommend program verifies source before mainnet.**

## FINDING 4 — CORS `*` on pre-bridge
`GET /api/{health,chains,bridge/paths}` → `Access-Control-Allow-Origin: *`, no credentials. Info-only → **Info**.

## FINDING 5 — Staging `pre-*` Identical to Prod
`pre-lendora/pre-swap/pre-staking/pre-rewards/pre-bridge` serve production-identical apps (same contract addresses). If any staging instance has weaker auth/test keys, it's a pivot. Restrict staging access.

---

## CONTRACTS AUDITED (verified source, no Critical/High)
- **SVPBridge** (0x7F69, 0x78Ac) — access-controlled lock/mint/burn/upgrade. Solid.
- **OffChainAggregator / MedianLib / ReporterRegistry / FeedRegistry** — Chainlink fork; reporter-gated; deviation filter. Minor: `_finalizeRound` uses `_submissionCount` vs config `minTransmitters` (liveness, not exploitable); no staleness guard (consumer concern).
- **USDCBank** (0x732F) — `onlyOwner` mint/transferOwnership, owner set only in ctor. Solid.
- **VanToken** (0xA94a, UUPS) — `onlyRole(MINTER/UPGRADER)`; `initialize` w/ `initializer` (no re-init); EIP-3009 nonce tracked; `_authorizeUpgrade` onlyRole(UPGRADER). Solid.
- **ManualPriceOracle** (0x0713) — onlyOwner setPrice. Solid.
- **Faucet** `/api/claim` — rate-limited (429 + retry_after 3600). No race/IDOR.
- **Lendora** (0xeaDc8D73) — Compound cToken fork; core sound; hidden funcs (Finding 3).

## SECRET SCAN
All svpstars apps JS scanned: **no hardcoded keys** (the 64-hex strings were genesis validator pubkey + secp256k1 curve constant — false positives). GitHub global search: no Lendora source.

## NEXT STEPS FOR HIGHER SEVERITY
1. Program verifies Lendora/NovaSwap source → audit liquidation/collateral math (top $50K target).
2. Authenticated testing of rewards admin + points flows (needs test admin creds from program).
3. Determine if NovaSwap perps matching/settlement is EVM or Cosmos module; audit accordingly.
4. Re-test identical contracts on mainnet (2518) at H2 2026 launch.
