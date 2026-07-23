🛡️ **SVP Chain — Authorized Audit (Testnet) — Full Submission [2/3]**
**By Nalreee**

**#3 Hidden admin fn in Lendora prod — Medium**
Lendora `0xeaDc8D73` unverified; reverse-engineered bytecode via `eth_getCode`. One genuinely-present fn (keccak-verified, NOT trusting 4byte.directory pranks):
`watch_tg_invmru_ae5c248(uint256,bool,bool)` → sel `0x5407cedf` ✅ confirmed.
`eth_call` from random/contract/zero addr all **REVERT** (owner-only) → not attacker-callable. Risk: if owner key compromised, undocumented admin fn reachable.
⚠️ Honesty: initial pass mislabeled 5 other selectors (`watch_tg_*`,`join_tg_*`,`uWjK9`) from 4byte.directory — those are PRANKS (actually `totalSupply`/`name`/`balanceOf`/`symbol`/`allowance`). Only `watch_tg_invmru_ae5c248` is real.
Repro: `python3 poc_lendora_hidden_fns.py`. Fix: remove debug fns, redeploy clean.

**#4 Lendora/NovaSwap UNVERIFIED — Medium (program gap)**
4 Lendora contracts `is_verified=false`; behave as Cosmos-EVM bridge (EVM storage empty, view fns revert). Full scan of 700 verified contracts found NONE Lendora/NovaSwap/Comptroller/perps. $50K lending/perps scope unauditable on-chain.
Repro: `curl "https://explorer.svpchain.com/api/v2/smart-contracts?filter=verified"` (700, none Lendora).
Rec: program verify source before mainnet.

➡️ lanjut Part 3/3
