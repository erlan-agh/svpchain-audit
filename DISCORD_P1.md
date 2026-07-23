🛡️ **SVP Chain — Authorized Audit (Testnet) — Full Submission [1/3]**
**By Nalreee** | Repo + all PoC: github.com/erlan-agh/svpchain-audit
Scope: svpchain/evm, oracle, mcp, agent, bridge UIs, SVPBridge, Lendora, MCP server.
✅ **No Critical/High fund-theft.** Code well-audited. Findings = Medium/Low/Info.

**#1 CORS `*` on pre-bridge API — Info/Low**
`/api/health`,`/api/chains`,`/api/bridge/paths` return `Access-Control-Allow-Origin: *` (no creds). Body is `{"result":"ok"}` / chain metadata — no sensitive data. Fix: scope CORS to allowlist.
Repro: `curl -i https://pre-bridge.svpstars.com/api/health` → see `Access-Control-Allow-Origin: *`

**#2 SVPBridge sig-loop order-dependent false-negative — Low/Med**
`SVPBridge.sol` (~L898–918) advances `sigIdx` ONLY on match, so mis-ordered sigs can fail quorum despite >2/3 power present → legit withdrawals rejected (liveness/DoS). Dup sig does NOT double-count → **no fund loss**.
Repro: `python3 poc_signature_loop.py` → "WRONG order [V1,V0] (80%)" → quorum=False (bug).
Fix: sort sigs or map signer→power. PoC: `poc_signature_loop.py`.

➡️ lanjut Part 2/3
