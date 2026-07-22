# SVP Chain — Authorized Security Audit

Authorized testnet bug-bounty hunt against SVP Chain public surface
(repos `svpchain/evm`, `svpchain/oracle`, `svpchain-mcp`, `svpchain-agent`,
bridge UIs, SVPBridge contract logic, MCP remote server).

**Result:** No Critical/High fund-theft path found. Two lower-severity issues:
1. CORS `*` on `/api/health` (no sensitive data leaked) — Info/Low
2. SVPBridge signature-loop order-dependent false-negative (liveness/DoS) — Low/Med

See `FINDINGS.md` for full write-up, live evidence, and dev fixes.
Run `python3 poc_signature_loop.py` to reproduce Finding #2.

Mainnet was not yet deployed at audit time; a watcher alerts on launch.
