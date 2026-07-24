# Finding SVP-T02 — Missing CSP / X-Frame-Options on SVP Web Properties

**Severity:** 🟡 Medium
**Component:** svpchain.org, svpstars.com, lendora/bridge/swap/rewards.svpstars.com
**Type:** Security misconfiguration (clickjacking / unmitigated XSS)
**Auditor:** Nalreee | Date: 2026-07-24 | Scope: "Websites & Applications"

---

## Why the bug exists

The web frontends return only `x-content-type-options: nosniff` (on svpchain.org) and no
security headers at all on the app subdomains. There is **no Content-Security-Policy** and
**no X-Frame-Options**, so any page can be framed by an attacker site.

## Impact

- **Clickjacking:** an attacker iframe can overlay the real app and trick a wallet-connected
  user into signing a malicious transaction.
- If any stored/reflected XSS is later found, the absence of CSP makes it trivially exploitable.
- In-scope per bounty: "XSS / CSRF leading to unauthorized transactions".

## How to check

```bash
for h in https://svpchain.org https://svpstars.com https://lendora.svpstars.com https://bridge.svpstars.com; do
  echo "--- $h ---"
  curl -s -I "$h" | grep -iE "content-security-policy|x-frame-options|x-content-type"
done
# Observed: only svpchain.org returns x-content-type-options: nosniff; no CSP / XFO anywhere.
```

## Recommendation

Add to all SVP web responses:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
```
