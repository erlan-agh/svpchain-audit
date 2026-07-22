#!/usr/bin/env python3
"""
PoC — SVPBridge _checkValidatorSignatures order-dependent false-negative.

Replicates the exact loop from SVPBridge.sol lines 898–918:
    for i in range(validators):
        signer = recoverSigner(message, signatures[sigIdx])
        if signer == validators[i]:
            cumPower += powers[i]
            if 3*cumPower > 2*totalPower: break
            sigIdx += 1
            if sigIdx >= nSigs: break

The loop only advances sigIdx on a MATCH. If signatures are submitted in an
order that doesn't align with validators[], the loop mis-aligns and can FAIL
to reach quorum even when >2/3 power is present.

Run:  python3 poc_signature_loop.py
"""
def check_loop_injected(validators, powers, signer_at_slot, total_power):
    nSigs = len(signer_at_slot)
    if nSigs == 0:
        return False, 0
    cumPower = 0
    sigIdx = 0
    end = len(validators)
    for i in range(end):
        signer = signer_at_slot[sigIdx]
        if signer == validators[i]:
            cumPower += powers[i]
            if 3 * cumPower > 2 * totalPower:
                break
            sigIdx += 1
            if sigIdx >= nSigs:
                break
    return (3 * cumPower > 2 * totalPower), cumPower

def main():
    validators = ["V0", "V1", "V2"]
    powers = [40, 40, 20]
    total = 100
    print(f"Validators={validators} powers={powers} total={total} threshold(>2/3)={2*total//3+1}\n")
    scenarios = [
        ("Correct order [V0,V1] (80%)",            ["V0", "V1"],     True),
        ("WRONG order [V1,V0] (80%)",              ["V1", "V0"],     True),
        ("WRONG order + pad [V1,V0,XXX] (80%)",    ["V1", "V0", "X"], True),
        ("1 key only [V0] (40%)",                  ["V0"],           False),
        ("Dup key x3 [V0,V0,V0] (40%)",            ["V0", "V0", "V0"], False),
        ("60% scattered [V0,XXX,V2] (60%)",        ["V0", "X", "V2"], False),
    ]
    fails = 0
    for name, sigs, expected in scenarios:
        ok, cp = check_loop_injected(validators, powers, sigs, total)
        flag = "PASS" if ok else "FAIL"
        bug = "" if ok == expected else "  <-- BUG (mismatch with expected)"
        if ok != expected:
            fails += 1
        print(f"  {name:38} quorum={ok} cum={cp:3} [{flag}]{bug}")
    print(f"\nMis-aligned/rejected-but-should-pass scenarios: {fails}")
    if fails:
        print("  => Confirms order-dependent false-negative (liveness/DoS on legit withdrawals).")
        print("  => Duplicate signature does NOT double-count power (no quorum bypass).")

if __name__ == "__main__":
    main()
