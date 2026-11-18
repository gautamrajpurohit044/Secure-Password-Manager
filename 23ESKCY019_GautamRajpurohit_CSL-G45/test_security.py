"""
test_security.py - automated verification of the Secure Password Manager core
Cyber Security Lab (7CS4-22 / 7CIT4-22), SKIT Jaipur  |  Project CSL-G45

Run:  python test_security.py
All attack simulations use dummy data on a temporary vault file.
"""

import base64
import json
import os
import statistics
import sys
import tempfile
import time

from vault_core import (AttemptLimiter, AutoLockTimer, ClipboardGuard, CryptoVault,
                        InvalidTag, PasswordGenerator, VaultError)

MASTER = "Correct-Horse#Battery-2026"
RESULTS = []


def case(tc_id, title):
    def deco(fn):
        def run(tmpdir):
            t0 = time.perf_counter()
            try:
                detail = fn(tmpdir)
                status = "PASS"
            except Exception as exc:                      # noqa: BLE001
                status, detail = "FAIL", f"{type(exc).__name__}: {exc}"
            ms = (time.perf_counter() - t0) * 1000
            RESULTS.append((tc_id, title, status, detail))
            print(f"[{tc_id}] {title:<46} {status}  ({ms:,.0f} ms)")
            print(f"        -> {detail}")
        run.tc_id = tc_id
        return run
    return deco


def new_vault(tmpdir, name):
    path = os.path.join(tmpdir, name)
    v = CryptoVault(path)
    v.create(MASTER)
    return v, path


@case("TC-01", "Vault creation / PBKDF2 key derivation")
def tc01(d):
    t0 = time.perf_counter()
    v, path = new_vault(d, "v1.json")
    ms = (time.perf_counter() - t0) * 1000
    doc = json.load(open(path))
    raw = open(path, "rb").read()
    assert len(base64.b64decode(doc["kdf_salt"])) == 16
    assert doc["iterations"] == 600_000 and doc["cipher"] == "AES-256-GCM"
    assert MASTER.encode() not in raw, "master password leaked to disk"
    return f"salt=16 B, iterations=600000, master password absent from file, create took {ms:.0f} ms"


@case("TC-02", "AES-256-GCM entry round-trip, unique nonces")
def tc02(d):
    v, path = new_vault(d, "v2.json")
    samples = [("erp.skit.ac.in", "23ESKCY019", "S1-demo-pass"), ("github.com", "gautam-demo", "S2-demo-pass"),
               ("aws.amazon.com", "lab-sandbox", "S3-demo-pass")]
    for s in samples:
        v.add_entry(*s, notes="dummy")
    got = v.get_entries()
    assert [(g["site"], g["username"], g["password"]) for g in got] == samples
    raw = open(path, "rb").read()
    assert all(s[2].encode() not in raw and s[0].encode() not in raw for s in samples), "plaintext on disk"
    nonces = [e["nonce"] for e in json.load(open(path))["entries"]]
    assert len(set(nonces)) == 3
    return "3 entries decrypt correctly; 3 distinct 96-bit nonces; no site/username/password in plaintext on disk"


@case("TC-03", "Wrong master password rejected")
def tc03(d):
    v, path = new_vault(d, "v3.json")
    v.lock()
    assert v.unlock("Wrong-Password-123!") is False and not v.is_unlocked
    assert v.unlock(MASTER) is True and v.is_unlocked
    return "wrong password -> False (verifier tag mismatch); correct password -> unlocked"


@case("TC-04", "Ciphertext bit-flip tampering detected")
def tc04(d):
    v, path = new_vault(d, "v4.json")
    v.add_entry("example.com", "user", "pw-for-tamper-test")
    v.lock()
    doc = json.load(open(path))
    ct = bytearray(base64.b64decode(doc["entries"][0]["ciphertext"]))
    ct[3] ^= 0x01                                         # flip ONE bit
    doc["entries"][0]["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    json.dump(doc, open(path, "w"))
    v2 = CryptoVault(path)
    assert v2.unlock(MASTER)
    try:
        v2.get_entries()
    except InvalidTag:
        return "1 flipped bit in an entry -> InvalidTag raised, nothing decrypted"
    raise AssertionError("tampering not detected")


@case("TC-05", "Entry-swap (record substitution) detected via AAD")
def tc05(d):
    v, path = new_vault(d, "v5.json")
    v.add_entry("bank.example", "alice", "pw-A")
    v.add_entry("mail.example", "bob", "pw-B")
    v.lock()
    doc = json.load(open(path))
    a, b = doc["entries"]
    a["nonce"], b["nonce"] = b["nonce"], a["nonce"]
    a["ciphertext"], b["ciphertext"] = b["ciphertext"], a["ciphertext"]   # keep ids, swap bodies
    json.dump(doc, open(path, "w"))
    v2 = CryptoVault(path)
    assert v2.unlock(MASTER)
    try:
        v2.get_entries()
    except InvalidTag:
        return "bodies swapped between two records -> InvalidTag (entry id is bound as AAD)"
    raise AssertionError("swap not detected")


@case("TC-06", "CSPRNG generator: classes, uniqueness, entropy")
def tc06(d):
    seen = set()
    for _ in range(500):
        pw, bits = PasswordGenerator.generate(20)
        assert len(pw) == 20
        assert any(c.isupper() for c in pw) and any(c.islower() for c in pw)
        assert any(c.isdigit() for c in pw) and any(c in PasswordGenerator.SYMBOLS for c in pw)
        seen.add(pw)
    assert len(seen) == 500
    pw, bits = PasswordGenerator.generate(20)
    pool = len(PasswordGenerator.UPPER + PasswordGenerator.LOWER + PasswordGenerator.DIGITS + PasswordGenerator.SYMBOLS)
    return f"500/500 unique, every class present; pool={pool}, 20 chars -> {bits} bits"


@case("TC-07", "Auto-lock timer + key zeroisation")
def tc07(d):
    now = [1000.0]
    t = AutoLockTimer(60, clock=lambda: now[0])
    assert t.remaining() == 60 and not t.expired()
    now[0] += 45
    assert t.remaining() == 15
    t.touch()                                              # activity resets the countdown
    now[0] += 59
    assert not t.expired()
    now[0] += 1
    assert t.expired()
    v, _ = new_vault(d, "v7.json")
    held = v._key                                          # keep a reference to the buffer
    assert any(held)
    v.lock()
    assert not v.is_unlocked and not any(held), "key buffer not zeroed"
    try:
        v.get_entries()
    except VaultError:
        return "60 s countdown, activity resets it; lock() zeroes the 32-byte key buffer and blocks access"
    raise AssertionError("locked vault still readable")


@case("TC-08", "Clipboard auto-clear (15 s) with simulated clipboard")
def tc08(d):
    now, clip = [0.0], {"v": ""}
    g = ClipboardGuard(15, clock=lambda: now[0])
    read, clear = (lambda: clip["v"]), (lambda: clip.update(v=""))
    clip["v"] = "s3cret"; g.arm("s3cret")
    now[0] = 14.0
    assert g.poll(read, clear) is False and clip["v"] == "s3cret"
    now[0] = 15.0
    assert g.poll(read, clear) is True and clip["v"] == ""
    clip["v"] = "s3cret"; g.arm("s3cret"); clip["v"] = "user-copied-something-else"
    now[0] = 40.0
    assert g.poll(read, clear) is False and clip["v"] == "user-copied-something-else"
    return "secret survives 14 s, cleared at 15 s; a newer user clipboard is NOT wiped"


@case("TC-09", "Brute-force throttle after failed unlocks")
def tc09(d):
    now = [0.0]
    lim = AttemptLimiter(clock=lambda: now[0])
    for _ in range(2):
        lim.record_failure()
    assert lim.wait_seconds() == 0
    lim.record_failure()
    w3 = lim.wait_seconds()
    now[0] += w3
    lim.record_failure()
    w4 = lim.wait_seconds()
    assert w3 == 2 and w4 == 4
    lim.reset()
    assert lim.wait_seconds() == 0
    return f"free attempts: 2; 3rd failure waits {w3}s, 4th waits {w4}s, doubling to a 60 s cap"


@case("TC-10", "Change master password re-keys everything")
def tc10(d):
    v, path = new_vault(d, "v10.json")
    v.add_entry("site.example", "u", "p")
    old_salt = json.load(open(path))["kdf_salt"]
    old_nonce = json.load(open(path))["entries"][0]["nonce"]
    try:
        v.change_master_password("not-the-right-one!", "Brand-New-Master#99")
        raise AssertionError("accepted wrong current password")
    except VaultError:
        pass
    v.change_master_password(MASTER, "Brand-New-Master#99")
    doc = json.load(open(path))
    assert doc["kdf_salt"] != old_salt and doc["entries"][0]["nonce"] != old_nonce
    v.lock()
    assert v.unlock(MASTER) is False and v.unlock("Brand-New-Master#99") is True
    assert v.get_entries()[0]["site"] == "site.example"
    return "wrong current pw refused; new salt + new nonces; old password dead, new works, data kept"


@case("TC-11", "Edit entry -> fresh nonce; delete works")
def tc11(d):
    v, path = new_vault(d, "v11.json")
    rid = v.add_entry("a.example", "u", "old")
    n1 = json.load(open(path))["entries"][0]["nonce"]
    assert v.update_entry(rid, "a.example", "u", "new")
    n2 = json.load(open(path))["entries"][0]["nonce"]
    assert n1 != n2 and v.get_entries()[0]["password"] == "new"
    assert v.delete_entry(rid) and v.get_entries() == []
    return "re-encrypted with a new nonce on edit; deletion persists"


@case("TC-12", "Weak master password refused")
def tc12(d):
    try:
        CryptoVault(os.path.join(d, "v12.json")).create("short")
    except VaultError:
        return "password shorter than 12 characters rejected at creation"
    raise AssertionError("weak password accepted")


def main():
    print("=" * 78)
    print(" SECURE PASSWORD MANAGER - SECURITY TEST SUITE  (CSL-G45, 7CS4-22)")
    print("=" * 78)
    with tempfile.TemporaryDirectory() as tmp:
        for fn in (tc01, tc02, tc03, tc04, tc05, tc06, tc07, tc08, tc09, tc10, tc11, tc12):
            fn(tmp)
    passed = sum(1 for r in RESULTS if r[2] == "PASS")
    print("=" * 78)
    print(f" {passed}/{len(RESULTS)} TESTS PASSED")
    print("=" * 78)
    with open("test_results.json", "w") as fh:
        json.dump(RESULTS, fh, indent=1)
    sys.exit(0 if passed == len(RESULTS) else 1)


if __name__ == "__main__":
    main()
