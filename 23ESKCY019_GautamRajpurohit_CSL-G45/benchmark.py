"""benchmark.py - measures PBKDF2 latency and AES-GCM speed on THIS machine."""
import json, math, os, platform, statistics, time
from vault_core import CryptoVault, PasswordGenerator

def median_ms(fn, runs=5):
    xs = []
    for _ in range(runs):
        t = time.perf_counter(); fn(); xs.append((time.perf_counter() - t) * 1000)
    return statistics.median(xs)

salt = os.urandom(16)
kdf = {}
for it in (10_000, 100_000, 300_000, 600_000, 1_000_000):
    kdf[it] = median_ms(lambda it=it: CryptoVault.derive_key("benchmark-password", salt, it))
    print(f"PBKDF2 {it:>9,} iterations: {kdf[it]:8.2f} ms  -> {1000/kdf[it]:6.2f} guesses/s/core")

key = os.urandom(32); blob = b"x" * 256
enc = median_ms(lambda: CryptoVault.encrypt_blob(key, blob, b"aad"), 200) 
b = CryptoVault.encrypt_blob(key, blob, b"aad")
dec = median_ms(lambda: CryptoVault.decrypt_blob(key, b, b"aad"), 200)
print(f"AES-256-GCM encrypt 256 B: {enc:.4f} ms | decrypt: {dec:.4f} ms")
json.dump({"kdf_ms": kdf, "enc_ms": enc, "dec_ms": dec, "python": platform.python_version(),
           "platform": platform.platform(), "cpus": os.cpu_count()}, open("benchmark.json", "w"), indent=1)
