"""
vault_core.py  -  Secure Password Manager: core (GUI-independent) engine
Cyber Security Lab (7CS4-22 / 7CIT4-22), SKIT Jaipur  |  Project CSL-G45

Contains everything that matters for security, with no Tkinter dependency so it
can be unit-tested headlessly:

  CryptoVault      master-password protected store (PBKDF2-HMAC-SHA256 -> AES-256-GCM)
  PasswordGenerator CSPRNG password generator with entropy estimate
  AutoLockTimer    inactivity timer (clock is injectable for testing)
  ClipboardGuard   clears a copied secret after a timeout (clipboard is injectable)
  AttemptLimiter   exponential back-off after repeated wrong master passwords
"""

from __future__ import annotations

import base64
import json
import math
import os
import secrets
import string
import time
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__all__ = [
    "CryptoVault", "PasswordGenerator", "AutoLockTimer", "ClipboardGuard",
    "AttemptLimiter", "VaultError", "InvalidTag",
]


class VaultError(Exception):
    """Raised for vault-level problems (locked vault, bad file, weak password)."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# =====================================================================
# 1. CRYPTOGRAPHIC VAULT
# =====================================================================
class CryptoVault:
    """
    On-disk format (JSON):
        version, cipher, kdf, iterations, kdf_salt (b64, 16 bytes),
        verifier {nonce, ciphertext},
        entries  [ {id, nonce, ciphertext}, ... ]

    * Key   = PBKDF2-HMAC-SHA256(master_password, salt, iterations) -> 32 bytes
    * Every blob = AES-256-GCM with its own fresh 96-bit random nonce
    * AAD binds each blob to its role: "verifier" or "entry:<id>", so a blob
      cannot be swapped into another slot without failing authentication.
    * The master password and the key are never written to disk.
    """

    VERSION = "1.1"
    SALT_SIZE = 16            # 128-bit salt
    NONCE_SIZE = 12           # 96-bit GCM nonce (NIST SP 800-38D)
    KEY_SIZE = 32             # AES-256
    DEFAULT_ITERATIONS = 600_000   # OWASP guidance for PBKDF2-HMAC-SHA256
    MIN_MASTER_LENGTH = 12
    VERIFIER_PLAINTEXT = b"SKIT-CSL-G45-VAULT-VERIFIER-v1"
    AAD_VERIFIER = b"skit-pm|verifier"

    def __init__(self, path: str = "secure_vault.json", iterations: int | None = None):
        self.path = path
        self.iterations = iterations or self.DEFAULT_ITERATIONS
        self._key: bytearray | None = None      # bytearray so it can be zeroed
        self._salt: bytes | None = None
        self._entries: list[dict] = []

    # ---------- primitives ----------
    @staticmethod
    def derive_key(master_password: str, salt: bytes, iterations: int) -> bytearray:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=CryptoVault.KEY_SIZE,
                         salt=salt, iterations=iterations)
        return bytearray(kdf.derive(master_password.encode("utf-8")))

    @staticmethod
    def encrypt_blob(key: bytes, plaintext: bytes, aad: bytes) -> dict:
        nonce = os.urandom(CryptoVault.NONCE_SIZE)           # fresh nonce every call
        ct = AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)  # ciphertext || 16-byte tag
        return {"nonce": _b64e(nonce), "ciphertext": _b64e(ct)}

    @staticmethod
    def decrypt_blob(key: bytes, blob: dict, aad: bytes) -> bytes:
        """Raises InvalidTag if key, nonce, ciphertext or AAD is wrong/tampered."""
        return AESGCM(bytes(key)).decrypt(_b64d(blob["nonce"]), _b64d(blob["ciphertext"]), aad)

    @staticmethod
    def _entry_aad(record_id: str) -> bytes:
        return b"skit-pm|entry|" + record_id.encode("ascii")

    # ---------- state ----------
    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def _require_unlocked(self) -> bytes:
        if self._key is None:
            raise VaultError("Vault is locked.")
        return bytes(self._key)

    # ---------- lifecycle ----------
    def create(self, master_password: str) -> None:
        if len(master_password) < self.MIN_MASTER_LENGTH:
            raise VaultError(f"Master password must be at least {self.MIN_MASTER_LENGTH} characters.")
        if self.exists():
            raise VaultError("A vault already exists at this path.")
        self._salt = os.urandom(self.SALT_SIZE)
        self._key = self.derive_key(master_password, self._salt, self.iterations)
        self._entries = []
        self._save()

    def unlock(self, master_password: str) -> bool:
        """True on success, False on wrong password. Raises VaultError on a corrupt file."""
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            salt = _b64d(data["kdf_salt"])
            iterations = int(data["iterations"])
            verifier = data["verifier"]
            entries = list(data.get("entries", []))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise VaultError(f"Vault file is missing or corrupt: {exc}") from exc

        candidate = self.derive_key(master_password, salt, iterations)
        try:
            ok = self.decrypt_blob(candidate, verifier, self.AAD_VERIFIER) == self.VERIFIER_PLAINTEXT
        except InvalidTag:
            ok = False
        if not ok:
            self._zero(candidate)
            return False
        self._key, self._salt, self.iterations, self._entries = candidate, salt, iterations, entries
        return True

    def lock(self) -> None:
        """Zero the key buffer and drop the reference."""
        if self._key is not None:
            self._zero(self._key)
        self._key = None
        self._entries = []

    @staticmethod
    def _zero(buf: bytearray) -> None:
        for i in range(len(buf)):
            buf[i] = 0

    # ---------- entries ----------
    def _seal(self, record: dict) -> dict:
        blob = self.encrypt_blob(self._require_unlocked(),
                                 json.dumps(record).encode("utf-8"),
                                 self._entry_aad(record["id"]))
        blob["id"] = record["id"]
        return blob

    def add_entry(self, site: str, username: str, password: str, notes: str = "") -> str:
        self._require_unlocked()
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        record = {"id": secrets.token_hex(8), "site": site, "username": username,
                  "password": password, "notes": notes, "created": now, "updated": now}
        self._entries.append(self._seal(record))
        self._save()
        return record["id"]

    def get_entries(self) -> list[dict]:
        """Decrypt every entry. Raises InvalidTag if any entry was tampered with."""
        key = self._require_unlocked()
        out = []
        for blob in self._entries:
            plain = self.decrypt_blob(key, blob, self._entry_aad(blob["id"]))
            out.append(json.loads(plain.decode("utf-8")))
        return out

    def update_entry(self, record_id: str, site: str, username: str, password: str, notes: str = "") -> bool:
        self._require_unlocked()
        for i, blob in enumerate(self._entries):
            if blob["id"] == record_id:
                old = json.loads(self.decrypt_blob(self._require_unlocked(), blob,
                                                   self._entry_aad(record_id)))
                old.update(site=site, username=username, password=password, notes=notes,
                           updated=time.strftime("%Y-%m-%d %H:%M:%S"))
                self._entries[i] = self._seal(old)        # re-encrypted with a NEW nonce
                self._save()
                return True
        return False

    def delete_entry(self, record_id: str) -> bool:
        self._require_unlocked()
        before = len(self._entries)
        self._entries = [e for e in self._entries if e["id"] != record_id]
        if len(self._entries) != before:
            self._save()
            return True
        return False

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """Re-key the vault: new salt, new key, every entry re-encrypted."""
        key = self._require_unlocked()
        if len(new_password) < self.MIN_MASTER_LENGTH:
            raise VaultError(f"New master password must be at least {self.MIN_MASTER_LENGTH} characters.")
        check = self.derive_key(old_password, self._salt, self.iterations)
        same = secrets.compare_digest(bytes(check), key)
        self._zero(check)
        if not same:
            raise VaultError("Current master password is incorrect.")
        records = self.get_entries()
        new_salt = os.urandom(self.SALT_SIZE)
        new_key = self.derive_key(new_password, new_salt, self.iterations)
        self._zero(self._key)
        self._key, self._salt = new_key, new_salt
        self._entries = [self._seal(r) for r in records]
        self._save()

    # ---------- persistence ----------
    def _save(self) -> None:
        key = self._require_unlocked()
        doc = {
            "version": self.VERSION, "cipher": "AES-256-GCM", "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": self.iterations, "kdf_salt": _b64e(self._salt),
            "verifier": self.encrypt_blob(key, self.VERIFIER_PLAINTEXT, self.AAD_VERIFIER),
            "entries": self._entries,
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, 0o600)          # owner-only where the OS supports it
        except OSError:
            pass
        os.replace(tmp, self.path)        # atomic: no half-written vault on crash


# =====================================================================
# 2. PASSWORD GENERATOR
# =====================================================================
class PasswordGenerator:
    UPPER, LOWER, DIGITS = string.ascii_uppercase, string.ascii_lowercase, string.digits
    SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"
    AMBIGUOUS = set("O0oIl1|")

    @classmethod
    def generate(cls, length: int = 16, upper: bool = True, lower: bool = True,
                 digits: bool = True, symbols: bool = True,
                 avoid_ambiguous: bool = False) -> tuple[str, float]:
        """Return (password, estimated_entropy_bits). Uses `secrets` (OS CSPRNG)."""
        if not 8 <= length <= 128:
            raise ValueError("Length must be between 8 and 128.")
        pools = []
        for enabled, chars in ((upper, cls.UPPER), (lower, cls.LOWER),
                               (digits, cls.DIGITS), (symbols, cls.SYMBOLS)):
            if enabled:
                if avoid_ambiguous:
                    chars = "".join(c for c in chars if c not in cls.AMBIGUOUS)
                pools.append(chars)
        if not pools:
            raise ValueError("Select at least one character set.")
        alphabet = "".join(pools)
        chars = [secrets.choice(p) for p in pools]                       # one from each class
        chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
        secrets.SystemRandom().shuffle(chars)                            # CSPRNG shuffle
        return "".join(chars), cls.entropy_bits(length, len(alphabet))

    @staticmethod
    def entropy_bits(length: int, pool_size: int) -> float:
        """E = L * log2(R). Slight over-estimate because one char per class is forced."""
        return round(length * math.log2(pool_size), 2)

    @staticmethod
    def strength_label(bits: float) -> str:
        if bits < 50:
            return "Weak"
        if bits < 80:
            return "Fair"
        if bits < 110:
            return "Strong"
        return "Very strong"

    @classmethod
    def estimate_text_entropy(cls, text: str) -> float:
        """Rough pool-size estimate for a user-typed password (upper bound)."""
        pool = 0
        if any(c in cls.LOWER for c in text): pool += 26
        if any(c in cls.UPPER for c in text): pool += 26
        if any(c in cls.DIGITS for c in text): pool += 10
        if any(c in cls.SYMBOLS for c in text): pool += len(cls.SYMBOLS)
        if any(c not in cls.LOWER + cls.UPPER + cls.DIGITS + cls.SYMBOLS for c in text): pool += 20
        return round(len(text) * math.log2(pool), 2) if pool and text else 0.0


# =====================================================================
# 3. ENDPOINT-HYGIENE HELPERS (pure logic -> testable without a GUI)
# =====================================================================
class AutoLockTimer:
    def __init__(self, timeout_seconds: float, clock: Callable[[], float] = time.monotonic):
        self.timeout, self._clock = timeout_seconds, clock
        self._last = clock()

    def touch(self) -> None:
        self._last = self._clock()

    def remaining(self) -> int:
        return max(0, math.ceil(self.timeout - (self._clock() - self._last)))

    def expired(self) -> bool:
        return self.remaining() == 0


class ClipboardGuard:
    """Clears a copied secret after `timeout`, but only if the clipboard still holds it."""

    def __init__(self, timeout_seconds: float, clock: Callable[[], float] = time.monotonic):
        self.timeout, self._clock = timeout_seconds, clock
        self._secret: str | None = None
        self._deadline = 0.0

    @property
    def armed(self) -> bool:
        return self._secret is not None

    def arm(self, secret: str) -> None:
        self._secret, self._deadline = secret, self._clock() + self.timeout

    def remaining(self) -> int:
        return max(0, math.ceil(self._deadline - self._clock())) if self.armed else 0

    def poll(self, read: Callable[[], str], clear: Callable[[], None]) -> bool:
        """Call periodically. Returns True when it actually cleared the clipboard."""
        if self.armed and self._clock() >= self._deadline:
            return self.flush(read, clear)
        return False

    def flush(self, read: Callable[[], str], clear: Callable[[], None]) -> bool:
        cleared = False
        if self.armed:
            if read() == self._secret:      # don't wipe something the user copied since
                clear()
                cleared = True
            self._secret = None
        return cleared


class AttemptLimiter:
    """After 3 wrong master passwords, force a wait: 2,4,8,... seconds (max 60)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock, self.failures, self._blocked_until = clock, 0, 0.0

    def wait_seconds(self) -> int:
        return max(0, math.ceil(self._blocked_until - self._clock()))

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= 3:
            self._blocked_until = self._clock() + min(60, 2 ** (self.failures - 2))

    def reset(self) -> None:
        self.failures, self._blocked_until = 0, 0.0
