"""
Contact book: maps peer username → {identity_pub_b64, verified: bool}.

Trust model: TOFU (trust-on-first-use). On first contact, the user is
prompted to manually verify the fingerprint out-of-band. After that,
the public key is pinned and any mismatch triggers a warning.

Key rotation: a KEY_ROTATION message carries the new key signed by the old
key, so we can verify authenticity before updating the stored key.
"""

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .keys import IdentityKey, _b64e, _b64d


class ContactBook:

    def __init__(self, path: Path):
        self._path = path
        self._db: dict[str, dict] = {}
        if path.exists():
            self._db = json.loads(path.read_text())

    def _save(self):
        self._path.write_text(json.dumps(self._db, indent=2))

    # -- Lookup -------------------------------------------------------------

    def get_pub(self, username: str) -> Ed25519PublicKey | None:
        entry = self._db.get(username)
        if entry is None:
            return None
        return Ed25519PublicKey.from_public_bytes(_b64d(entry["pub_b64"]))

    def is_verified(self, username: str) -> bool:
        return self._db.get(username, {}).get("verified", False)

    def fingerprint(self, username: str) -> str | None:
        pub_b64 = self._db.get(username, {}).get("pub_b64")
        if pub_b64 is None:
            return None
        raw = _b64d(pub_b64)
        import hashlib
        digest = hashlib.sha256(raw).hexdigest()
        # format as groups of 4 for readability
        return ":".join(digest[i:i+4] for i in range(0, len(digest), 4))

    # -- Add / update -------------------------------------------------------

    def add_or_check(self, username: str, pub_b64: str) -> tuple[bool, bool]:
        """
        Returns (is_new, key_matches).
        Caller should warn user if not is_new and not key_matches.
        """
        if username not in self._db:
            self._db[username] = {"pub_b64": pub_b64, "verified": False}
            self._save()
            return True, True

        matches = self._db[username]["pub_b64"] == pub_b64
        return False, matches

    def mark_verified(self, username: str) -> None:
        if username in self._db:
            self._db[username]["verified"] = True
            self._save()

    def rotate_key(
        self,
        username: str,
        new_pub_b64: str,
        sig_b64: str,
    ) -> bool:
        """
        Accept a key rotation if the new key announcement is signed by the
        old key. Returns True on success.
        """
        old_pub = self.get_pub(username)
        if old_pub is None:
            return False

        payload = f"KEY_ROTATION|{username}|{new_pub_b64}".encode()
        sig     = _b64d(sig_b64)
        if not IdentityKey.verify(old_pub, payload, sig):
            return False

        # Preserve verification status — user already verified this contact
        verified = self._db[username].get("verified", False)
        self._db[username] = {"pub_b64": new_pub_b64, "verified": verified}
        self._save()
        return True
