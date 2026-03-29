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
    # stores peer contacts as a JSON file: { username: { pub_b64, verified } }
    # pub_b64 is the base64-encoded raw Ed25519 public key (32 bytes)
    # verified tracks whether the user has confirmed the fingerprint out-of-band

    def __init__(self, path: Path):
        self._path = path
        self._db: dict[str, dict] = {}
         # load existing contacts if the file is there
        if path.exists():
            self._db = json.loads(path.read_text())

    def _save(self):
          # write the full contact book back to disk after any change
        self._path.write_text(json.dumps(self._db, indent=2))

    # Lookup

    def get_pub(self, username: str) -> Ed25519PublicKey | None:
         # return the stored Ed25519 public key for a contact, or None if unknown
        entry = self._db.get(username)
        if entry is None:
            return None
        return Ed25519PublicKey.from_public_bytes(_b64d(entry["pub_b64"]))

    def is_verified(self, username: str) -> bool:
         # True if the user has manually confirmed this contact's fingerprint
        return self._db.get(username, {}).get("verified", False)

    def fingerprint(self, username: str) -> str | None:
        # SHA-256 the raw public key bytes and format as colon-separated hex groups
        # e.g. "3f9a:b182:..." — shown to the user for out-of-band verification
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
        # called every time a peer connects and sends their identity key
        # returns (is_new, key_matches)
        # if is_new: first time seeing this peer, pin the key
        # if not key_matches: key changed unexpectedly — possible MITM, warn user
        if username not in self._db:
            self._db[username] = {"pub_b64": pub_b64, "verified": False}
            self._save()
            return True, True

        matches = self._db[username]["pub_b64"] == pub_b64
        return False, matches

    def mark_verified(self, username: str) -> None:
        # user has confirmed the fingerprint out-of-band, mark the contact trusted
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
        # handle a KEY_ROTATION message from a contact
        # the new key is only accepted if it's signed by the old key
        # this prevents an attacker from hijacking a contact's identity
        old_pub = self.get_pub(username)
        if old_pub is None:
            return False

        # the signed payload is always "KEY_ROTATION|username|new_pub_b64"
        # both sides must construct this string the same way
        payload = f"KEY_ROTATION|{username}|{new_pub_b64}".encode()
        sig     = _b64d(sig_b64)
        if not IdentityKey.verify(old_pub, payload, sig):
            return False

        # keep the verified flag — if the user already trusted this contact
        # they shouldn't need to re-verify just because the key rotated
        verified = self._db[username].get("verified", False)
        self._db[username] = {"pub_b64": new_pub_b64, "verified": verified}
        self._save()
        return True
