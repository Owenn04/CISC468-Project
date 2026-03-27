"""
File integrity utilities.

SHA-256 hash of raw file bytes, signed by the original owner's Ed25519 key.
This lets peer B verify a file obtained from peer C actually came from peer A.
"""

import hashlib
import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .keys import IdentityKey, _b64e, _b64d


def sha256_file(data: bytes) -> str:
    """Return hex SHA-256 of file bytes."""
    return hashlib.sha256(data).hexdigest()


def sign_file_meta(identity: IdentityKey, filename: str, sha256: str) -> str:
    """
    Sign  "filename|sha256"  with the identity key.
    Returns base64-encoded signature.
    """
    payload = f"{filename}|{sha256}".encode()
    sig     = identity.sign(payload)
    return _b64e(sig)


def verify_file_meta(
    pub: Ed25519PublicKey,
    filename: str,
    sha256: str,
    sig_b64: str,
) -> bool:
    """Verify a file meta signature produced by sign_file_meta."""
    payload = f"{filename}|{sha256}".encode()
    sig     = _b64d(sig_b64)
    return IdentityKey.verify(pub, payload, sig)


def build_file_listing(identity: IdentityKey, shared_dir) -> list[dict]:
    """
    Scan shared_dir for plaintext files and return a signed listing.
    Each entry: {filename, size, sha256, sig}
    """
    from pathlib import Path
    entries = []
    for f in Path(shared_dir).iterdir():
        if not f.is_file():
            continue
        data   = f.read_bytes()
        sha256 = sha256_file(data)
        sig    = sign_file_meta(identity, f.name, sha256)
        entries.append({
            "filename": f.name,
            "size":     len(data),
            "sha256":   sha256,
            "sig":      sig,
        })
    return entries
