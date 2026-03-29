"""
Identity and session key management.

Identity: Ed25519 keypair (signing/verification)
Session:  X25519 ephemeral keypair per connection (PFS via ECDH + HKDF)
"""

import os
import json
import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import argon2.low_level as argon2ll



# Helpers
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _b64d(s: str) -> bytes:
    return base64.b64decode(s)

class IdentityKey:
    """Long-term Ed25519 signing key for a peer."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._priv = private_key
        self._pub  = private_key.public_key()

    @classmethod
    def generate(cls) -> "IdentityKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: Path, passphrase: bytes) -> "IdentityKey":
        """Load a passphrase-encrypted PEM private key from disk."""
        pem = path.read_bytes()
        priv = serialization.load_pem_private_key(pem, password=passphrase)
        return cls(priv)

    def save(self, path: Path, passphrase: bytes) -> None:
        """Encrypt and save private key to disk as PEM."""
        pem = self._priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )
        path.write_bytes(pem)

    # Public key export

    def public_bytes(self) -> bytes:
        return self._pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def public_b64(self) -> str:
        return _b64e(self.public_bytes())

    @staticmethod
    def pub_from_b64(s: str) -> Ed25519PublicKey:
        raw = _b64d(s)
        return Ed25519PublicKey.from_public_bytes(raw)

    # Sign / verify

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)

    @staticmethod
    def verify(pub: Ed25519PublicKey, data: bytes, sig: bytes) -> bool:
        try:
            pub.verify(sig, data)
            return True
        except InvalidSignature:
            return False


# Session key exchange (X25519 ECDH → HKDF → AES-256-GCM)

class SessionKey:
    """
    Ephemeral X25519 keypair for one connection.
    After ECDH with the peer's ephemeral public key, derive a 256-bit AES key
    via HKDF-SHA256.
    """

    def __init__(self):
        self._priv = X25519PrivateKey.generate()
        self._pub  = self._priv.public_key()
        self._send_aes: AESGCM | None = None
        self._recv_aes: AESGCM | None = None

    def public_b64(self) -> str:
        raw = self._pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return _b64e(raw)

    def derive(self, peer_pub_b64: str, initiator: bool) -> None:
        """
        Run ECDH and derive shared AES-256-GCM key.
        `initiator` flag ensures both sides feed the same info string to HKDF.
        """
        peer_raw = _b64d(peer_pub_b64)
        peer_pub = X25519PublicKey.from_public_bytes(peer_raw)
        shared   = self._priv.exchange(peer_pub)

        if initiator:
            send_info = b"initiator-to-responder"
            recv_info = b"responder-to-initiator"
        else:
            send_info = b"responder-to-initiator"
            recv_info = b"initiator-to-responder"

        send_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=send_info,
        ).derive(shared)

        recv_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=recv_info,
        ).derive(shared)

        self._send_aes = AESGCM(send_key)
        self._recv_aes = AESGCM(recv_key)

    # Encrypt / decrypt 

    def encrypt(self, plaintext: bytes) -> dict:
        """Returns {"nonce": b64, "ct": b64}"""
        if self._send_aes is None:
            raise RuntimeError("Session key not derived yet")
        nonce = os.urandom(12)
        ct    = self._send_aes.encrypt(nonce, plaintext, None)
        return {"nonce": _b64e(nonce), "ct": _b64e(ct)}

    def decrypt(self, nonce_b64: str, ct_b64: str) -> bytes:
        if self._recv_aes is None:
            raise RuntimeError("Session key not derived yet")
        nonce = _b64d(nonce_b64)
        ct    = _b64d(ct_b64)
        return self._recv_aes.decrypt(nonce, ct, None)


# File encryption (local storage — Argon2id + AES-256-GCM)


def derive_storage_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a passphrase using Argon2id."""
    return argon2ll.hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=argon2ll.Type.ID,
    )

def encrypt_file(plaintext: bytes, passphrase: str) -> bytes:
    """
    Returns bytes: salt(16) + nonce(12) + ciphertext
    """
    salt  = os.urandom(16)
    key   = derive_storage_key(passphrase, salt)
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ct

def decrypt_file(data: bytes, passphrase: str) -> bytes:
    """Inverse of encrypt_file. Raises ValueError on bad passphrase/tamper."""
    salt, nonce, ct = data[:16], data[16:28], data[28:]
    key = derive_storage_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Decryption failed — wrong passphrase or file tampered")