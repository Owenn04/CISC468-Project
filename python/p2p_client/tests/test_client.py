"""
Tests for the P2P Secure File Sharing Client.

Coverage:
  - Req 2:  mutual authentication (key mismatch rejection)
  - Req 3:  file send/receive with consent
  - Req 4:  file listing (no consent)
  - Req 5:  offline peer fallback — tamper detection via signature
  - Req 6:  key rotation
  - Req 7:  confidentiality (AES-GCM) and integrity (SHA-256 + signature)
  - Req 8:  perfect forward secrecy (new ephemeral keys per session)
  - Req 9:  local encrypted storage
  - Req 10: error messages (file not found, tamper, bad passphrase)
"""

import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from p2p_client.crypto.keys     import IdentityKey, SessionKey, encrypt_file, decrypt_file
from p2p_client.crypto.integrity import sha256_file, sign_file_meta, verify_file_meta, build_file_listing
from p2p_client.crypto.contacts  import ContactBook
from p2p_client.network.protocol import (
    MsgType, send_msg, recv_msg,
    hello_payload, hello_ack_payload,
    key_exchange_payload, consent_response_payload,
    file_request_payload, file_transfer_payload,
    error_payload,
)
from p2p_client.network.connection import Connection
from p2p_client.network.server     import Server
from p2p_client.storage.store      import Storage

# Fixtures

PASSPHRASE = "test-passphrase-123"

@pytest.fixture
def tmp(tmp_path):
    return tmp_path

@pytest.fixture
def identity():
    return IdentityKey.generate()

@pytest.fixture
def identity2():
    return IdentityKey.generate()

@pytest.fixture
def contacts(tmp):
    return ContactBook(tmp / "contacts.json")

@pytest.fixture
def contacts2(tmp):
    return ContactBook(tmp / "contacts2.json")

@pytest.fixture
def shared_dir(tmp):
    d = tmp / "shared"
    d.mkdir()
    return d

@pytest.fixture
def recv_dir(tmp):
    d = tmp / "received"
    d.mkdir()
    return d

def _make_connection_pair(
    username_a, identity_a, contacts_a, shared_a, recv_a,
    username_b, identity_b, contacts_b, shared_b, recv_b,
    passphrase=PASSPHRASE,
):
    """
    Create a pair of connected sockets and return (conn_a, conn_b).
    conn_a is initiator, conn_b is responder.
    """
    srv, cli = socket.socketpair()
    conn_a = Connection(
        sock=srv, own_username=username_a, identity=identity_a,
        contacts=contacts_a, shared_dir=shared_a, recv_dir=recv_a,
        passphrase=passphrase, initiator=True,
    )
    conn_b = Connection(
        sock=cli, own_username=username_b, identity=identity_b,
        contacts=contacts_b, shared_dir=shared_b, recv_dir=recv_b,
        passphrase=passphrase, initiator=False,
    )
    return conn_a, conn_b


def _handshake_pair(conn_a, conn_b):
    results = [None, None]
    def do_a(): results[0] = conn_a.handshake()
    def do_b(): results[1] = conn_b.handshake()
    ta = threading.Thread(target=do_a)
    tb = threading.Thread(target=do_b)
    ta.start(); tb.start()
    ta.join(timeout=5); tb.join(timeout=5)
    return results[0], results[1]


# Req 9: Local encrypted storage (AES-256-GCM + Argon2id)

class TestLocalStorage:

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"secret file contents"
        blob = encrypt_file(plaintext, PASSPHRASE)
        assert decrypt_file(blob, PASSPHRASE) == plaintext

    def test_wrong_passphrase_raises(self):
        blob = encrypt_file(b"data", PASSPHRASE)
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_file(blob, "wrong-passphrase")

    def test_tampered_ciphertext_raises(self):
        blob = bytearray(encrypt_file(b"data", PASSPHRASE))
        blob[-1] ^= 0xFF  # flip a bit
        with pytest.raises(ValueError):
            decrypt_file(bytes(blob), PASSPHRASE)

    def test_storage_store_and_retrieve(self, tmp, shared_dir, recv_dir):
        store = Storage(shared_dir, recv_dir, PASSPHRASE)

        # Write encrypted file manually (simulating received transfer)
        filename = "hello.txt"
        data = b"hello world"
        enc = encrypt_file(data, PASSPHRASE)
        (recv_dir / (filename + ".enc")).write_bytes(enc)

        assert filename in store.list_received()
        assert store.read_received(filename) == data

    def test_export_received(self, tmp, shared_dir, recv_dir):
        store = Storage(shared_dir, recv_dir, PASSPHRASE)
        data = b"export me"
        enc = encrypt_file(data, PASSPHRASE)
        (recv_dir / "export.txt.enc").write_bytes(enc)

        dest = tmp / "out.txt"
        store.export_received("export.txt", dest)
        assert dest.read_bytes() == data


# Req 7: File integrity — SHA-256 + Ed25519 signature

class TestIntegrity:

    def test_sha256_consistent(self):
        data = b"test data"
        assert sha256_file(data) == sha256_file(data)
        assert sha256_file(data) != sha256_file(b"other data")

    def test_sign_and_verify(self, identity):
        data = b"file bytes"
        sha  = sha256_file(data)
        sig  = sign_file_meta(identity, "file.txt", sha)
        pub  = IdentityKey.pub_from_b64(identity.public_b64())
        assert verify_file_meta(pub, "file.txt", sha, sig)

    def test_verify_fails_tampered_hash(self, identity):
        data = b"file bytes"
        sha  = sha256_file(data)
        sig  = sign_file_meta(identity, "file.txt", sha)
        pub  = IdentityKey.pub_from_b64(identity.public_b64())
        assert not verify_file_meta(pub, "file.txt", "deadbeef" * 8, sig)

    def test_verify_fails_wrong_key(self, identity, identity2):
        data = b"file bytes"
        sha  = sha256_file(data)
        sig  = sign_file_meta(identity, "file.txt", sha)
        pub2 = IdentityKey.pub_from_b64(identity2.public_b64())
        assert not verify_file_meta(pub2, "file.txt", sha, sig)

    def test_build_file_listing(self, tmp, identity, shared_dir):
        (shared_dir / "a.txt").write_bytes(b"aaa")
        (shared_dir / "b.txt").write_bytes(b"bbb")
        listing = build_file_listing(identity, shared_dir)
        assert len(listing) == 2
        names = {e["filename"] for e in listing}
        assert names == {"a.txt", "b.txt"}
        pub = IdentityKey.pub_from_b64(identity.public_b64())
        for e in listing:
            assert verify_file_meta(pub, e["filename"], e["sha256"], e["sig"])


# Req 8: Perfect forward secrecy — new ephemeral keys per session

class TestPFS:

    def test_different_session_keys_each_time(self):
        """Two separate session key exchanges should produce different keys."""
        alice1 = SessionKey()
        bob1   = SessionKey()
        alice1.derive(bob1.public_b64(), initiator=True)
        bob1.derive(alice1.public_b64(), initiator=False)

        alice2 = SessionKey()
        bob2   = SessionKey()
        alice2.derive(bob2.public_b64(), initiator=True)
        bob2.derive(alice2.public_b64(), initiator=False)

        # Encrypt same plaintext with both sessions
        pt = b"test"
        enc1 = alice1.encrypt(pt)
        enc2 = alice2.encrypt(pt)
        # Ciphertexts should differ (different keys + random nonces)
        assert enc1["ct"] != enc2["ct"]

    def test_session_encrypt_decrypt(self):
        alice = SessionKey()
        bob   = SessionKey()
        alice.derive(bob.public_b64(), initiator=True)
        bob.derive(alice.public_b64(), initiator=False)

        pt  = b"hello bob"
        enc = alice.encrypt(pt)
        assert bob.decrypt(enc["nonce"], enc["ct"]) == pt

    def test_session_not_derived_raises(self):
        session = SessionKey()
        with pytest.raises(RuntimeError):
            session.encrypt(b"data")


# Req 2: Mutual authentication — TOFU + key mismatch rejection

class TestAuthentication:

    def test_tofu_first_contact(self, tmp, identity, identity2, shared_dir, recv_dir):
        contacts_a = ContactBook(tmp / "ca.json")
        contacts_b = ContactBook(tmp / "cb.json")
        shared_b   = tmp / "sb"; shared_b.mkdir()
        recv_b     = tmp / "rb"; recv_b.mkdir()

        conn_a, conn_b = _make_connection_pair(
            "alice", identity,  contacts_a, shared_dir, recv_dir,
            "bob",   identity2, contacts_b, shared_b,   recv_b,
        )
        ok_a, ok_b = _handshake_pair(conn_a, conn_b)
        assert ok_a and ok_b
        # Both should have stored each other's keys
        assert contacts_a.get_pub("bob") is not None
        assert contacts_b.get_pub("alice") is not None
        conn_a.close(); conn_b.close()

    def test_key_mismatch_rejected(self, tmp, identity, identity2, shared_dir, recv_dir):
        """If bob's stored key doesn't match what he sends, connection is rejected."""
        contacts_a = ContactBook(tmp / "ca.json")
        contacts_b = ContactBook(tmp / "cb.json")
        shared_b   = tmp / "sb"; shared_b.mkdir()
        recv_b     = tmp / "rb"; recv_b.mkdir()

        # Pre-populate alice's contacts with a DIFFERENT key for bob
        imposter = IdentityKey.generate()
        contacts_a.add_or_check("bob", imposter.public_b64())

        conn_a, conn_b = _make_connection_pair(
            "alice", identity,  contacts_a, shared_dir, recv_dir,
            "bob",   identity2, contacts_b, shared_b,   recv_b,
        )
        ok_a, ok_b = _handshake_pair(conn_a, conn_b)
        # Alice should reject (key mismatch)
        assert not ok_a
        conn_a.close(); conn_b.close()


# Req 6: Key rotation

class TestKeyRotation:

    def test_valid_rotation_accepted(self, tmp):
        contacts = ContactBook(tmp / "contacts.json")
        old_key  = IdentityKey.generate()
        new_key  = IdentityKey.generate()
        username = "alice"

        contacts.add_or_check(username, old_key.public_b64())

        new_pub  = new_key.public_b64()
        payload  = f"KEY_ROTATION|{username}|{new_pub}".encode()
        sig      = old_key.sign(payload)
        import base64
        sig_b64  = base64.b64encode(sig).decode()

        assert contacts.rotate_key(username, new_pub, sig_b64)
        stored = contacts.get_pub(username)
        assert stored.public_bytes_raw() == new_key.public_bytes()

    def test_invalid_rotation_rejected(self, tmp):
        contacts  = ContactBook(tmp / "contacts.json")
        old_key   = IdentityKey.generate()
        new_key   = IdentityKey.generate()
        attacker  = IdentityKey.generate()
        username  = "alice"

        contacts.add_or_check(username, old_key.public_b64())
        new_pub  = new_key.public_b64()
        payload  = f"KEY_ROTATION|{username}|{new_pub}".encode()
        # Sign with attacker key — should be rejected
        sig      = attacker.sign(payload)
        import base64
        sig_b64  = base64.b64encode(sig).decode()

        assert not contacts.rotate_key(username, new_pub, sig_b64)
        # Old key should still be stored
        stored = contacts.get_pub(username)
        assert stored.public_bytes_raw() == old_key.public_bytes()


# Req 5: Offline peer fallback — signature verifies original owner

class TestOfflineFallback:

    def test_original_signature_verifies_via_third_party(self, identity):
        """
        Peer A signs file. Peer B gets it from Peer C.
        B can verify with A's public key, not C's.
        """
        data   = b"important file"
        sha    = sha256_file(data)
        sig    = sign_file_meta(identity, "file.txt", sha)
        pub_a  = IdentityKey.pub_from_b64(identity.public_b64())

        # Simulate C sending the same file (sha + sig unchanged)
        assert verify_file_meta(pub_a, "file.txt", sha, sig)

    def test_tampered_file_detected(self, identity):
        data      = b"important file"
        sha_orig  = sha256_file(data)
        sig       = sign_file_meta(identity, "file.txt", sha_orig)
        pub_a     = IdentityKey.pub_from_b64(identity.public_b64())

        tampered_data = b"important FILE"  # content changed
        sha_tampered  = sha256_file(tampered_data)

        # Hash mismatch reveals tamper even before checking signature
        assert sha_tampered != sha_orig
        # Signature won't verify against tampered hash
        assert not verify_file_meta(pub_a, "file.txt", sha_tampered, sig)


# Req 4 + 3: File listing and transfer over real sockets (integration)

class TestIntegration:

    def _setup_peers(self, tmp):
        identity_a = IdentityKey.generate()
        identity_b = IdentityKey.generate()
        contacts_a = ContactBook(tmp / "ca.json")
        contacts_b = ContactBook(tmp / "cb.json")
        shared_a   = tmp / "sa"; shared_a.mkdir()
        shared_b   = tmp / "sb"; shared_b.mkdir()
        recv_a     = tmp / "ra"; recv_a.mkdir()
        recv_b     = tmp / "rb"; recv_b.mkdir()
        return (identity_a, contacts_a, shared_a, recv_a,
                identity_b, contacts_b, shared_b, recv_b)

    def test_list_files(self, tmp):
        (ia, ca, sa, ra, ib, cb, sb, rb) = self._setup_peers(tmp)
        (sb / "hello.txt").write_bytes(b"hi there")

        conn_a, conn_b = _make_connection_pair(
            "alice", ia, ca, sa, ra,
            "bob",   ib, cb, sb, rb,
        )

        results = [None]
        def alice():
            conn_a.handshake()
            results[0] = conn_a.request_file_list()
            conn_a.close()

        def bob():
            conn_b.handshake()
            conn_b.handle_incoming()

        tb = threading.Thread(target=bob, daemon=True)
        tb.start()
        time.sleep(0.05)
        alice()

        assert results[0] is not None
        assert any(f["filename"] == "hello.txt" for f in results[0])

    def test_file_transfer(self, tmp):
        (ia, ca, sa, ra, ib, cb, sb, rb) = self._setup_peers(tmp)
        file_data = b"secret content"
        (sb / "secret.txt").write_bytes(file_data)

        conn_a, conn_b = _make_connection_pair(
            "alice", ia, ca, sa, ra,
            "bob",   ib, cb, sb, rb,
        )

        success = [False]
        def alice():
            conn_a.handshake()
            success[0] = conn_a.request_file("secret.txt")
            conn_a.close()

        def bob():
            conn_b.handshake()
            conn_b.handle_incoming()

        tb = threading.Thread(target=bob, daemon=True)
        tb.start()
        time.sleep(0.05)
        alice()

        assert success[0]
        enc_file = ra / "secret.txt.enc"
        assert enc_file.exists()
        decrypted = decrypt_file(enc_file.read_bytes(), PASSPHRASE)
        assert decrypted == file_data

    def test_file_not_found_error(self, tmp):
        (ia, ca, sa, ra, ib, cb, sb, rb) = self._setup_peers(tmp)
        # Bob has no files shared

        conn_a, conn_b = _make_connection_pair(
            "alice", ia, ca, sa, ra,
            "bob",   ib, cb, sb, rb,
        )

        success = [True]
        def alice():
            conn_a.handshake()
            success[0] = conn_a.request_file("nonexistent.txt")
            conn_a.close()

        def bob():
            conn_b.handshake()
            conn_b.handle_incoming()

        tb = threading.Thread(target=bob, daemon=True)
        tb.start()
        time.sleep(0.05)
        alice()

        assert not success[0]


# Protocol framing

class TestProtocolFraming:

    def test_send_recv_roundtrip(self):
        a, b = socket.socketpair()
        payload = {"key": "value", "num": 42}
        send_msg(a, MsgType.LIST_REQUEST, "alice", payload)
        msg = recv_msg(b)
        assert msg["type"] == MsgType.LIST_REQUEST
        assert msg["sender"] == "alice"
        assert msg["payload"] == payload
        a.close(); b.close()

    def test_large_message(self):
        a, b = socket.socketpair()
        large = {"data": "x" * 100_000}
        send_msg(a, MsgType.FILE_TRANSFER, "alice", large)
        msg = recv_msg(b)
        assert msg["payload"]["data"] == "x" * 100_000
        a.close(); b.close()
