"""
Connection handler.

Each TCP connection (inbound or outbound) runs through:
  1. HELLO / HELLO_ACK  — exchange identity public keys
  2. KEY_EXCHANGE        — exchange ephemeral X25519 keys, derive session key
  3. Application messages (LIST, FILE_REQUEST, FILE_TRANSFER, etc.)

All application messages after step 2 have their payload encrypted with
the session AES-256-GCM key (perfect forward secrecy).
"""

import json
import socket
import threading

from ..crypto.keys     import IdentityKey, SessionKey, encrypt_file, decrypt_file
from ..crypto.integrity import sha256_file, sign_file_meta, verify_file_meta, build_file_listing
from ..crypto.contacts  import ContactBook
from .protocol import (
    MsgType, send_msg, recv_msg,
    hello_payload, hello_ack_payload,
    key_exchange_payload,
    list_response_payload,
    file_request_payload,
    consent_request_payload, consent_response_payload,
    file_transfer_payload,
    key_rotation_payload,
    error_payload,
)

import base64
from pathlib import Path


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


class Connection:
    """
    Wraps a single TCP socket. Can be used as initiator (connect to peer)
    or responder (accepted connection).
    """

    def __init__(
        self,
        sock:        socket.socket,
        own_username: str,
        identity:    IdentityKey,
        contacts:    ContactBook,
        shared_dir:  Path,
        recv_dir:    Path,
        passphrase:  str,
        initiator:   bool,
    ):
        self._sock        = sock
        self._username    = own_username
        self._identity    = identity
        self._contacts    = contacts
        self._shared_dir  = shared_dir
        self._recv_dir    = recv_dir
        self._passphrase  = passphrase
        self._initiator   = initiator
        self._session:    SessionKey | None = None
        self._peer_name:  str | None = None
        self._peer_pub    = None  # Ed25519PublicKey

    # Handshake 

    def handshake(self) -> bool:
        """
        Perform HELLO + KEY_EXCHANGE. Returns True on success.
        Caller should close and discard the connection on False.
        """
        try:
            if self._initiator:
                self._send_hello()
                self._recv_hello_ack()
                self._send_key_exchange()
                self._recv_key_exchange_ack()
            else:
                self._recv_hello()
                self._send_hello_ack()
                self._recv_key_exchange()
                self._send_key_exchange_ack()
        except Exception as e:
            print(f"[conn] Handshake failed: {e}")
            return False
        return True

    def _send_hello(self):
        send_msg(self._sock, MsgType.HELLO, self._username,
                 hello_payload(self._identity.public_b64()))

    def _recv_hello_ack(self):
        msg = recv_msg(self._sock)
        self._process_hello(msg)

    def _recv_hello(self):
        msg = recv_msg(self._sock)
        self._process_hello(msg)

    def _send_hello_ack(self):
        send_msg(self._sock, MsgType.HELLO_ACK, self._username,
                 hello_ack_payload(self._identity.public_b64()))

    def _process_hello(self, msg: dict):
        sender  = msg["sender"]
        pub_b64 = msg["payload"]["identity_pub"]
        is_new, matches = self._contacts.add_or_check(sender, pub_b64)
        if not matches:
            print(f"\n[!] WARNING: Key mismatch for '{sender}'! "
                  "Possible MITM attack. Rejecting connection.")
            raise ValueError("Key mismatch")
        if is_new:
            fp = self._contacts.fingerprint(sender)
            print(f"\n[trust] New peer '{sender}'. Fingerprint: {fp}")
            print("[trust] Verify this out-of-band, then run: /verify <username>")
        self._peer_name = sender
        self._peer_pub  = IdentityKey.pub_from_b64(pub_b64)

    def _send_key_exchange(self):
        self._session = SessionKey()
        send_msg(self._sock, MsgType.KEY_EXCHANGE, self._username,
                 key_exchange_payload(self._session.public_b64()))

    def _recv_key_exchange_ack(self):
        msg = recv_msg(self._sock)
        peer_eph = msg["payload"]["ephemeral_pub"]
        self._session.derive(peer_eph, initiator=True)
        print(f"[conn] Session key derived with {self._peer_name} (PFS active)")

    def _recv_key_exchange(self):
        msg = recv_msg(self._sock)
        peer_eph = msg["payload"]["ephemeral_pub"]
        self._session = SessionKey()
        self._session.derive(peer_eph, initiator=False)

    def _send_key_exchange_ack(self):
        send_msg(self._sock, MsgType.KEY_EXCHANGE_ACK, self._username,
                 key_exchange_payload(self._session.public_b64()))
        print(f"[conn] Session key derived with {self._peer_name} (PFS active)")

    # Encrypted send/recv 

    def _send_encrypted(self, msg_type: str, payload: dict):
        encrypted = self._session.encrypt(json.dumps(payload).encode())
        send_msg(self._sock, msg_type, self._username, {"enc": encrypted})

    def _recv_encrypted(self) -> tuple[str, dict]:
        msg     = recv_msg(self._sock)
        enc     = msg["payload"]["enc"]
        raw     = self._session.decrypt(enc["nonce"], enc["ct"])
        payload = json.loads(raw.decode())
        return msg["type"], payload

    # Application layer 

    def request_file_list(self) -> list[dict] | None:
        """Ask peer for their file listing."""
        self._send_encrypted(MsgType.LIST_REQUEST, {})
        msg_type, payload = self._recv_encrypted()
        if msg_type != MsgType.LIST_RESPONSE:
            print(f"[conn] Unexpected response: {msg_type}")
            return None
        return payload["files"]

    def send_file(self, filename: str) -> bool:
        """
        Push a file to the peer. Sends CONSENT_REQUEST first.
        Returns True if peer accepted and transfer completed.
        """
        filepath = self._shared_dir / filename
        if not filepath.exists():
            print(f"[send] File not found: {filename}")
            return False

        data   = filepath.read_bytes()
        sha256 = sha256_file(data)
        sig    = sign_file_meta(self._identity, filename, sha256)

        self._send_encrypted(MsgType.CONSENT_REQUEST,
                             consent_request_payload(filename, len(data), sha256, sig))

        msg_type, payload = self._recv_encrypted()
        if msg_type != MsgType.CONSENT_RESPONSE or not payload["accepted"]:
            print(f"[send] Peer rejected file transfer for '{filename}'")
            return False

        # Encrypt file with session key
        enc = self._session.encrypt(data)
        self._send_encrypted(MsgType.FILE_TRANSFER,
                             file_transfer_payload(filename, enc["nonce"], enc["ct"], sha256, sig))
        print(f"[send] Sent '{filename}' to {self._peer_name}")
        return True

    def request_file(self, filename: str, peer_pub=None) -> bool:
        """
        Request a file by name. If peer_pub is provided it is the original
        owner's public key (for offline fallback verification).
        Returns True on success.
        """
        self._send_encrypted(MsgType.FILE_REQUEST,
                             file_request_payload(filename))

        # Peer may send CONSENT_REQUEST first (they want our consent to send)
        msg_type, payload = self._recv_encrypted()

        if msg_type == MsgType.ERROR:
            print(f"[req] Error from peer: {payload['message']}")
            return False

        if msg_type == MsgType.FILE_TRANSFER:
            return self._handle_file_transfer(payload, peer_pub)

        print(f"[req] Unexpected response type: {msg_type}")
        return False

    def _handle_file_transfer(self, payload: dict, expected_pub=None) -> bool:
        filename = payload["filename"]
        sha256   = payload["sha256"]
        sig      = payload["sig"]
        nonce    = payload["nonce"]
        ct       = payload["ct"]

        # Decrypt
        try:
            data = self._session.decrypt(nonce, ct)
        except Exception:
            print(f"[recv] Decryption failed for '{filename}'")
            return False

        # Integrity check
        if sha256_file(data) != sha256:
            print(f"[recv] INTEGRITY FAILURE: hash mismatch for '{filename}'")
            return False

        # Signature verification (use original owner's key if provided)
        verify_pub = expected_pub or self._peer_pub
        if not verify_file_meta(verify_pub, filename, sha256, sig):
            print(f"[recv] SIGNATURE FAILURE: '{filename}' may have been tampered with")
            return False

        # Store encrypted on disk
        encrypted = encrypt_file(data, self._passphrase)
        out = self._recv_dir / (filename + ".enc")
        out.write_bytes(encrypted)
        print(f"[recv] Received and stored '{filename}' (encrypted on disk)")
        return True

    #Handlers (responder side) 

    def handle_incoming(self):
        """
        Loop handling incoming requests after handshake.
        Call this in a thread for inbound connections.
        """
        try:
            while True:
                msg_type, payload = self._recv_encrypted()
                if msg_type == MsgType.LIST_REQUEST:
                    self._handle_list_request()
                elif msg_type == MsgType.FILE_REQUEST:
                    self._handle_file_request(payload)
                elif msg_type == MsgType.CONSENT_REQUEST:
                    self._handle_consent_request(payload)
                elif msg_type == MsgType.KEY_ROTATION:
                    self._handle_key_rotation(payload)
                else:
                    self._send_encrypted(MsgType.ERROR,
                                         error_payload(f"Unknown message type: {msg_type}"))
        except (ConnectionError, json.JSONDecodeError):
            print(f"[conn] Connection closed with {self._peer_name}")

    def _handle_list_request(self):
        entries = build_file_listing(self._identity, self._shared_dir)
        self._send_encrypted(MsgType.LIST_RESPONSE,
                             list_response_payload(entries))

    def _handle_file_request(self, payload: dict):
        filename = payload["filename"]
        filepath = self._shared_dir / filename
        if not filepath.exists():
            self._send_encrypted(MsgType.ERROR,
                                 error_payload(f"File not found: {filename}"))
            return
        data   = filepath.read_bytes()
        sha256 = sha256_file(data)
        sig    = sign_file_meta(self._identity, filename, sha256)
        enc    = self._session.encrypt(data)
        self._send_encrypted(MsgType.FILE_TRANSFER,
                             file_transfer_payload(filename, enc["nonce"], enc["ct"], sha256, sig))

    def _handle_consent_request(self, payload: dict):
        filename = payload["filename"]
        size_kb  = payload["size"] // 1024
        print(f"\n[consent] '{self._peer_name}' wants to send '{filename}' ({size_kb} KB)")
        answer = input("Accept? [y/N] ").strip().lower()
        accepted = answer == "y"
        self._send_encrypted(MsgType.CONSENT_RESPONSE,
                             consent_response_payload(accepted, filename))
        if accepted:
            msg_type, transfer_payload = self._recv_encrypted()
            if msg_type == MsgType.FILE_TRANSFER:
                self._handle_file_transfer(transfer_payload)

    def _handle_key_rotation(self, payload: dict):
        new_pub = payload["new_pub"]
        sig     = payload["sig"]
        if self._contacts.rotate_key(self._peer_name, new_pub, sig):
            print(f"[trust] Key rotation accepted for '{self._peer_name}'")
            self._peer_pub = IdentityKey.pub_from_b64(new_pub)
        else:
            print(f"[!] Key rotation REJECTED for '{self._peer_name}' — invalid signature")

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass
