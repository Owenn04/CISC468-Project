"""
Wire protocol: 4-byte big-endian length prefix + UTF-8 JSON body.

All binary payloads (keys, signatures, file chunks) are base64-encoded
inside JSON so the protocol is language-agnostic. Java can implement the
same framing trivially.

Message envelope:
{
    "type":    "<MSG_TYPE>",
    "sender":  "<username>",
    "payload": { ... }
}
"""

import json
import struct
import socket

# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------

class MsgType:
    HELLO          = "HELLO"            # identity pub key on connect
    HELLO_ACK      = "HELLO_ACK"        # respond with own identity pub key
    KEY_EXCHANGE   = "KEY_EXCHANGE"     # ephemeral X25519 pub key
    KEY_EXCHANGE_ACK = "KEY_EXCHANGE_ACK"
    LIST_REQUEST   = "LIST_REQUEST"     # ask for available files
    LIST_RESPONSE  = "LIST_RESPONSE"    # signed file listing
    FILE_REQUEST   = "FILE_REQUEST"     # request a specific file
    CONSENT_REQUEST  = "CONSENT_REQUEST"   # incoming push — ask recipient
    CONSENT_RESPONSE = "CONSENT_RESPONSE"  # accept / reject
    FILE_TRANSFER  = "FILE_TRANSFER"    # encrypted file data
    KEY_ROTATION   = "KEY_ROTATION"     # signed new identity key
    ERROR          = "ERROR"            # human-readable error


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

HEADER_FMT  = ">I"   # 4-byte big-endian unsigned int
HEADER_SIZE = 4
MAX_MSG     = 256 * 1024 * 1024  # 256 MB safety limit


def send_msg(sock: socket.socket, msg_type: str, sender: str, payload: dict) -> None:
    """Serialize and send a framed message."""
    envelope = json.dumps({
        "type":    msg_type,
        "sender":  sender,
        "payload": payload,
    }).encode("utf-8")
    header = struct.pack(HEADER_FMT, len(envelope))
    sock.sendall(header + envelope)


def recv_msg(sock: socket.socket) -> dict:
    """Receive and deserialize a framed message. Blocks until complete."""
    header = _recv_exact(sock, HEADER_SIZE)
    length = struct.unpack(HEADER_FMT, header)[0]
    if length > MAX_MSG:
        raise ValueError(f"Message too large: {length} bytes")
    body = _recv_exact(sock, length)
    return json.loads(body.decode("utf-8"))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Payload builders (keep message construction consistent)
# ---------------------------------------------------------------------------

def hello_payload(pub_b64: str) -> dict:
    return {"identity_pub": pub_b64}

def hello_ack_payload(pub_b64: str) -> dict:
    return {"identity_pub": pub_b64}

def key_exchange_payload(ephemeral_pub_b64: str) -> dict:
    return {"ephemeral_pub": ephemeral_pub_b64}

def list_response_payload(entries: list[dict]) -> dict:
    return {"files": entries}

def file_request_payload(filename: str) -> dict:
    return {"filename": filename}

def consent_request_payload(filename: str, size: int, sha256: str, sig: str) -> dict:
    return {"filename": filename, "size": size, "sha256": sha256, "sig": sig}

def consent_response_payload(accepted: bool, filename: str) -> dict:
    return {"accepted": accepted, "filename": filename}

def file_transfer_payload(filename: str, nonce: str, ct: str, sha256: str, sig: str) -> dict:
    return {
        "filename": filename,
        "nonce":    nonce,
        "ct":       ct,
        "sha256":   sha256,
        "sig":      sig,
    }

def key_rotation_payload(new_pub_b64: str, sig_b64: str) -> dict:
    return {"new_pub": new_pub_b64, "sig": sig_b64}

def error_payload(message: str) -> dict:
    return {"message": message}
