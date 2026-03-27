# CISC 468 — P2P Secure File Sharing: Python Client

## Setup

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Running

```bash
python -m p2p_client --username alice --port 55000
```

Two terminals on the same machine (or two machines on the same LAN) will discover each other automatically via mDNS.

### Commands

| Command | Description |
|---|---|
| `/peers` | List discovered peers |
| `/list <peer>` | Browse files a peer is sharing |
| `/get <peer> <file>` | Download a file from a peer |
| `/send <peer> <file>` | Push a file to a peer (they must consent) |
| `/shared` | Show your shared files |
| `/received` | Show files you've received (stored encrypted) |
| `/export <file> <path>` | Decrypt a received file and save it |
| `/share <path>` | Add a local file to your shared folder |
| `/verify <peer>` | Confirm a peer's fingerprint out-of-band |
| `/rotate` | Rotate your identity key and notify online peers |
| `/quit` | Exit |

## Testing

```bash
pytest p2p_client/tests/ -v
```

Tests cover all 11 spec requirements without needing two live processes.

## Testing with the C Client

Once your partner has the C client running:

1. Both clients must be on the **same LAN** (or same machine).
2. Start Python client: `python -m p2p_client --username alice`
3. Start C client with a different username on a different port.
4. Run `/peers` — the C client should appear automatically via mDNS.
5. Run `/list <c-peer>` to fetch their file listing.
6. Run `/get <c-peer> <filename>` to download a file.

### Integration test checklist (run together once both clients work)

| # | Test | Pass condition |
|---|---|---|
| 1 | Peer discovery | `/peers` on each client shows the other |
| 2 | File listing (Python → C) | `/list <c-peer>` returns C's shared files |
| 3 | File listing (C → Python) | C's list command returns Python's shared files |
| 4 | File transfer pull (both directions) | `/get <peer> <file>` works both ways |
| 5 | File transfer push + consent accept | `/send <peer> <file>`, accept on receiver — file arrives |
| 6 | Consent rejection | `/send <peer> <file>`, reject — graceful error message shown |
| 7 | Tamper detection | Flip a byte in a received `.enc` file, try `/export` — client rejects it |
| 8 | Key mismatch rejection | Edit `contacts.json` with wrong key for peer — connection refused |
| 9 | Key rotation | Run `/rotate` on Python — C client accepts new key |
| 10 | Offline fallback | Share file from Python, shut Python down, retrieve from a third instance |

### What your C partner needs to implement

Give them this document. The wire protocol is:

**Framing:** 4-byte big-endian unsigned int length prefix + UTF-8 JSON body.

**Message envelope:**
```json
{
  "type":    "MSG_TYPE",
  "sender":  "username",
  "payload": { "enc": { "nonce": "<base64>", "ct": "<base64>" } }
}
```

All application payloads (after KEY_EXCHANGE) are AES-256-GCM encrypted and
base64-encoded in the `enc` field.

**Handshake sequence (initiator side):**
1. Send `HELLO` with `{"identity_pub": "<Ed25519 pub, base64 raw>"}` — **unencrypted**
2. Receive `HELLO_ACK` — **unencrypted**
3. Send `KEY_EXCHANGE` with `{"ephemeral_pub": "<X25519 pub, base64 raw>"}` — **unencrypted**
4. Receive `KEY_EXCHANGE_ACK`
5. Derive session key: ECDH(own X25519 priv, peer X25519 pub) → HKDF-SHA256 with info=`"initiator-to-responder"` → 32-byte AES-256-GCM key

**Message types:** `HELLO`, `HELLO_ACK`, `KEY_EXCHANGE`, `KEY_EXCHANGE_ACK`, `LIST_REQUEST`, `LIST_RESPONSE`, `FILE_REQUEST`, `FILE_TRANSFER`, `CONSENT_REQUEST`, `CONSENT_RESPONSE`, `KEY_ROTATION`, `ERROR`

**Recommended C libraries:**
- `libsodium` — Ed25519, X25519, AES-256-GCM, HKDF all in one (`crypto_sign_*`, `crypto_box_*`, `crypto_kdf_hkdf_sha256_*`)
- `avahi` — mDNS on Linux; `mDNSResponder` on macOS (service type: `_p2pshare._tcp.local.`)
- `cJSON` — lightweight JSON parsing/serialization

## File Structure

```
python/
├── p2p_client/
│   ├── __main__.py          # CLI entry point
│   ├── crypto/
│   │   ├── keys.py          # Ed25519 identity, X25519 session, AES-GCM, Argon2id
│   │   ├── integrity.py     # SHA-256 hashing, file signing/verification
│   │   └── contacts.py      # Contact book, TOFU trust, key rotation
│   ├── network/
│   │   ├── protocol.py      # Wire protocol, framing, message types
│   │   ├── discovery.py     # mDNS peer discovery (zeroconf)
│   │   ├── server.py        # TCP server, inbound connection threading
│   │   └── connection.py    # Per-connection handshake and message dispatch
│   ├── storage/
│   │   └── store.py         # Encrypted local file storage management
│   └── tests/
│       └── test_client.py   # pytest suite
└── requirements.txt
```

## Security Design

| Requirement | Implementation |
|---|---|
| Peer discovery | mDNS via `zeroconf` (`_p2pshare._tcp.local.`) |
| Mutual authentication | Ed25519 identity keys, TOFU model, fingerprint verification |
| File confidentiality + integrity | AES-256-GCM encryption, SHA-256 hash, Ed25519 signature |
| Perfect forward secrecy | Ephemeral X25519 per connection, HKDF-SHA256 key derivation |
| Offline peer file verification | SHA-256 + original owner's Ed25519 signature travel with file |
| Key rotation | New key signed by old key, broadcast to online contacts |
| Local encrypted storage | Argon2id (passphrase) + AES-256-GCM, 16-byte random salt |
