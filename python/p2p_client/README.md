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

