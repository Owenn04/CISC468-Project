# CISC 468 — P2P Secure File Sharing (C Client)

## Overview

This is the C implementation of a secure peer-to-peer (P2P) file sharing system.

It is fully interoperable with the Python reference client and follows the same protocol, handshake flow, and encryption scheme.

The system supports secure file transfer, authenticated connections, and encrypted messaging over TCP with automatic peer discovery via mDNS.

---

## Build

```bash
gcc -o p2p_client \
src/main.c \
src/network/connection.c \
src/network/protocol.c \
src/network/server.c \
src/crypto/crypto.c \
src/network/discovery.c \
src/storage/storage.c \
-Iinclude \
-lsodium -lcrypto -lcjson -lavahi-client -lavahi-common -lpthread
```

---

## Running

```bash
./p2p_client <username> <port>
```

Example:

```bash
./p2p_client alice 5000
```

Run multiple instances (or use another machine on the same LAN) and peers will be discovered automatically via mDNS.

---

## Commands

| Command | Description |
|--------|-------------|
| `/peers` | List discovered peers |
| `/list <peer>` | View files shared by a peer |
| `/get <peer> <file>` | Download a file |
| `/shared` | Show your shared files |
| `/received` | Show received files |
| `/export <file> <path>` | Decrypt and export a file |
| `/share <path>` | Add a file to your shared folder |
| `/verify <peer>` | Verify peer fingerprint (local, out-of-band) |
| `/rotate` | Rotate identity key and notify peers |
| `/quit` | Exit client |

---

## Testing

The C client includes a custom test suite to validate core functionality.

### Build tests

```bash
gcc -o run_tests \
tests/run_tests.c \
tests/test_utils.c \
tests/test_crypto.c \
tests/test_protocol.c \
tests/test_connection.c \
src/network/connection.c \
src/network/protocol.c \
src/crypto/crypto.c \
-Iinclude \
-lsodium -lcjson -lcrypto -lpthread
```

### Run tests

```bash
./run_tests
```

### Test coverage

- AES-256-GCM encryption and decryption  
- Tamper detection  
- Protocol message construction and framing  
- Handshake correctness  
- Session key agreement (send/receive direction)  
- Encrypted message round-trip  

---

## Interoperability (Python ↔ C)

This client is fully compatible with the Python implementation.

### Quick test

1. Start Python client:
   ```bash
   python -m p2p_client --username alice --port 55000
   ```

2. Start C client:
   ```bash
   ./p2p_client bob 55001
   ```

3. Verify:
   - `/peers` shows both clients  
   - `/list` works both directions  
   - `/get` works both directions  
   - `/verify` confirms fingerprint  
   - `/rotate` updates keys correctly  

---

## Project Structure

```
c/
├── src/
│   ├── main.c              # CLI entry point
│   ├── crypto/             # Encryption and key management
│   ├── network/            # Protocol, connections, server, discovery
│   └── storage/            # File storage
├── include/                # Header files
└── tests/                  # Test suite
```

---

## Security Features

- Mutual authentication using Ed25519 identity keys (TOFU model)  
- Perfect forward secrecy via ephemeral X25519 key exchange  
- AES-256-GCM encrypted communication  
- HKDF-SHA256 session key derivation with directional keys  
- Tamper detection via authenticated encryption  
- Key rotation with signed updates  
- Local fingerprint verification using `/verify`  

---

## Notes

- Peers must be on the same network (LAN) for discovery  
- File transfers are end-to-end encrypted  
- Protocol behavior matches the Python client exactly  