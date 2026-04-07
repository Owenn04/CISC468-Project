# CISC 468 — P2P Secure File Sharing (C Client)

## Overview

This is the C implementation of a secure peer-to-peer (P2P) file sharing system built for CISC 468. It is fully interoperable with the Python reference client and follows the same protocol, handshake flow, and encryption scheme.

The system supports secure file transfer, authenticated connections, and encrypted messaging over TCP, with automatic peer discovery via mDNS.

---

## Features

- Mutual authentication using Ed25519 identity keys (TOFU model)
- Perfect forward secrecy via ephemeral X25519 key exchange
- AES-256-GCM encrypted communication
- HKDF-SHA256 session key derivation with directional keys
- Tamper detection via authenticated encryption
- Key rotation with signed peer notifications
- Local fingerprint verification
- Automatic peer discovery via mDNS (Avahi)

---

## Requirements

### System Dependencies

You need the following libraries installed before building:

| Library | Package Name | Purpose |
|---|---|---|
| libsodium | `libsodium-dev` | Ed25519 / X25519 key operations |
| OpenSSL | `libssl-dev` | AES-256-GCM, HKDF |
| cJSON | `libcjson-dev` | JSON message parsing |
| Avahi Client | `libavahi-client-dev` | mDNS peer discovery |
| Avahi Common | `libavahi-common-dev` | mDNS support (shared with client) |
| pthreads | *(bundled with gcc)* | Multithreading |

### Compiler

- `gcc`

---

## Installation

### Linux (Native)

```bash
sudo apt update
sudo apt install -y gcc libsodium-dev libssl-dev libcjson-dev \
  libavahi-client-dev libavahi-common-dev
```

### WSL (Windows Subsystem for Linux)

If you are running on WSL (Ubuntu), follow these steps:

**1. Install WSL (if not already set up)**

Open PowerShell as Administrator and run:

```powershell
wsl --install
```

Restart your machine, then open the Ubuntu terminal.

**2. Update your package list**

```bash
sudo apt update && sudo apt upgrade -y
```

**3. Install GCC and all required libraries**

```bash
sudo apt install -y gcc libsodium-dev libssl-dev libcjson-dev \
  libavahi-client-dev libavahi-common-dev
```

**4. Install and start the Avahi daemon**

```bash
sudo apt install -y avahi-daemon avahi-utils
sudo service dbus start
sudo service avahi-daemon start
```

> **Note:** On WSL, you may need to start these services manually each session since WSL does not run systemd by default.

## Build

### Build the Client

From the project root (`c/` directory):

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

### Build the Test Suite

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

---

## Running

```bash
./p2p_client <username> <port>
```

**Example:**

```bash
./p2p_client alice 5000
```

Run multiple instances on the same LAN (or on the same machine using different ports) and peers will be discovered automatically via mDNS.

---

## Commands

Once the client is running, use the following commands in the CLI:

| Command | Description |
|---|---|
| `/peers` | List all discovered peers on the network |
| `/list <peer>` | View files shared by a specific peer |
| `/get <peer> <file>` | Download a file from a peer |
| `/shared` | Show files you are currently sharing |
| `/received` | Show files you have received |
| `/export <file> <path>` | Decrypt and export a received file to a path |
| `/share <path>` | Add a local file to your shared folder |
| `/verify <peer>` | Verify a peer's fingerprint out-of-band |
| `/rotate` | Rotate your identity key and notify peers |
| `/quit` | Exit the client |

---

## Testing

Run the test suite to validate core functionality:

```bash
./run_tests
```

### What is Tested

- AES-256-GCM encryption and decryption
- Tamper detection via authenticated encryption
- Protocol message construction and framing
- Handshake correctness
- Session key agreement (send and receive directions)
- Encrypted message round-trip

---

## Interoperability (Python and C)

This client is fully compatible with the Python reference implementation. Both clients follow the same protocol and handshake flow.

### Quick Interoperability Test

**1. Start the Python client:**

```bash
python -m p2p_client --username alice --port 55000
```

**2. Start the C client:**

```bash
./p2p_client bob 55001
```

**3. Verify everything works:**

- `/peers` should show both clients
- `/list` should work in both directions
- `/get` should successfully transfer files both ways
- `/verify` should confirm matching fingerprints
- `/rotate` should propagate key updates correctly

---

## Project Structure

```
c/
├── src/
│   ├── main.c                  # CLI entry point
│   ├── crypto/                 # Encryption and key management
│   ├── network/                # Protocol, connections, server, discovery
│   └── storage/                # File storage and management
├── include/                    # Header files
└── tests/                      # Test suite
```

---

## Troubleshooting

**`fatal error: sodium.h: No such file or directory`**

libsodium development headers are not installed. Run:

```bash
sudo apt install libsodium-dev
```

---

**`fatal error: cjson/cJSON.h: No such file or directory`**

cJSON is not installed. Run:

```bash
sudo apt install libcjson-dev
```

---

**`/peers` shows no peers**

The Avahi daemon is likely not running. Start it with:

```bash
sudo service dbus start
sudo service avahi-daemon start
```

Also make sure both clients are on the same network. mDNS discovery does not work across different subnets.

---

**`undefined reference to pthread_create`**

Make sure `-lpthread` is included at the end of your gcc command. Linker flags must come after source files.

---

**Avahi warnings on WSL**

WSL does not run systemd, so Avahi may produce warnings at startup. As long as the daemon is running via `sudo service avahi-daemon start`, discovery should still work. These warnings can generally be ignored.

---

**`libcrypto` not found**

OpenSSL development headers are missing. Run:

```bash
sudo apt install libssl-dev
```

---

## Notes

- Both clients must be on the same LAN for mDNS peer discovery to work
- All file transfers are end-to-end encrypted
- The TOFU (Trust On First Use) model is used for peer authentication — fingerprints should be verified out-of-band using `/verify` for sensitive use
- On WSL, Avahi services need to be started manually each session unless you add them to your shell startup file
- Protocol behavior matches the Python client exactly
