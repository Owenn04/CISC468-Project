"""
P2P Secure File Sharing Client — CLI

Usage:
    python -m p2p_client [--username NAME] [--port PORT]

Commands (interactive):
    /peers              List discovered peers
    /list <peer>        List files available from a peer
    /get <peer> <file>  Download a file from a peer
    /send <peer> <file> Push a file to a peer
    /shared             Show your shared files
    /received           Show received files
    /export <file> <path>  Decrypt a received file and save it
    /share <path>       Add a local file to your shared folder
    /verify <peer>      Mark a peer's key as verified
    /rotate             Generate a new identity key and notify all peers
    /quit               Exit
"""

import argparse
import getpass
import socket
import sys
import threading
from pathlib import Path

from .crypto.keys     import IdentityKey
from .crypto.contacts  import ContactBook
from .network.discovery import Discovery
from .network.server    import Server
from .network.connection import Connection
from .storage.store     import Storage

DEFAULT_PORT = 55000
DATA_DIR     = Path.home() / ".p2pshare"


def main():
    parser = argparse.ArgumentParser(description="P2P Secure File Share")
    parser.add_argument("--username", default=None)
    parser.add_argument("--port",     type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    username = args.username or input("Username: ").strip()
    passphrase = getpass.getpass("Passphrase (encrypts keys and stored files): ")

    # Directories
    user_dir   = DATA_DIR / username
    key_file   = user_dir / "identity.pem"
    contacts_f = user_dir / "contacts.json"
    shared_dir = user_dir / "shared"
    recv_dir   = user_dir / "received"
    user_dir.mkdir(parents=True, exist_ok=True)

    # Load or generate identity key
    if key_file.exists():
        try:
            identity = IdentityKey.load(key_file, passphrase.encode())
            print(f"[init] Loaded identity key for '{username}'")
        except Exception:
            print("[!] Wrong passphrase or corrupted key file. Exiting.")
            sys.exit(1)
    else:
        identity = IdentityKey.generate()
        identity.save(key_file, passphrase.encode())
        print(f"[init] Generated new identity key for '{username}'")
        print(f"[init] Fingerprint: {_fingerprint(identity)}")

    contacts = ContactBook(contacts_f)
    storage  = Storage(shared_dir, recv_dir, passphrase)

    # Start server
    server = Server(
        host="0.0.0.0",
        port=args.port,
        username=username,
        identity=identity,
        contacts=contacts,
        shared_dir=shared_dir,
        recv_dir=recv_dir,
        passphrase=passphrase,
    )
    server.start()

    # Start mDNS discovery
    discovery = Discovery(username, args.port)
    discovery.start()

    print(f"\nWelcome, {username}! Type /help for commands.\n")

    # REPL
    try:
        while True:
            try:
                line = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not line:
                continue

            parts = line.split()
            cmd   = parts[0].lower()

            if cmd == "/help":
                print(__doc__)

            elif cmd == "/peers":
                peers = discovery.peers()
                if not peers:
                    print("No peers found yet.")
                else:
                    for p in peers:
                        print(f"  {p.username} @ {p.host}:{p.port}")

            elif cmd == "/list" and len(parts) == 2:
                peer_name = parts[1]
                conn = _connect(peer_name, discovery, username, identity,
                                contacts, shared_dir, recv_dir, passphrase)
                if conn:
                    files = conn.request_file_list()
                    conn.close()
                    if files:
                        print(f"Files available from {peer_name}:")
                        for f in files:
                            print(f"  {f['filename']}  ({f['size']} bytes)  sha256={f['sha256'][:16]}...")
                    else:
                        print("No files available or request failed.")

            elif cmd == "/get" and len(parts) == 3:
                peer_name, filename = parts[1], parts[2]
                conn = _connect(peer_name, discovery, username, identity,
                                contacts, shared_dir, recv_dir, passphrase)
                if conn:
                    conn.request_file(filename)
                    conn.close()

            elif cmd == "/send" and len(parts) == 3:
                peer_name, filename = parts[1], parts[2]
                conn = _connect(peer_name, discovery, username, identity,
                                contacts, shared_dir, recv_dir, passphrase)
                if conn:
                    conn.send_file(filename)
                    conn.close()

            elif cmd == "/shared":
                files = storage.list_shared()
                print("Shared files:", files if files else "(none)")

            elif cmd == "/received":
                files = storage.list_received()
                print("Received files:", files if files else "(none)")

            elif cmd == "/export" and len(parts) == 3:
                filename, dest = parts[1], Path(parts[2])
                try:
                    storage.export_received(filename, dest)
                except FileNotFoundError as e:
                    print(f"[!] {e}")
                except ValueError as e:
                    print(f"[!] {e}")

            elif cmd == "/share" and len(parts) == 2:
                src = Path(parts[1])
                if not src.exists():
                    print(f"[!] File not found: {src}")
                else:
                    storage.add_to_shared(src)

            elif cmd == "/verify" and len(parts) == 2:
                peer_name = parts[1]
                fp = contacts.fingerprint(peer_name)
                if fp is None:
                    print(f"[!] Unknown peer: {peer_name}")
                else:
                    print(f"Fingerprint for '{peer_name}': {fp}")
                    answer = input("Confirm this matches out-of-band? [y/N] ").strip().lower()
                    if answer == "y":
                        contacts.mark_verified(peer_name)
                        print(f"[trust] '{peer_name}' marked as verified.")

            elif cmd == "/rotate":
                _rotate_key(username, user_dir, passphrase, identity,
                            contacts, discovery)

            elif cmd in ("/quit", "/exit", "/q"):
                break

            else:
                print("Unknown command. Type /help for usage.")

    finally:
        print("\nShutting down...")
        discovery.stop()
        server.stop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _connect(
    peer_name:  str,
    discovery:  Discovery,
    username:   str,
    identity:   IdentityKey,
    contacts:   ContactBook,
    shared_dir: Path,
    recv_dir:   Path,
    passphrase: str,
) -> Connection | None:
    peer = discovery.get_peer(peer_name)
    if peer is None:
        print(f"[!] Peer '{peer_name}' not found. Try /peers to refresh.")
        return None
    try:
        sock = socket.create_connection((peer.host, peer.port), timeout=10)
    except OSError as e:
        print(f"[!] Could not connect to {peer_name}: {e}")
        return None
    conn = Connection(
        sock=sock,
        own_username=username,
        identity=identity,
        contacts=contacts,
        shared_dir=shared_dir,
        recv_dir=recv_dir,
        passphrase=passphrase,
        initiator=True,
    )
    if not conn.handshake():
        conn.close()
        return None
    return conn


def _fingerprint(identity: IdentityKey) -> str:
    import hashlib
    raw    = identity.public_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    return ":".join(digest[i:i+4] for i in range(0, len(digest), 4))


def _rotate_key(
    username:  str,
    user_dir:  Path,
    passphrase: str,
    old_identity: IdentityKey,
    contacts:  ContactBook,
    discovery: Discovery,
) -> None:
    """Generate a new identity key, sign rotation notice with old key, notify all peers."""
    from .crypto.keys import _b64e
    new_identity = IdentityKey.generate()
    new_pub_b64  = new_identity.public_b64()
    payload_bytes = f"KEY_ROTATION|{username}|{new_pub_b64}".encode()
    sig           = old_identity.sign(payload_bytes)
    sig_b64       = _b64e(sig)

    from .network.protocol import MsgType
    from .network.protocol import key_rotation_payload

    notified = 0
    for peer in discovery.peers():
        try:
            sock = socket.create_connection((peer.host, peer.port), timeout=5)
            conn = Connection(
                sock=sock,
                own_username=username,
                identity=old_identity,   # still using old key for handshake
                contacts=contacts,
                shared_dir=user_dir / "shared",
                recv_dir=user_dir / "received",
                passphrase=passphrase,
                initiator=True,
            )
            if conn.handshake():
                conn._send_encrypted(MsgType.KEY_ROTATION,
                                     key_rotation_payload(new_pub_b64, sig_b64))
            conn.close()
            notified += 1
        except Exception:
            pass

    # Save new key
    key_file = user_dir / "identity.pem"
    new_identity.save(key_file, passphrase.encode())
    print(f"[rotate] New key saved. Notified {notified} online peer(s).")
    print(f"[rotate] New fingerprint: {_fingerprint(new_identity)}")


if __name__ == "__main__":
    main()
