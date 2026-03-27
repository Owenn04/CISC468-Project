"""
TCP server: accepts inbound peer connections and spawns a handler thread
for each one.
"""

import socket
import threading
from pathlib import Path

from ..crypto.keys    import IdentityKey
from ..crypto.contacts import ContactBook
from .connection       import Connection


class Server:

    def __init__(
        self,
        host:       str,
        port:       int,
        username:   str,
        identity:   IdentityKey,
        contacts:   ContactBook,
        shared_dir: Path,
        recv_dir:   Path,
        passphrase: str,
    ):
        self._host       = host
        self._port       = port
        self._username   = username
        self._identity   = identity
        self._contacts   = contacts
        self._shared_dir = shared_dir
        self._recv_dir   = recv_dir
        self._passphrase = passphrase
        self._sock: socket.socket | None = None
        self._running = False

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(10)
        self._running = True
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        print(f"[server] Listening on {self._host}:{self._port}")

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client_sock, addr = self._sock.accept()
            except OSError:
                break
            print(f"[server] Inbound connection from {addr}")
            conn = Connection(
                sock=client_sock,
                own_username=self._username,
                identity=self._identity,
                contacts=self._contacts,
                shared_dir=self._shared_dir,
                recv_dir=self._recv_dir,
                passphrase=self._passphrase,
                initiator=False,
            )
            t = threading.Thread(
                target=self._handle, args=(conn,), daemon=True
            )
            t.start()

    @staticmethod
    def _handle(conn: Connection) -> None:
        if conn.handshake():
            conn.handle_incoming()
        conn.close()
