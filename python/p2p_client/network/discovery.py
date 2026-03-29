"""
mDNS peer discovery via zeroconf.

Advertises this client on the local network and maintains a live list of
discovered peers. Each peer is registered under the service type
_p2pshare._tcp.local.
"""

import socket
import threading
from dataclasses import dataclass, field

from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf


SERVICE_TYPE = "_p2pshare._tcp.local."


@dataclass
class PeerInfo:
    username: str
    host:     str
    port:     int


class Discovery:

    def __init__(self, username: str, port: int):
        self._username  = username
        self._port      = port
        self._zeroconf  = Zeroconf()
        self._peers:    dict[str, PeerInfo] = {}
        self._lock      = threading.Lock()
        self._listener  = _PeerListener(self._peers, self._lock, username)
        self._browser   = None
        self._info      = None

    # -- Lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Advertise and start listening for peers."""
        local_ip = _local_ip()
        self._info = ServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{self._username}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self._port,
            properties={"username": self._username},
        )
        self._zeroconf.register_service(self._info)
        self._browser = ServiceBrowser(self._zeroconf, SERVICE_TYPE, self._listener)
        print(f"[discovery] Advertising as '{self._username}' on {local_ip}:{self._port}")

    def stop(self) -> None:
        if self._info:
            self._zeroconf.unregister_service(self._info)
        self._zeroconf.close()

    # Peer list 

    def peers(self) -> list[PeerInfo]:
        with self._lock:
            return list(self._peers.values())

    def get_peer(self, username: str) -> PeerInfo | None:
        with self._lock:
            return self._peers.get(username)


# Internal zeroconf listener

class _PeerListener:

    def __init__(self, peers: dict, lock: threading.Lock, own_username: str):
        self._peers    = peers
        self._lock     = lock
        self._own      = own_username

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info is None:
            return
        username = info.properties.get(b"username", b"").decode()
        if not username or username == self._own:
            return
        host = socket.inet_ntoa(info.addresses[0])
        with self._lock:
            self._peers[username] = PeerInfo(username=username, host=host, port=info.port)
        print(f"[discovery] Peer found: {username} @ {host}:{info.port}")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        # strip service type suffix to get username
        username = name.replace(f".{type_}", "").rstrip(".")
        with self._lock:
            self._peers.pop(username, None)
        print(f"[discovery] Peer left: {username}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.add_service(zc, type_, name)


# Helpers


def _local_ip() -> str:
    """Best-effort local IP (not 127.0.0.1)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()
