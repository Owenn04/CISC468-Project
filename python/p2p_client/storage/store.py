"""
Local storage management.

Files received from peers are stored encrypted on disk using Argon2id + AES-256-GCM.
This module handles decryption for reading, and manages the shared/received dirs.
"""

from pathlib import Path

from ..crypto.keys import encrypt_file, decrypt_file


class Storage:

    def __init__(self, shared_dir: Path, recv_dir: Path, passphrase: str):
        self._shared  = shared_dir
        self._recv    = recv_dir
        self._pw      = passphrase
        shared_dir.mkdir(parents=True, exist_ok=True)
        recv_dir.mkdir(parents=True, exist_ok=True)

    # -- Received files (encrypted on disk) ---------------------------------

    def list_received(self) -> list[str]:
        """Return filenames of decryptable received files (strips .enc suffix)."""
        return [f.stem for f in self._recv.glob("*.enc")]

    def read_received(self, filename: str) -> bytes:
        """Decrypt and return a received file."""
        path = self._recv / (filename + ".enc")
        if not path.exists():
            raise FileNotFoundError(f"No received file: {filename}")
        return decrypt_file(path.read_bytes(), self._pw)

    def export_received(self, filename: str, dest: Path) -> None:
        """Decrypt a received file and write to dest."""
        data = self.read_received(filename)
        dest.write_bytes(data)
        print(f"[storage] Exported '{filename}' to {dest}")

    # -- Shared files (plaintext, readable by peers) ------------------------

    def list_shared(self) -> list[str]:
        return [f.name for f in self._shared.iterdir() if f.is_file()]

    def add_to_shared(self, src: Path) -> None:
        """Copy a file into the shared directory."""
        import shutil
        dest = self._shared / src.name
        shutil.copy2(src, dest)
        print(f"[storage] Added '{src.name}' to shared files")

    def remove_from_shared(self, filename: str) -> None:
        path = self._shared / filename
        if path.exists():
            path.unlink()
            print(f"[storage] Removed '{filename}' from shared files")
        else:
            print(f"[storage] File not found: {filename}")
