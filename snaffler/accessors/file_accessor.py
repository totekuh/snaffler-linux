# snaffler/transport/file_accessor.py

from abc import ABC, abstractmethod
from typing import Optional, List, Any


class FileAccessor(ABC):
    @abstractmethod
    def can_read(self, server: str, share: str, path: str) -> bool:
        ...

    @abstractmethod
    def read(self, server: str, share: str, path: str) -> Optional[bytes]:
        ...

    @abstractmethod
    def copy_to_local(
            self,
            server: str,
            share: str,
            path: str,
            dest_root,
    ) -> None:
        ...

    @abstractmethod
    def list_path(self, server: str, share: str, path: str) -> List[Any]:
        """List directory contents.

        Args:
            server: Target server hostname/IP
            share: Share name
            path: Path within share (with wildcard, e.g. "/dir/*")

        Returns:
            List of directory entries
        """
        ...
