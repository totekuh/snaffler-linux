# snaffler/transport/file_accessor.py

from abc import ABC, abstractmethod
from typing import Optional


class FileAccessor(ABC):
    @abstractmethod
    def read(self, server: str, share: str, path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
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
