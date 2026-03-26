# snaffler/accessors/file_accessor.py

import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger("snaffler")


class FileAccessor(ABC):
    @abstractmethod
    def read(self, file_path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        ...

    @abstractmethod
    def copy_to_local(self, file_path: str, dest_root) -> None:
        ...

    def close(self):
        """Release resources. Override in subclasses with connections to clean up."""
        pass

    def _safe_local_write(self, dest_root, relative_parts: list, data: bytes) -> bool:
        """Write data under dest_root with path traversal protection. Returns True on success."""
        from pathlib import Path
        local = Path(dest_root).joinpath(*relative_parts).resolve()
        root = Path(dest_root).resolve()
        if not local.is_relative_to(root):
            logger.warning(f"Path traversal blocked: {'/'.join(relative_parts)}")
            return False
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(data)
        return True
