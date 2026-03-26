import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class FileContext:
    unc_path: str
    name: str
    ext: str
    size: int
    modified: Optional[datetime]

    @classmethod
    def from_path(cls, file_path: str, size: int, mtime_epoch: float) -> "FileContext":
        """Create a :class:`FileContext` from a file path and metadata.

        Extracts basename and extension via :func:`os.path.basename` /
        :func:`os.path.splitext`, and converts *mtime_epoch* to a
        :class:`datetime` (``None`` when *mtime_epoch* is ``None``).
        """
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1]
        modified = datetime.fromtimestamp(mtime_epoch) if mtime_epoch is not None else None
        return cls(
            unc_path=file_path,
            name=file_name,
            ext=file_ext,
            size=size,
            modified=modified,
        )
