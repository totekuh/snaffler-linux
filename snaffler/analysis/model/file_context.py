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
