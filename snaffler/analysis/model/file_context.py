from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class FileContext:
    unc_path: str
    smb_path: str
    name: str
    ext: str
    size: int
    modified: datetime
