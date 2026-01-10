from dataclasses import dataclass


@dataclass(frozen=True)
class FileContext:
    unc_path: str
    name: str
    ext: str
    size: int
