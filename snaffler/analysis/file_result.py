#!/usr/bin/env python3
from datetime import datetime
from typing import Optional

from snaffler.classifiers.rules import Triage


class FileResult:
    def __init__(self, file_path: str, size: int = 0, modified: datetime = None):
        self.file_path = file_path
        self.size = size
        self.modified = modified
        self.triage: Optional[Triage] = None
        self.rule_name: Optional[str] = None
        self.match: Optional[str] = None
        self.context: Optional[str] = None
