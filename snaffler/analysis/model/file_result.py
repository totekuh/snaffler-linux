#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime
from typing import Optional

from snaffler.classifiers.rules import Triage


class FileResult:
    __slots__ = (
        "file_path",
        "size",
        "modified",
        "triage",
        "rule_name",
        "match",
        "context",
    )

    def __init__(
            self,
            file_path: str,
            size: int,
            modified: Optional[datetime],
            triage: Triage,
            rule_name: str,
            match: str,
            context: Optional[str] = None,
    ):
        self.file_path = file_path
        self.size = size
        self.modified = modified
        self.triage = triage
        self.rule_name = rule_name
        self.match = match
        self.context = context

    @staticmethod
    def pick_best(
            current: Optional[FileResult],
            candidate: Optional[FileResult],
    ) -> Optional[FileResult]:
        if not candidate:
            return current
        if not current:
            return candidate
        if candidate.triage.more_severe_than(current.triage):
            return candidate
        return current
