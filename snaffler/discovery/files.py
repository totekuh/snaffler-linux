"""
File scanning and classification
"""

import logging
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from snaffler.analysis.certificates import CertificateChecker
from snaffler.classifiers.rules import ClassifierRule, MatchLocation, MatchAction, Triage
from snaffler.transport.smb import SMBTransport
from snaffler.utils.logger import log_file_result
from snaffler.utils.path_utils import parse_unc_path, get_modified_time

logger = logging.getLogger("snaffler")


class FileResult:
    def __init__(self, file_path: str, size: int = 0, modified: datetime = None):
        self.file_path = file_path
        self.size = size
        self.modified = modified
        self.triage: Optional[Triage] = None
        self.rule_name: Optional[str] = None
        self.match: Optional[str] = None
        self.context: Optional[str] = None


class FileScanner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.smb_transport = SMBTransport(cfg)

        self.file_rules = cfg.rules.file
        self.content_rules = cfg.rules.content
        self.postmatch_rules = cfg.rules.postmatch

        self.content_rules_by_name = {
            r.rule_name: r for r in self.content_rules
        }

        self.cert_checker = CertificateChecker(
            custom_passwords=cfg.scanning.cert_passwords
        )

        self._thread_local = threading.local()

    # ------------------------------------------------------------------ SMB

    def _get_smb(self, server: str):
        cache = getattr(self._thread_local, "smb_cache", {})
        self._thread_local.smb_cache = cache

        smb = cache.get(server)
        if smb:
            try:
                smb.getServerName()
                return smb
            except Exception:
                try:
                    smb.logoff()
                except Exception:
                    pass
                cache.pop(server, None)

        smb = self.smb_transport.connect(server)
        cache[server] = smb
        return smb

    def _read_file_smb(self, server: str, share: str, path: str) -> Optional[bytes]:
        try:
            smb = self._get_smb(server)
            from io import BytesIO
            buf = BytesIO()
            smb.getFile(share, path, buf.write)
            return buf.getvalue()
        except Exception:
            return None

    def _can_read_file(self, server: str, share: str, path: str) -> bool:
        try:
            smb = self._get_smb(server)
            from io import BytesIO
            buf = BytesIO()
            smb.getFile(share, path, buf.write, 0, 1)
            return True
        except Exception:
            return False

    # -------------------------------------------------------------- Results

    def _finalize_result(
            self,
            result: FileResult,
            server: str,
            share: str,
            smb_path: str,
    ) -> Optional[FileResult]:

        if result.triage.below(self.cfg.scanning.min_interest):
            return None

        log_file_result(
            logger,
            result.file_path,
            result.triage.label,
            result.rule_name,
            result.match,
            result.context,
            result.size,
            result.modified.strftime("%Y-%m-%d %H:%M:%S") if result.modified else None,
        )

        if (
                self.cfg.scanning.snaffle
                and result.size <= self.cfg.scanning.max_size_to_snaffle
        ):
            self._snaffle_file(server, share, smb_path, result.file_path)

        return result

    def _build_result(
            self,
            unc_path: str,
            size: int,
            modified: datetime,
            triage: Triage,
            rule_name: str,
            match: str,
            context: Optional[str] = None,
    ) -> FileResult:

        r = FileResult(unc_path, size, modified)
        r.triage = triage
        r.rule_name = rule_name
        r.match = match
        r.context = context
        return r

    # -------------------------------------------------------------- Scanning

    def scan_file(self, unc_path: str, file_info) -> Optional[FileResult]:
        try:
            parsed = parse_unc_path(unc_path)
            if not parsed:
                return None

            server, share, smb_path, file_name, file_ext = parsed
            size = getattr(file_info, "get_filesize", lambda: 0)()
            modified = get_modified_time(file_info)

            relay_targets = []
            best_result = None

            for rule in self.file_rules:
                match = self._match_file_rule(rule, unc_path, file_name, file_ext, size)
                if not match:
                    continue

                action = rule.match_action

                if action == MatchAction.DISCARD:
                    return None

                if action == MatchAction.RELAY:
                    relay_targets.extend(rule.relay_targets)
                    continue

                if action == MatchAction.CHECK_FOR_KEYS:
                    cert = self._check_certificate(
                        server, share, smb_path, unc_path, size, modified
                    )
                    if cert:
                        cert = self._finalize_result(cert, server, share, smb_path)
                        if cert and not best_result:
                            best_result = cert
                    continue

                if action != MatchAction.SNAFFLE:
                    continue

                if self._postmatch_discard(unc_path, file_name):
                    return None

                if not self._can_read_file(server, share, smb_path):
                    continue

                result = self._build_result(
                    unc_path,
                    size,
                    modified,
                    rule.triage,
                    rule.rule_name,
                    match if isinstance(match, str) else match.group(0),
                )

                result = self._finalize_result(result, server, share, smb_path)
                if result and not best_result:
                    best_result = result

            if size <= self.cfg.scanning.max_size_to_grep:
                content_result = self._scan_file_contents(
                    server,
                    share,
                    smb_path,
                    unc_path,
                    size,
                    modified,
                    relay_targets or None,
                )
                return content_result or best_result

            return best_result

        except Exception as e:
            logger.debug(f"Error scanning file {unc_path}: {e}")
            return None

    def _match_file_rule(
            self,
            rule: ClassifierRule,
            full_path: str,
            name: str,
            ext: str,
            size: int,
    ):
        if rule.match_location == MatchLocation.FILE_PATH:
            return rule.matches(full_path)
        if rule.match_location == MatchLocation.FILE_NAME:
            return rule.matches(name)
        if rule.match_location == MatchLocation.FILE_EXTENSION:
            return rule.matches(ext)
        if rule.match_location == MatchLocation.FILE_LENGTH:
            return f"size == {size}" if rule.match_length == size else None
        return None

    def _postmatch_discard(self, unc_path: str, name: str) -> bool:
        for rule in self.postmatch_rules:
            if rule.match_action != MatchAction.DISCARD:
                continue

            text = (
                unc_path
                if rule.match_location == MatchLocation.FILE_PATH
                else name
            )
            if rule.matches(text):
                return True

        return False

    def _scan_file_contents(
            self,
            server: str,
            share: str,
            smb_path: str,
            unc_path: str,
            size: int,
            modified: datetime,
            relay_rule_names: Optional[list],
    ) -> Optional[FileResult]:

        data = self._read_file_smb(server, share, smb_path)
        if not data:
            return None

        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = data.decode("latin-1", errors="ignore")

        rules = (
            [self.content_rules_by_name[n] for n in relay_rule_names if n in self.content_rules_by_name]
            if relay_rule_names
            else self.content_rules
        )

        for rule in rules:
            if rule.match_location != MatchLocation.FILE_CONTENT_AS_STRING:
                continue

            match = rule.matches(text)
            if not match:
                continue

            if self._postmatch_discard(unc_path, Path(unc_path).name):
                continue

            start = max(0, match.start() - self.cfg.scanning.match_context_bytes)
            end = min(len(text), match.end() + self.cfg.scanning.match_context_bytes)

            result = self._build_result(
                unc_path,
                size,
                modified,
                rule.triage,
                rule.rule_name,
                match.group(0),
                re.escape(text[start:end]),
            )

            return self._finalize_result(result, server, share, smb_path)

        return None

    # -------------------------------------------------------------- Certs

    def _check_certificate(
            self,
            server: str,
            share: str,
            smb_path: str,
            unc_path: str,
            size: int,
            modified: datetime,
    ) -> Optional[FileResult]:

        data = self._read_file_smb(server, share, smb_path)
        if not data:
            return None

        reasons = self.cert_checker.check_certificate(data, Path(unc_path).name)
        if not reasons or "HasPrivateKey" not in reasons:
            return None

        return self._build_result(
            unc_path,
            size,
            modified,
            Triage.RED,
            "RelayCertByExtension",
            Path(unc_path).name,
            ", ".join(reasons),
        )

    # -------------------------------------------------------------- Snaffle

    def _snaffle_file(self, server: str, share: str, smb_path: str, unc_path: str):
        if not self.cfg.scanning.snaffle_path:
            return

        try:
            clean = smb_path.lstrip("\\/")
            local = Path(self.cfg.scanning.snaffle_path) / server / share / clean
            local.parent.mkdir(parents=True, exist_ok=True)

            data = self._read_file_smb(server, share, smb_path)
            if data:
                local.write_bytes(data)
        except Exception:
            pass
