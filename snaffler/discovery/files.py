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

logger = logging.getLogger('snaffler')


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

        self.file_classifiers = cfg.rules.file
        self.content_classifiers = cfg.rules.content
        self.postmatch_classifiers = cfg.rules.postmatch

        self.content_rules_by_name = {
            rule.rule_name: rule for rule in self.content_classifiers
        }

        self.cert_checker = CertificateChecker(
            custom_passwords=self.cfg.scanning.cert_passwords
        )

        self._thread_local = threading.local()

    def _get_smb(self, server: str):
        if not hasattr(self._thread_local, "smb_cache"):
            self._thread_local.smb_cache = {}

        cache = self._thread_local.smb_cache

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

    def scan_file(self, unc_path: str, file_info) -> Optional[FileResult]:
        try:
            parts = [p for p in unc_path.replace('\\', '/').split('/') if p]
            if len(parts) < 3:
                return None

            server, share = parts[0], parts[1]
            file_path = '\\' + '\\'.join(parts[2:])

            file_name = Path(unc_path).name
            file_ext = Path(unc_path).suffix

            if file_ext.lower() == '.bak':
                stripped = file_name[:-4]
                alt_ext = Path(stripped).suffix
                if alt_ext:
                    file_ext = alt_ext

            if not file_ext:
                return None

            file_size = file_info.get_filesize() if hasattr(file_info, 'get_filesize') else 0

            modified_time = None
            if hasattr(file_info, 'get_mtime_epoch'):
                try:
                    modified_time = datetime.fromtimestamp(file_info.get_mtime_epoch())
                except Exception:
                    pass

            relay_targets = []
            best_result = None

            for rule in self.file_classifiers:
                match = self._check_file_rule(
                    rule, unc_path, file_name, file_ext, file_size
                )
                if not match:
                    continue

                if rule.match_action == MatchAction.DISCARD:
                    return None

                if rule.match_action == MatchAction.RELAY:
                    relay_targets.extend(rule.relay_targets)
                    continue

                if rule.match_action == MatchAction.CHECK_FOR_KEYS:
                    cert = self._check_certificate(
                        server, share, file_path, unc_path, file_size, modified_time
                    )
                    if cert and not best_result:
                        best_result = cert
                    continue

                if rule.match_action != MatchAction.SNAFFLE:
                    continue

                if self._postmatch_discard(unc_path, file_name):
                    return None

                if not self._can_read_file(server, share, file_path):
                    continue

                result = FileResult(unc_path, file_size, modified_time)
                result.triage = rule.triage

                if result.triage.below(self.cfg.scanning.min_interest):
                    continue

                result.rule_name = rule.rule_name
                result.match = match if isinstance(match, str) else match.group(0)

                log_file_result(
                    logger,
                    unc_path,
                    result.triage.label,
                    result.rule_name,
                    result.match,
                    size=file_size,
                    modified=modified_time.strftime('%Y-%m-%d %H:%M:%S') if modified_time else None
                )

                if (
                        self.cfg.scanning.snaffle
                        and file_size <= self.cfg.scanning.max_size_to_snaffle
                ):
                    self._snaffle_file(server, share, file_path, unc_path)

                if not best_result:
                    best_result = result

            if file_size <= self.cfg.scanning.max_size_to_grep:
                content_result = self._scan_file_contents(
                    server,
                    share,
                    file_path,
                    unc_path,
                    file_size,
                    modified_time,
                    relay_targets or None
                )
                return content_result or best_result

            return best_result

        except Exception as e:
            logger.debug(f"Error scanning file {unc_path}: {e}")
            return None

    def _check_file_rule(
            self,
            rule: ClassifierRule,
            full_path: str,
            file_name: str,
            file_ext: str,
            file_size: int
    ) -> Optional[object]:

        if rule.match_location == MatchLocation.FILE_PATH:
            return rule.matches(full_path)

        if rule.match_location == MatchLocation.FILE_NAME:
            return rule.matches(file_name)

        if rule.match_location == MatchLocation.FILE_EXTENSION:
            return rule.matches(file_ext)

        if rule.match_location == MatchLocation.FILE_LENGTH:
            if rule.match_length == file_size:
                return f"size == {file_size}"
            return None

        return None

    def _postmatch_discard(self, unc_path: str, file_name: str) -> bool:
        for rule in self.postmatch_classifiers:
            if rule.match_action != MatchAction.DISCARD:
                continue

            text = (
                unc_path
                if rule.match_location == MatchLocation.FILE_PATH
                else file_name
            )

            if rule.matches(text):
                return True

        return False

    def _scan_file_contents(
            self,
            server: str,
            share: str,
            file_path: str,
            unc_path: str,
            file_size: int,
            modified_time: datetime,
            relay_target_names: Optional[list]
    ) -> Optional[FileResult]:

        try:
            data = self._read_file_smb(server, share, file_path)
            if not data:
                return None

            try:
                text = data.decode('utf-8', errors='ignore')
            except Exception:
                text = data.decode('latin-1', errors='ignore')

            rules = (
                [self.content_rules_by_name[n] for n in relay_target_names if n in self.content_rules_by_name]
                if relay_target_names
                else self.content_classifiers
            )

            for rule in rules:
                if rule.match_location != MatchLocation.FILE_CONTENT_AS_STRING:
                    continue

                match = rule.matches(text)
                if not match:
                    continue

                if self._postmatch_discard(unc_path, Path(unc_path).name):
                    continue

                result = FileResult(unc_path, file_size, modified_time)
                result.triage = rule.triage

                if result.triage.below(self.cfg.scanning.min_interest):
                    continue

                result.rule_name = rule.rule_name
                result.match = match.group(0)

                start = max(0, match.start() - self.cfg.scanning.match_context_bytes)
                end = min(len(text), match.end() + self.cfg.scanning.match_context_bytes)
                result.context = re.escape(text[start:end])

                log_file_result(
                    logger,
                    unc_path,
                    result.triage.label,
                    result.rule_name,
                    result.match,
                    result.context,
                    file_size,
                    modified_time.strftime('%Y-%m-%d %H:%M:%S') if modified_time else None
                )

                if (
                        self.cfg.scanning.snaffle
                        and file_size <= self.cfg.scanning.max_size_to_snaffle
                ):
                    self._snaffle_file(server, share, file_path, unc_path)

                return result

            return None

        except Exception as e:
            logger.debug(f"Error scanning contents of {unc_path}: {e}")
            return None

    def _can_read_file(self, server: str, share: str, file_path: str) -> bool:
        try:
            smb = self._get_smb(server)
            from io import BytesIO
            buf = BytesIO()
            smb.getFile(share, file_path, buf.write, 0, 1)
            return True
        except Exception as e:
            logger.debug(f"Cannot access file {server}/{share}/{file_path}: {e}")
            return False

    def _check_certificate(
            self,
            server: str,
            share: str,
            file_path: str,
            unc_path: str,
            file_size: int,
            modified_time: datetime
    ) -> Optional[FileResult]:

        try:
            data = self._read_file_smb(server, share, file_path)
            if not data:
                return None

            filename = Path(unc_path).name
            reasons = self.cert_checker.check_certificate(data, filename)

            if not reasons or "HasPrivateKey" not in reasons:
                return None

            result = FileResult(unc_path, file_size, modified_time)
            result.triage = Triage.RED

            if result.triage.below(self.cfg.scanning.min_interest):
                return None

            result.rule_name = "RelayCertByExtension"
            result.match = filename
            result.context = ", ".join(reasons)

            log_file_result(
                logger,
                unc_path,
                result.triage.label,
                result.rule_name,
                result.match,
                context=result.context,
                size=file_size,
                modified=modified_time.strftime('%Y-%m-%d %H:%M:%S') if modified_time else None
            )

            if (
                    self.cfg.scanning.snaffle
                    and file_size <= self.cfg.scanning.max_size_to_snaffle
            ):
                self._snaffle_file(server, share, file_path, unc_path)

            return result

        except Exception as e:
            logger.debug(f"Error checking certificate {unc_path}: {e}")
            return None

    def _read_file_smb(self, server: str, share: str, file_path: str) -> Optional[bytes]:
        try:
            smb = self._get_smb(server)
            from io import BytesIO
            buf = BytesIO()
            smb.getFile(share, file_path, buf.write)
            return buf.getvalue()
        except Exception:
            return None

    def _snaffle_file(self, server: str, share: str, file_path: str, unc_path: str):
        if not self.cfg.scanning.snaffle_path:
            return

        try:
            clean = file_path.lstrip("\\/")
            local = Path(self.cfg.scanning.snaffle_path) / server / share / clean
            local.parent.mkdir(parents=True, exist_ok=True)

            data = self._read_file_smb(server, share, file_path)
            if data:
                local.write_bytes(data)
        except Exception:
            pass
