"""
File scanning and classification
"""

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from snaffler.analysis.certificates import CertificateChecker
from snaffler.classifiers.rules import ClassifierRule, MatchLocation, MatchAction
from snaffler.transport.smb import SMBTransport
from snaffler.utils.logger import log_file_result

logger = logging.getLogger('snaffler')


class FileResult:
    """Container for file scan results"""

    def __init__(self, file_path: str, size: int = 0, modified: datetime = None):
        self.file_path = file_path
        self.size = size
        self.modified = modified
        self.triage = None
        self.rule_name = None
        self.match = None
        self.context = None


class FileScanner:
    def __init__(self, cfg):
        """
        cfg: SnafflerConfiguration
        """
        self.cfg = cfg
        self.smb_transport = SMBTransport(cfg)

        # Rules
        self.file_classifiers = cfg.rules.file
        self.content_classifiers = cfg.rules.content
        self.postmatch_classifiers = cfg.rules.postmatch

        self.content_rules_by_name = {
            rule.rule_name: rule for rule in self.content_classifiers
        }

        # Certificate checker
        self.cert_checker = CertificateChecker(
            custom_passwords=self.cfg.scanning.cert_passwords
        )

    def scan_file(self, unc_path: str, file_info) -> Optional[FileResult]:
        try:
            parts = unc_path.replace('\\', '/').split('/')
            parts = [p for p in parts if p]

            if len(parts) < 3:
                return None

            server = parts[0]
            share = parts[1]
            file_path = '\\' + '\\'.join(parts[2:])

            file_name = Path(unc_path).name
            file_ext = Path(unc_path).suffix

            # Special handling for .bak files - treat files like 'thing.kdbx.bak' as '.kdbx' not '.bak'
            if file_ext.lower() == '.bak':
                # Strip off .bak and get the extension of what remains
                name_without_bak = file_name.replace('.bak', '').replace('.BAK', '')
                ext_without_bak = Path(name_without_bak).suffix
                # If there's an extension after stripping .bak, use that
                if ext_without_bak:
                    file_ext = ext_without_bak
                # Otherwise keep .bak

            # Skip files with no extension (matching C# behavior)
            if not file_ext:
                return None

            file_size = file_info.get_filesize() if hasattr(file_info, 'get_filesize') else 0

            modified_time = None
            if hasattr(file_info, 'get_mtime_epoch'):
                try:
                    modified_time = datetime.fromtimestamp(file_info.get_mtime_epoch())
                except:
                    pass

            # ---------- FILE RULES ----------
            relay_targets = []
            file_result = None
            for rule in self.file_classifiers:
                match = self._check_file_rule(
                    rule, unc_path, file_name, file_ext, file_size
                )

                if not match:
                    continue

                if rule.match_action == MatchAction.DISCARD:
                    return None

                if rule.match_action == MatchAction.RELAY:
                    # Collect relay targets for content grepping
                    relay_targets.extend(rule.relay_targets)
                    continue

                if rule.match_action == MatchAction.CHECK_FOR_KEYS:
                    # Certificate checking - parse and extract private key info
                    cert_info = self._check_certificate(server, share, file_path, unc_path, file_size, modified_time)
                    if cert_info:
                        # Track first file match, but continue checking other rules
                        if not file_result:
                            file_result = cert_info
                    continue

                if rule.match_action == MatchAction.SNAFFLE:
                    # Apply postmatch filters
                    if self._postmatch_discard(unc_path, file_name):
                        return None

                    # Test if file is readable (matching C# RwStatus filtering)
                    if not self._can_read_file(server, share, file_path):
                        logger.debug(f"Skipping {unc_path} - access denied")
                        continue

                    result = FileResult(unc_path, file_size, modified_time)
                    result.triage = rule.triage.value
                    result.rule_name = rule.rule_name
                    result.match = match.group(0) if hasattr(match, 'group') else str(match)

                    log_file_result(
                        logger,
                        unc_path,
                        result.triage,
                        result.rule_name,
                        result.match,
                        size=file_size,
                        modified=modified_time.strftime('%Y-%m-%d %H:%M:%S') if modified_time else None
                    )

                    if self.cfg.scanning.snaffle and file_size <= self.cfg.scanning.max_size_to_snaffle:
                        self._snaffle_file(server, share, file_path, unc_path)

                    # Track first file match, but continue checking other rules
                    if not file_result:
                        file_result = result

            # ---------- CONTENT RULES ----------
            # If relay targets collected, use only those rules
            # Otherwise, use all content rules (backward compatible)
            if file_size <= self.cfg.scanning.max_size_to_grep:
                content_result = self._scan_file_contents(
                    server,
                    share,
                    file_path,
                    unc_path,
                    file_size,
                    modified_time,
                    relay_target_names=relay_targets if relay_targets else None
                )
                # Return content result if found, otherwise return file result
                return content_result if content_result else file_result

            # Return file result if we found one
            return file_result

        except Exception as e:
            logger.debug(f"Error scanning file {unc_path}: {e}")
            return None

    def _check_file_rule(self, rule: ClassifierRule, full_path: str, file_name: str,
                         file_ext: str, file_size: int) -> Optional[re.Match]:
        """
        Check if a file matches a rule

        Args:
            rule: ClassifierRule to check
            full_path: Full UNC path
            file_name: File name only
            file_ext: File extension
            file_size: File size in bytes

        Returns:
            Match object if matched, None otherwise
        """
        # Determine what to match against
        if rule.match_location == MatchLocation.FILE_PATH:
            text = full_path
        elif rule.match_location == MatchLocation.FILE_NAME:
            text = file_name
        elif rule.match_location == MatchLocation.FILE_EXTENSION:
            text = file_ext
        elif rule.match_location == MatchLocation.FILE_LENGTH:
            # Check file size
            if 0 < rule.match_length == file_size:
                return True
            return None
        else:
            return None

        # Check for match
        return rule.matches(text)

    def _postmatch_discard(self, unc_path: str, file_name: str) -> bool:
        """
        Apply postmatch discard rules to filter false positives

        Args:
            unc_path: Full UNC path
            file_name: File name only

        Returns:
            True if file should be discarded, False otherwise
        """
        for rule in self.postmatch_classifiers:
            if rule.match_action != MatchAction.DISCARD:
                continue

            # Determine what to match against
            if rule.match_location == MatchLocation.FILE_PATH:
                text = unc_path
            elif rule.match_location == MatchLocation.FILE_NAME:
                text = file_name
            else:
                continue

            # Check for match
            if rule.matches(text):
                logger.debug(f"PostMatch discard: {unc_path} matched rule {rule.rule_name}")
                return True

        return False

    def _scan_file_contents(self, server: str, share: str, file_path: str,
                            unc_path: str, file_size: int, modified_time: datetime,
                            relay_target_names: Optional[list] = None) -> Optional[FileResult]:
        """
        Scan file contents for interesting strings

        Args:
            server: SMB server
            share: Share name
            file_path: Path within share
            unc_path: Full UNC path
            file_size: File size
            modified_time: Last modified time
            relay_target_names: If provided, only apply these named content rules (relay mode)

        Returns:
            FileResult if interesting content found, None otherwise
        """
        try:
            # Read file contents over SMB
            contents = self._read_file_smb(server, share, file_path)
            if not contents:
                return None

            # Try to decode as text
            try:
                text_content = contents.decode('utf-8', errors='ignore')
            except:
                text_content = contents.decode('latin-1', errors='ignore')

            # Determine which content rules to apply
            if relay_target_names:
                # Relay mode: only apply specified rules
                rules_to_apply = []
                for target_name in relay_target_names:
                    if target_name in self.content_rules_by_name:
                        rules_to_apply.append(self.content_rules_by_name[target_name])
                    else:
                        logger.debug(f"Relay target '{target_name}' not found in content rules")
            else:
                # Normal mode: apply all content rules
                rules_to_apply = self.content_classifiers

            # Apply content classifiers
            for rule in rules_to_apply:
                if rule.match_location == MatchLocation.FILE_CONTENT_AS_STRING:
                    match = rule.matches(text_content)

                    if match:
                        # Found interesting content!
                        # Apply postmatch filters
                        file_name = unc_path.split('\\')[-1] if '\\' in unc_path else unc_path.split('/')[-1]
                        if self._postmatch_discard(unc_path, file_name):
                            continue

                        result = FileResult(unc_path, file_size, modified_time)
                        result.triage = rule.triage.value
                        result.rule_name = rule.rule_name
                        result.match = match.group(0) if hasattr(match, 'group') else str(match)

                        # Extract context around the match
                        if hasattr(match, 'start') and hasattr(match, 'end'):
                            start_pos = max(0, match.start() - self.cfg.scanning.match_context_bytes)
                            end_pos = min(len(text_content), match.end() + self.cfg.scanning.match_context_bytes)
                            # Escape regex metacharacters in context (matching C# behavior)
                            result.context = re.escape(text_content[start_pos:end_pos])

                        # Log the result
                        log_file_result(
                            logger,
                            unc_path,
                            result.triage,
                            result.rule_name,
                            result.match,
                            result.context,
                            file_size,
                            modified_time.strftime('%Y-%m-%d %H:%M:%S') if modified_time else None
                        )

                        # Maybe snaffle the file
                        if self.cfg.scanning.snaffle and file_size <= self.cfg.scanning.max_size_to_snaffle:
                            self._snaffle_file(server, share, file_path, unc_path)

                        return result

            return None

        except Exception as e:
            logger.debug(f"Error scanning contents of {unc_path}: {e}")
            return None

    def _can_read_file(self, server: str, share: str, file_path: str) -> bool:
        try:
            smb = self.smb_transport.connect(server, timeout=10)

            from io import BytesIO
            file_obj = BytesIO()
            smb.getFile(share, file_path, file_obj.write, 0, 1)

            smb.logoff()
            return True

        except Exception as e:
            logger.debug(f"Cannot access file {server}/{share}/{file_path}: {e}")
            return False

    def _check_certificate(self, server: str, share: str, file_path: str,
                           unc_path: str, file_size: int, modified_time: datetime) -> Optional[FileResult]:
        """
        Check certificate file for private keys and extract metadata

        Args:
            server: SMB server
            share: Share name
            file_path: Path within share
            unc_path: Full UNC path
            file_size: File size
            modified_time: Last modified time

        Returns:
            FileResult if certificate has interesting properties, None otherwise
        """
        try:
            # Read certificate file
            cert_data = self._read_file_smb(server, share, file_path)
            if not cert_data:
                return None

            # Extract filename for password guessing
            filename = unc_path.split('\\')[-1] if '\\' in unc_path else unc_path.split('/')[-1]

            # Check certificate using CertificateChecker
            match_reasons = self.cert_checker.check_certificate(cert_data, filename)

            # Only create result if we found something interesting (has private key)
            if not match_reasons or "HasPrivateKey" not in match_reasons:
                logger.debug(f"Certificate {unc_path} has no private key")
                return None

            # Create result with certificate metadata
            result = FileResult(unc_path, file_size, modified_time)
            result.triage = "Red"  # Certificates with private keys are high priority
            result.rule_name = "RelayCertByExtension"
            result.match = filename
            result.context = ", ".join(match_reasons)

            # Log the finding
            log_file_result(
                logger,
                unc_path,
                result.triage,
                result.rule_name,
                result.match,
                context=result.context,
                size=file_size,
                modified=modified_time.strftime('%Y-%m-%d %H:%M:%S') if modified_time else None
            )

            # Maybe snaffle the cert file
            if self.cfg.scanning.snaffle and file_size <= self.cfg.scanning.max_size_to_snaffle:
                self._snaffle_file(server, share, file_path, unc_path)

            return result

        except Exception as e:
            logger.debug(f"Error checking certificate {unc_path}: {e}")
            return None

    def _read_file_smb(self, server: str, share: str, file_path: str) -> Optional[bytes]:
        try:
            smb = self.smb_transport.connect(server, timeout=30)

            from io import BytesIO
            file_obj = BytesIO()
            smb.getFile(share, file_path, file_obj.write)

            smb.logoff()
            return file_obj.getvalue()

        except Exception as e:
            logger.debug(f"Cannot read file {server}/{share}/{file_path}: {e}")
            return None

    def _snaffle_file(self, server: str, share: str, file_path: str, unc_path: str):
        """
        Download (snaffle) an interesting file

        Args:
            server: SMB server
            share: Share name
            file_path: Path within share
            unc_path: Full UNC path for logging
        """
        if not self.cfg.scanning.snaffle_path:
            return

        try:
            # Create local path maintaining directory structure
            local_base = Path(self.cfg.snaffle_path)
            relative_path = Path(server) / share / file_path
            local_path = local_base / relative_path

            # Create directories
            local_path.parent.mkdir(parents=True, exist_ok=True)

            # Download file
            contents = self._read_file_smb(server, share, file_path)

            if contents:
                with open(local_path, 'wb') as f:
                    f.write(contents)

                logger.info(f"Snaffled file to: {local_path}")

        except Exception as e:
            logger.debug(f"Error snaffling {unc_path}: {e}")
