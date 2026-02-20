"""
Share enumeration using Impacket SMB client
Uses listShares() (SRVSVC NetShareEnum) — same method as NetExec/CrackMapExec.
"""

import logging
import threading
from typing import List, Tuple

from impacket.smbconnection import SessionError

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.transport.smb import SMBTransport

logger = logging.getLogger('snaffler')


class ShareInfo:
    """Container for share information"""

    def __init__(self, name: str, share_type: int, remark: str):
        self.name = name
        self.share_type = share_type
        self.remark = remark
        self.readable = False
        self.writable = False

    def __repr__(self):
        return f"ShareInfo(name={self.name}, type={self.share_type}, remark={self.remark})"


class ShareFinder:
    """Find and enumerate SMB shares using Impacket"""

    # Share type constants
    STYPE_DISKTREE = 0
    STYPE_PRINTQ = 1
    STYPE_DEVICE = 2
    STYPE_IPC = 3
    STYPE_SPECIAL = 0x80000000

    NEVER_SCAN = ['IPC$', 'PRINT$']

    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.smb_transport = SMBTransport(cfg)
        self.share_classifiers = cfg.rules.share

        if (
                not self.cfg.auth.username
                and not self.cfg.auth.password
                and not self.cfg.auth.nthash
                and not self.cfg.auth.kerberos
        ):
            logger.warning("No credentials provided (NTLM or Kerberos) – continuing with NULL session")

        self._thread_local = threading.local()

    def _get_smb(self, computer: str):
        if not hasattr(self._thread_local, "smb_cache"):
            self._thread_local.smb_cache = {}

        cache = self._thread_local.smb_cache

        smb = cache.get(computer)
        if smb:
            try:
                smb.getServerName()
                return smb
            except Exception:
                try:
                    smb.logoff()
                except Exception:
                    pass
                cache.pop(computer, None)

        smb = self.smb_transport.connect(computer, timeout=10)
        cache[computer] = smb
        return smb

    def enumerate_shares(self, target: str) -> List[ShareInfo]:
        """
        Enumerate shares via SMB listShares() (SRVSVC NetShareEnum RPC).
        This reuses the authenticated SMB session, so Kerberos/NTLM/PTH all work.
        """
        shares = []
        try:
            smb = self._get_smb(target)
            for share in smb.listShares():
                share_name = share['shi1_netname'][:-1]
                share_type = share['shi1_type']
                share_remark = share['shi1_remark'][:-1] if share['shi1_remark'] else ""

                shares.append(ShareInfo(
                    name=share_name,
                    share_type=share_type,
                    remark=share_remark
                ))
        except SessionError as e:
            logger.warning(f"[{target}] Share enumeration failed (access denied): {e}")
        except Exception as e:
            logger.warning(f"[{target}] Share enumeration failed: {e}")
        return shares

    def _classify_share(self, unc_path: str) -> bool:
        """
        Apply share classifiers to determine if share should be discarded

        Args:
            unc_path: UNC path of the share (e.g., //computer/share)

        Returns:
            True if share should be discarded, False otherwise
        """
        from snaffler.classifiers.rules import MatchLocation, MatchAction

        for classifier in self.share_classifiers:
            # Only match against SHARE_NAME location
            if classifier.match_location != MatchLocation.SHARE_NAME:
                continue

            # Check if share name matches the rule
            if classifier.matches(unc_path):
                if classifier.match_action == MatchAction.DISCARD:
                    logger.debug(f"Share {unc_path} matched DISCARD rule: {classifier.rule_name}")
                    return True
                elif classifier.match_action == MatchAction.SNAFFLE:
                    # Log the interesting share (only if readable)
                    # Extract computer and share name from unc_path
                    parts = unc_path.strip('/').split('/', 1)
                    if len(parts) == 2 and self.is_share_readable(parts[0], parts[1]):
                        logger.warning(f"[{classifier.triage.value}] [{classifier.rule_name}] Share: {unc_path}")
                    # Continue scanning this share
                    return False

        return False

    def get_computer_shares(self, computer: str) -> List[Tuple[str, ShareInfo]]:
        """
        Get all readable shares from a computer.
        Uses listShares() which calls SRVSVC NetShareEnum over the existing
        authenticated SMB session (same approach as NetExec/CrackMapExec).
        """
        logger.debug(f"Enumerating shares on {computer}")

        shares = self.enumerate_shares(computer)

        if shares:
            share_names = [s.name for s in shares]
            logger.info(f"[{computer}] Enumerated {len(shares)} shares: {share_names}")
        else:
            logger.warning(f"[{computer}] No shares found")
            return []

        results: List[Tuple[str, ShareInfo]] = []

        for share in shares:
            share_name = share.name.upper()

            # Hard skip
            if share_name in self.NEVER_SCAN:
                logger.debug(f"[{computer}] Skipping {share.name} (in NEVER_SCAN list)")
                continue

            unc_path = f"//{computer}/{share.name}"

            # --- SYSVOL / NETLOGON handling ---
            apply_classifiers = True

            if share_name == "SYSVOL":
                apply_classifiers = False
                if not self.cfg.targets.scan_sysvol:
                    logger.debug(f"Skipping SYSVOL replica at {unc_path}")
                    continue
                self.cfg.targets.scan_sysvol = False
                logger.debug(f"Scanning first SYSVOL replica at {unc_path}")

            elif share_name == "NETLOGON":
                apply_classifiers = False
                if not self.cfg.targets.scan_netlogon:
                    logger.debug(f"Skipping NETLOGON replica at {unc_path}")
                    continue
                self.cfg.targets.scan_netlogon = False
                logger.debug(f"Scanning first NETLOGON replica at {unc_path}")

            # --- Share classifiers ---
            if apply_classifiers and self._classify_share(unc_path):
                logger.debug(f"Share {unc_path} discarded by classifier")
                continue

            # --- Readability check ---
            share.readable = self.is_share_readable(computer, share.name)

            if share.readable:
                logger.info(f"Readable share: {unc_path}")
                results.append((unc_path, share))
            else:
                logger.info(f"Unreadable share (access denied): {unc_path}")

        # Summary for diagnostics
        if shares:
            logger.debug(
                f"[{computer}] Share discovery summary: "
                f"{len(shares)} enumerated, {len(results)} readable"
            )

        return results

    def is_share_readable(self, computer: str, share_name: str) -> bool:
        if share_name.upper() in self.NEVER_SCAN:
            return False

        try:
            smb = self._get_smb(computer)

            # listPath tests actual directory listing — not just tree connect.
            # A share might accept connectTree but deny directory reads.
            # This matches what NetExec does for readability checks.
            smb.listPath(share_name, "*")

            return True

        except SessionError as e:
            logger.debug(f"Cannot read share {computer}\\{share_name}: {e}")
            return False
        except Exception as e:
            logger.debug(f"Error testing share {computer}\\{share_name}: {e}")
            return False
