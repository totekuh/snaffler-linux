"""
Certificate checking functionality
Detects certificates with private keys and extracts metadata
"""

import logging
from typing import List, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime

logger = logging.getLogger(__name__)


class CertificateChecker:
    """Check certificate files for private keys and extract metadata"""

    # Default password list for cracking protected certs
    DEFAULT_PASSWORDS = [
        "",  # Try blank password first
        "password",
        "Password",
        "PASSWORD",
        "changeit",
        "changeme",
        "admin",
        "root",
        "123456",
        "password123",
    ]

    def __init__(self, custom_passwords: Optional[List[str]] = None):
        """
        Initialize certificate checker

        Args:
            custom_passwords: Optional list of custom passwords to try
        """
        self.passwords = self.DEFAULT_PASSWORDS.copy()
        if custom_passwords:
            self.passwords.extend(custom_passwords)

    def check_certificate(self, cert_data: bytes, filename: str) -> List[str]:
        """
        Check a certificate file for private keys and extract metadata

        Args:
            cert_data: Raw certificate file contents
            filename: Original filename (used as password guess)

        Returns:
            List of match reasons describing what was found
        """
        match_reasons = []

        # Add filename without extension as password candidate
        passwords_to_try = self.passwords.copy()
        if '.' in filename:
            filename_password = filename.rsplit('.', 1)[0]
            passwords_to_try.append(filename_password)

        # Try to parse the certificate
        cert, private_key, password_used = self._parse_certificate(
            cert_data, passwords_to_try, filename
        )

        if cert is None:
            return match_reasons  # Could not parse

        # Check for private key
        if private_key is not None:
            match_reasons.append("HasPrivateKey")

            # Report password status
            if password_used is None:
                match_reasons.append("NoPasswordRequired")
            elif password_used == "":
                match_reasons.append("PasswordBlank")
            else:
                match_reasons.append(f"PasswordCracked:{password_used}")

            # Extract certificate metadata
            match_reasons.extend(self._extract_cert_info(cert))
        else:
            # No private key found
            logger.debug(f"Certificate {filename} has no private key")

        return match_reasons

    def _parse_certificate(self, cert_data: bytes, passwords: List[str], filename: str):
        """
        Try to parse certificate with various methods

        Returns:
            Tuple of (certificate, private_key, password_used)
        """
        # Try PEM format first (most common)
        cert, private_key, password_used = self._try_parse_pem(cert_data, passwords)
        if cert is not None:
            return cert, private_key, password_used

        # Try PKCS#12/PFX format (.pfx, .p12, .pkcs12)
        cert, private_key, password_used = self._try_parse_pkcs12(cert_data, passwords)
        if cert is not None:
            return cert, private_key, password_used

        # Try DER format
        cert, private_key, password_used = self._try_parse_der(cert_data)
        if cert is not None:
            return cert, private_key, password_used

        logger.debug(f"Could not parse certificate {filename} in any known format")
        return None, None, None

    def _try_parse_pem(self, cert_data: bytes, passwords: List[str]):
        """Try to parse as PEM format"""
        try:
            # Try to load certificate
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            # Try to load private key (may be in same file)
            private_key = None
            password_used = None

            # Try without password first
            try:
                private_key = serialization.load_pem_private_key(
                    cert_data, password=None, backend=default_backend()
                )
                password_used = None
            except (ValueError, TypeError):
                # Try with passwords
                for pwd in passwords:
                    try:
                        pwd_bytes = pwd.encode('utf-8') if pwd else None
                        private_key = serialization.load_pem_private_key(
                            cert_data, password=pwd_bytes, backend=default_backend()
                        )
                        password_used = pwd
                        break
                    except Exception:
                        continue

            return cert, private_key, password_used

        except Exception as e:
            logger.debug(f"PEM parsing failed: {e}")
            return None, None, None

    def _try_parse_pkcs12(self, cert_data: bytes, passwords: List[str]):
        """Try to parse as PKCS#12/PFX format"""
        # Try without password first
        try:
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                cert_data, password=None, backend=default_backend()
            )
            return cert, private_key, None
        except Exception:
            pass

        # Try with passwords
        for pwd in passwords:
            try:
                pwd_bytes = pwd.encode('utf-8') if pwd else None
                private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                    cert_data, password=pwd_bytes, backend=default_backend()
                )
                return cert, private_key, pwd
            except Exception:
                continue

        return None, None, None

    def _try_parse_der(self, cert_data: bytes):
        """Try to parse as DER format (no private key support in DER alone)"""
        try:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            # DER files typically don't contain private keys
            return cert, None, None
        except Exception as e:
            logger.debug(f"DER parsing failed: {e}")
            return None, None, None

    def _extract_cert_info(self, cert: x509.Certificate) -> List[str]:
        """Extract metadata from certificate"""
        info = []

        # Subject
        try:
            subject = cert.subject.rfc4514_string()
            info.append(f"Subject:{subject}")
        except Exception:
            pass

        # Issuer
        try:
            issuer = cert.issuer.rfc4514_string()
            info.append(f"Issuer:{issuer}")
        except Exception:
            pass

        # Expiry
        try:
            # Use UTC-aware version to avoid deprecation warning
            if hasattr(cert, 'not_valid_after_utc'):
                expiry = cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S')
            else:
                expiry = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
            info.append(f"Expiry:{expiry}")
        except Exception:
            pass

        # Extensions
        try:
            # Basic Constraints
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                )
                if basic_constraints.value.ca:
                    info.append("IsCACert")
            except x509.ExtensionNotFound:
                pass

            # Key Usage
            try:
                key_usage = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.KEY_USAGE
                )
                usages = []
                if key_usage.value.digital_signature:
                    usages.append("DigitalSignature")
                if key_usage.value.key_encipherment:
                    usages.append("KeyEncipherment")
                if key_usage.value.key_cert_sign:
                    usages.append("KeyCertSign")
                if usages:
                    info.append(",".join(usages))
            except x509.ExtensionNotFound:
                pass

            # Enhanced Key Usage
            try:
                eku = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
                )
                eku_names = []
                for oid in eku.value:
                    # Map common OIDs to friendly names
                    if oid == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                        eku_names.append("ServerAuth")
                    elif oid == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                        eku_names.append("ClientAuth")
                    elif oid == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                        eku_names.append("CodeSigning")
                    elif oid == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                        eku_names.append("EmailProtection")
                    else:
                        eku_names.append(oid.dotted_string)
                if eku_names:
                    info.append("|".join(eku_names))
            except x509.ExtensionNotFound:
                pass

            # Subject Alternative Names
            try:
                san = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                san_values = []
                for name in san.value:
                    if isinstance(name, x509.DNSName):
                        san_values.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        san_values.append(f"IP:{name.value}")
                if san_values:
                    info.append("SAN:" + ",".join(san_values[:5]))  # Limit to 5
            except x509.ExtensionNotFound:
                pass

        except Exception as e:
            logger.debug(f"Error extracting cert extensions: {e}")

        return info
