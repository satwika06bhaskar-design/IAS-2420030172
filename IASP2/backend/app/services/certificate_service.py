import datetime
from typing import Dict, Any, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

class CertificateService:
    @staticmethod
    def generate_demo_certificate(
        common_name: str = "demo-server.securetunnel.local",
        organization: str = "SecureTunnel Educational Lab",
        validity_days: int = 365,
        tamper_signature: bool = False
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey, bytes]:
        """
        Generate an educational self-signed X.509 certificate and private key.
        Returns (certificate, private_key, cert_pem_bytes).
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CyberLab"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
        )

        cert = cert_builder.sign(private_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        if tamper_signature:
            # We will use this to test validation failure
            pass

        return cert, private_key, cert_pem

    @staticmethod
    def parse_certificate_info(cert: x509.Certificate) -> Dict[str, Any]:
        """Extract educational inspection fields from X.509 certificate."""
        def get_attr(name: x509.Name, oid) -> str:
            attrs = name.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else "N/A"

        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        formatted_fp = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))

        return {
            "subject": {
                "common_name": get_attr(cert.subject, NameOID.COMMON_NAME),
                "organization": get_attr(cert.subject, NameOID.ORGANIZATION_NAME),
                "country": get_attr(cert.subject, NameOID.COUNTRY_NAME),
            },
            "issuer": {
                "common_name": get_attr(cert.issuer, NameOID.COMMON_NAME),
                "organization": get_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
                "country": get_attr(cert.issuer, NameOID.COUNTRY_NAME),
            },
            "is_self_signed": cert.subject == cert.issuer,
            "serial_number_hex": hex(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "public_key_type": "RSA 2048-bit",
            "sha256_fingerprint": formatted_fp,
            "pem": cert.public_bytes(serialization.Encoding.PEM).decode('ascii')
        }

    @staticmethod
    def verify_certificate_signature(cert: x509.Certificate, issuer_public_key: rsa.RSAPublicKey) -> Dict[str, Any]:
        """
        Verify the mathematical signature on the certificate using issuer's public key.
        Distinguishes cryptographic signature verification from root trust verification.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        time_valid = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc

        try:
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            sig_valid = True
            error_reason = None
        except InvalidSignature:
            sig_valid = False
            error_reason = "Cryptographic signature check failed: signature does not match certificate contents."
        except Exception as e:
            sig_valid = False
            error_reason = f"Verification error: {str(e)}"

        return {
            "signature_valid": sig_valid,
            "dates_valid": time_valid,
            "overall_valid": sig_valid and time_valid,
            "is_self_signed": cert.subject == cert.issuer,
            "trust_status": "Untrusted Self-Signed" if cert.subject == cert.issuer else "CA Signed",
            "error_reason": error_reason,
            "explanation": (
                "Signature check confirms the certificate was not altered in transit. "
                "However, self-signed certificates require explicit user trust because they "
                "are not signed by an installed Certificate Authority (CA) root."
            )
        }
