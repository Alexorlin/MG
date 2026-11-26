import os
import datetime
from typing import Tuple, Optional, List, Set, Dict, Any
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


class CertificateAuthority:
    """Локальний Центр сертифікації (Root CA): випуск, валідація X.509 v3 та генерація CRL (RFC 5280)."""

    def __init__(self, storage_dir: Optional[str] = None):
        if storage_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            storage_dir = os.path.join(base_dir, "ca_storage")

        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

        self.ca_key_path = os.path.join(self.storage_dir, "root_ca.key")
        self.ca_cert_path = os.path.join(self.storage_dir, "root_ca.crt")

        self.ca_key = None
        self.ca_cert = None
        self._initialize_root_ca()

    def _initialize_root_ca(self):
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
        else:
            self._generate_root_ca()

    def _generate_root_ca(self):
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        ca_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EDS Document Management PKI"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Root Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "EDS Local Root CA"),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = now + datetime.timedelta(days=3650)

        builder = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(expires_at)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                critical=False,
            )
        )

        self.ca_cert = builder.sign(self.ca_key, hashes.SHA256())

        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def get_root_certificate_pem(self) -> str:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    def issue_user_certificate(
        self,
        username: str,
        public_key_pem: str | bytes,
        days_valid: int = 365,
        organization: str = "EDS Document Management",
        extended_key_usages: Optional[List[Any]] = None
    ) -> Tuple[str, str, datetime.datetime]:
        public_key_bytes = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
        user_public_key = serialization.load_pem_public_key(public_key_bytes)

        user_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = now + datetime.timedelta(days=days_valid)
        serial_number = x509.random_serial_number()
        is_rsa = isinstance(user_public_key, rsa.RSAPublicKey)

        eku_list = extended_key_usages or [
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.EMAIL_PROTECTION,
        ]

        builder = (
            x509.CertificateBuilder()
            .subject_name(user_subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(user_public_key)
            .serial_number(serial_number)
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(expires_at)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=is_rsa,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage(eku_list), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_cert.public_key()),
                critical=False,
            )
        )

        user_cert = builder.sign(self.ca_key, hashes.SHA256())
        cert_pem = user_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        serial_hex = format(serial_number, "X")

        return cert_pem, serial_hex, expires_at

    def validate_certificate(
        self,
        cert_pem: str | bytes,
        revoked_serials: Optional[Set[str] | List[str]] = None
    ) -> Tuple[bool, str, Dict[str, Any]]:
        revoked_set = set(revoked_serials or [])
        cert_bytes = cert_pem.encode("utf-8") if isinstance(cert_pem, str) else cert_pem

        try:
            cert = x509.load_pem_x509_certificate(cert_bytes)
        except Exception as e:
            return False, f"Помилка читання формату X.509: {e}", {}

        serial_hex = format(cert.serial_number, "X")
        now = datetime.datetime.now(datetime.timezone.utc)

        if now < cert.not_valid_before_utc:
            return False, "Сертифікат ще не набув чинності (not_valid_before).", {}
        if now > cert.not_valid_after_utc:
            return False, f"Термін дії сертифіката вичерпано ({cert.not_valid_after_utc.strftime('%Y-%m-%d')}).", {}

        if serial_hex in revoked_set or str(cert.serial_number) in revoked_set:
            return False, f"Сертифікат (Serial: {serial_hex}) АНУЛЬОВАНО/ВІДКЛИКАНО в системі!", {}

        try:
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except InvalidSignature:
            return False, "Недійсний підпис сертифіката! Сертифікат не видавався цим Центром сертифікації.", {}
        except Exception as e:
            return False, f"Помилка перевірки підпису сертифіката CA: {e}", {}

        pub_key_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn_value = common_name[0].value if common_name else "Unknown"

        details = {
            "serial_number": serial_hex,
            "subject": cn_value,
            "issuer": "EDS Local Root CA",
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "public_key_pem": pub_key_pem,
        }

        return True, "Сертифікат валідний і завірений Root CA.", details

    def generate_crl(
        self,
        revoked_items: List[Dict[str, Any]],
        days_valid: int = 7
    ) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca_cert.subject)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=days_valid))
        )

        for item in revoked_items:
            serial_raw = item["serial_number"]
            serial_int = int(serial_raw, 16) if isinstance(serial_raw, str) and not serial_raw.isdigit() else int(serial_raw)
            rev_date = item.get("revocation_date") or now

            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial_int)
                .revocation_date(rev_date)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(self.ca_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")


_ca_instance: Optional[CertificateAuthority] = None


def get_ca() -> CertificateAuthority:
    global _ca_instance
    if _ca_instance is None:
        _ca_instance = CertificateAuthority()
    return _ca_instance
