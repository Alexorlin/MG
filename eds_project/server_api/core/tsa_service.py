import os
import json
import base64
import hashlib
import datetime
from typing import Tuple, Optional, Dict, Any
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

from .ca_manager import CertificateAuthority, get_ca


class TimeStampingAuthority:
    """Служба достовірних позначок часу TSA (за моделлю RFC 3161)."""

    TSA_POLICY_OID = "1.3.6.1.4.1.58557.1.1"

    def __init__(
        self,
        ca_instance: Optional[CertificateAuthority] = None,
        storage_dir: Optional[str] = None
    ):
        self.ca = ca_instance or get_ca()

        if storage_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            storage_dir = os.path.join(base_dir, "ca_storage", "tsa")

        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

        self.tsa_key_path = os.path.join(self.storage_dir, "tsa.key")
        self.tsa_cert_path = os.path.join(self.storage_dir, "tsa.crt")

        self.tsa_key = None
        self.tsa_cert = None
        self.tsa_cert_pem = None
        self._initialize_tsa()

    def _initialize_tsa(self):
        if os.path.exists(self.tsa_key_path) and os.path.exists(self.tsa_cert_path):
            with open(self.tsa_key_path, "rb") as f:
                self.tsa_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.tsa_cert_path, "rb") as f:
                cert_bytes = f.read()
                self.tsa_cert = x509.load_pem_x509_certificate(cert_bytes)
                self.tsa_cert_pem = cert_bytes.decode("utf-8")
        else:
            self._generate_tsa_credentials()

    def _generate_tsa_credentials(self):
        self.tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self.tsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        cert_pem, _, _ = self.ca.issue_user_certificate(
            username="EDS Official Time-Stamping Authority",
            public_key_pem=pub_pem,
            days_valid=1825,
            organization="EDS Document Management TSA Service",
            extended_key_usages=[ExtendedKeyUsageOID.TIME_STAMPING]
        )

        self.tsa_cert_pem = cert_pem
        self.tsa_cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

        with open(self.tsa_key_path, "wb") as f:
            f.write(self.tsa_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(self.tsa_cert_path, "wb") as f:
            f.write(cert_pem.encode("utf-8"))

    @staticmethod
    def _normalize_imprint(data_or_hash: bytes | str) -> str:
        if isinstance(data_or_hash, str):
            if len(data_or_hash) == 64 and all(c in "0123456789abcdefABCDEF" for c in data_or_hash):
                return data_or_hash.lower()
            data_bytes = data_or_hash.encode("utf-8")
        else:
            data_bytes = data_or_hash

        return hashlib.sha256(data_bytes).hexdigest()

    def create_timestamp_token(
        self,
        data_or_hash: bytes | str
    ) -> Tuple[str, datetime.datetime, int]:
        imprint_hex = self._normalize_imprint(data_or_hash)
        now = datetime.datetime.now(datetime.timezone.utc)
        serial_number = int(datetime.datetime.now().timestamp() * 1000)

        tst_info = {
            "version": 1,
            "policy": self.TSA_POLICY_OID,
            "hash_algorithm": "SHA-256",
            "message_imprint": imprint_hex,
            "serial_number": serial_number,
            "gen_time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "accuracy": {"seconds": 1, "millis": 0, "micros": 0},
            "ordering": True,
            "tsa_name": "EDS Official Time-Stamping Authority"
        }

        canonical_bytes = json.dumps(tst_info, sort_keys=True, separators=(",", ":")).encode("utf-8")

        signature = self.tsa_key.sign(
            canonical_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        token_package = {
            "tst_info": tst_info,
            "signature": base64.b64encode(signature).decode("ascii"),
            "tsa_cert": self.tsa_cert_pem
        }

        token_json = json.dumps(token_package, sort_keys=True)
        token_b64 = base64.b64encode(token_json.encode("utf-8")).decode("ascii")

        return token_b64, now, serial_number

    def verify_timestamp_token(
        self,
        token_b64: str,
        data_or_hash: bytes | str
    ) -> Tuple[bool, str, Dict[str, Any]]:
        try:
            raw_json = base64.b64decode(token_b64.encode("ascii")).decode("utf-8")
            token_package = json.loads(raw_json)
            tst_info = token_package["tst_info"]
            sig_bytes = base64.b64decode(token_package["signature"].encode("ascii"))
            cert_pem = token_package["tsa_cert"]
        except Exception as e:
            return False, f"Помилка структури токена TSA: {e}", {}

        is_cert_valid, cert_reason, _ = self.ca.validate_certificate(cert_pem)
        if not is_cert_valid:
            return False, f"Сертифікат служби часу (TSA) недійсний: {cert_reason}", {}

        tsa_cert_obj = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        try:
            eku = tsa_cert_obj.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE).value
            if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
                return False, "Сертифікат не має призначення TIME_STAMPING!", {}
        except Exception:
            return False, "Відсутнє розширення ExtendedKeyUsage у сертифікаті TSA!", {}

        canonical_bytes = json.dumps(tst_info, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            tsa_public_key = tsa_cert_obj.public_key()
            tsa_public_key.verify(
                sig_bytes,
                canonical_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False, "Недійсний цифровий підпис служби TSA!", {}
        except Exception as e:
            return False, f"Помилка верифікації підпису TSA: {e}", {}

        expected_imprint = self._normalize_imprint(data_or_hash)
        actual_imprint = tst_info.get("message_imprint", "").lower()
        if expected_imprint != actual_imprint:
            return (
                False,
                f"Невідповідність хешу документа! Очікувався {expected_imprint[:16]}..., а в мітці {actual_imprint[:16]}...",
                {}
            )

        details = {
            "timestamp": tst_info.get("gen_time"),
            "serial_number": tst_info.get("serial_number"),
            "tsa_name": tst_info.get("tsa_name"),
            "policy": tst_info.get("policy"),
            "imprint": actual_imprint
        }

        return True, "Криптографічний штамп часу дійсний та завірений TSA.", details


_tsa_instance: Optional[TimeStampingAuthority] = None


def get_tsa() -> TimeStampingAuthority:
    global _tsa_instance
    if _tsa_instance is None:
        _tsa_instance = TimeStampingAuthority()
    return _tsa_instance
