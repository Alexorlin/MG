import base64
import json
import hashlib
from typing import Tuple, Optional, Set, List, Dict, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .ca_manager import get_ca, CertificateAuthority
from .tsa_service import get_tsa, TimeStampingAuthority


def get_key_algorithm_name(public_key) -> str:
    if isinstance(public_key, RSAPublicKey):
        return f"RSA-{public_key.key_size}"
    elif isinstance(public_key, EllipticCurvePublicKey):
        return f"ECDSA-{public_key.curve.name}"
    elif isinstance(public_key, Ed25519PublicKey):
        return "Ed25519"
    return "Unknown"


def verify_raw_signature(data: bytes, signature: bytes, public_key) -> bool:
    """Перевірка цифрового підпису для відкритих ключів RSA-PSS, ECDSA та Ed25519."""
    try:
        if isinstance(public_key, RSAPublicKey):
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        elif isinstance(public_key, EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        elif isinstance(public_key, Ed25519PublicKey):
            public_key.verify(signature, data)
            return True
        return False
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_signature(data: bytes, signature: bytes, public_pem: bytes | str) -> bool:
    try:
        pem_bytes = public_pem.encode("utf-8") if isinstance(public_pem, str) else public_pem
        public_key = serialization.load_pem_public_key(pem_bytes)
        return verify_raw_signature(data, signature, public_key)
    except Exception:
        return False


def verify_document_with_certificate(
    data: bytes,
    signature: bytes,
    certificate_pem: str | bytes,
    ca_instance: Optional[CertificateAuthority] = None,
    revoked_serials: Optional[Set[str] | List[str]] = None
) -> Tuple[bool, str, Dict[str, Any]]:
    """Перевірка підпису документа разом із валідацією сертифіката X.509 та статусу CRL."""
    ca = ca_instance or get_ca()

    is_cert_valid, cert_reason, cert_details = ca.validate_certificate(
        certificate_pem,
        revoked_serials=revoked_serials
    )

    if not is_cert_valid:
        return False, f"Сертифікат автора підпису недійсний: {cert_reason}", cert_details

    try:
        cert_bytes = certificate_pem.encode("utf-8") if isinstance(certificate_pem, str) else certificate_pem
        cert_obj = x509.load_pem_x509_certificate(cert_bytes)
        author_pub_key = cert_obj.public_key()
    except Exception as e:
        return False, f"Помилка читання відкритого ключа з сертифіката: {e}", cert_details

    is_sig_valid = verify_raw_signature(data, signature, author_pub_key)
    algo_name = get_key_algorithm_name(author_pub_key)
    cert_details["algorithm"] = algo_name

    if not is_sig_valid:
        return False, "Підпис документа недійсний або файл було змінено після підписання!", cert_details

    return True, f"✅ Підпис валідний. Автор: '{cert_details['subject']}' ({algo_name}), сертифікат завірений Root CA.", cert_details


def verify_multisignature(
    document_bytes: bytes,
    multisig_package: Dict[str, Any] | str,
    ca_instance: Optional[CertificateAuthority] = None,
    revoked_serials: Optional[Set[str] | List[str]] = None,
    tsa_instance: Optional[TimeStampingAuthority] = None
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """Верифікація контейнера колективного мультипідпису документа."""
    ca = ca_instance or get_ca()
    tsa = tsa_instance or get_tsa()

    if isinstance(multisig_package, str):
        try:
            package = json.loads(multisig_package)
        except Exception as e:
            return False, f"Помилка парсингу JSON контейнера мультипідпису: {e}", []
    else:
        package = multisig_package

    doc_hash = hashlib.sha256(document_bytes).hexdigest()
    expected_hash = package.get("document_hash")

    if expected_hash and doc_hash.lower() != expected_hash.lower():
        return False, f"КРИТИЧНО: Хеш документа ({doc_hash[:16]}...) не збігається з хешем у пакеті підписів ({expected_hash[:16]}...)!", []

    signatures_list = package.get("signatures", [])
    if not signatures_list:
        return False, "У пакеті мультипідпису відсутні підписи!", []

    reports = []
    all_signatures_valid = True

    for idx, sig_entry in enumerate(signatures_list, start=1):
        signer_name = sig_entry.get("signer_name", f"Signer #{idx}")
        role = sig_entry.get("role", "Participant")
        cert_pem = sig_entry.get("certificate_pem")
        sig_b64 = sig_entry.get("signature_b64")
        tsa_token_b64 = sig_entry.get("tsa_token_b64")

        report = {
            "index": idx,
            "signer_name": signer_name,
            "role": role,
            "is_valid": False,
            "reason": "",
            "tsa_verified": False,
            "timestamp": None
        }

        if not cert_pem or not sig_b64:
            report["reason"] = "Відсутній сертифікат або підпис."
            reports.append(report)
            all_signatures_valid = False
            continue

        try:
            sig_bytes = base64.b64decode(sig_b64)
        except Exception:
            report["reason"] = "Помилка декодування Base64 підпису."
            reports.append(report)
            all_signatures_valid = False
            continue

        is_val, reason, details = verify_document_with_certificate(
            data=document_bytes,
            signature=sig_bytes,
            certificate_pem=cert_pem,
            ca_instance=ca,
            revoked_serials=revoked_serials
        )

        report["is_valid"] = is_val
        report["reason"] = reason
        report["serial_number"] = details.get("serial_number")
        report["algorithm"] = details.get("algorithm")

        if tsa_token_b64:
            is_tsa_val, tsa_reason, tsa_info = tsa.verify_timestamp_token(tsa_token_b64, sig_bytes)
            report["tsa_verified"] = is_tsa_val
            report["tsa_reason"] = tsa_reason
            if is_tsa_val:
                report["timestamp"] = tsa_info.get("timestamp")

        if not is_val:
            all_signatures_valid = False

        reports.append(report)

    valid_count = sum(1 for r in reports if r["is_valid"])
    summary = f"Мультипідпис: {valid_count} з {len(reports)} підписів дійсні."
    if all_signatures_valid:
        summary = f"✅ УСПІХ: Всі {len(reports)} підписів колективного погодження валідні!"

    return all_signatures_valid, summary, reports
