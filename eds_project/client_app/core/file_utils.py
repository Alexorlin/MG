import os
import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any


class FileUtils:
    """Утиліти для бінарного читання/запису файлів, ключів та JSON-контейнерів мультипідпису."""

    @staticmethod
    def read_file_bytes(file_path: str) -> bytes:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Файл не знайдено: {file_path}")

        with open(file_path, 'rb') as file:
            return file.read()

    @staticmethod
    def write_file_bytes(file_path: str, data: bytes) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, 'wb') as file:
            file.write(data)

    @staticmethod
    def save_key_to_file(file_path: str, key_pem: bytes | str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        data = key_pem.encode('utf-8') if isinstance(key_pem, str) else key_pem
        with open(file_path, 'wb') as file:
            file.write(data)

    @staticmethod
    def get_signature_path(original_file_path: str) -> str:
        return f"{original_file_path}.sig"

    @staticmethod
    def get_multisig_path(original_file_path: str) -> str:
        return f"{original_file_path}.multisig.json"

    @staticmethod
    def append_to_multisig_file(
        doc_bytes: bytes,
        multisig_path: str,
        signer_name: str,
        role: str,
        certificate_pem: str,
        signature_bytes: bytes,
        tsa_token_b64: Optional[str] = None
    ) -> Dict[str, Any]:
        doc_hash = hashlib.sha256(doc_bytes).hexdigest()

        if os.path.exists(multisig_path):
            with open(multisig_path, 'r', encoding='utf-8') as f:
                container = json.load(f)
            if container.get("document_hash", "").lower() != doc_hash.lower():
                raise ValueError("Хеш документа не збігається з існуючим контейнером мультипідпису!")
        else:
            container = {
                "version": "2.0",
                "hash_algorithm": "SHA-256",
                "document_hash": doc_hash,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "signatures": []
            }

        sig_entry = {
            "signer_name": signer_name,
            "role": role,
            "certificate_pem": certificate_pem,
            "signature_b64": base64.b64encode(signature_bytes).decode("ascii"),
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "tsa_token_b64": tsa_token_b64
        }

        container["signatures"].append(sig_entry)

        os.makedirs(os.path.dirname(os.path.abspath(multisig_path)), exist_ok=True)
        with open(multisig_path, 'w', encoding='utf-8') as f:
            json.dump(container, f, indent=2, ensure_ascii=False)

        return container
