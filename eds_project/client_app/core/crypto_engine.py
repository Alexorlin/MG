from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


class CryptoEngine:
    """Криптографічне ядро: генерація ключів, підпис та верифікація (RSA-PSS, ECDSA P-256, Ed25519)."""

    SUPPORTED_ALGORITHMS = ("RSA-2048", "RSA-4096", "ECDSA", "Ed25519")

    @classmethod
    def generate_key_pair(
        cls,
        algorithm: str = "RSA-2048",
        password: Optional[str | bytes] = None
    ) -> Tuple[bytes, bytes]:
        algo_normalized = algorithm.upper().strip()

        if algo_normalized == "RSA-2048":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif algo_normalized == "RSA-4096":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        elif algo_normalized in ("ECDSA", "ECDSA-P256", "SECP256R1"):
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif algo_normalized in ("ED25519", "EDWARDS25519"):
            private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(
                f"Непідтримуваний алгоритм: '{algorithm}'. "
                f"Доступні: {', '.join(cls.SUPPORTED_ALGORITHMS)}"
            )

        if password:
            pwd_bytes = password.encode("utf-8") if isinstance(password, str) else password
            encryption_algo = serialization.BestAvailableEncryption(pwd_bytes)
        else:
            encryption_algo = serialization.NoEncryption()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    @staticmethod
    def is_key_encrypted(private_pem: bytes) -> bool:
        try:
            serialization.load_pem_private_key(private_pem, password=None)
            return False
        except TypeError:
            return True
        except Exception:
            return False

    @staticmethod
    def load_private_key(private_pem: bytes, password: Optional[str | bytes] = None):
        pwd_bytes = None
        if password is not None:
            pwd_bytes = password.encode("utf-8") if isinstance(password, str) else password

        try:
            return serialization.load_pem_private_key(private_pem, password=pwd_bytes)
        except TypeError as e:
            raise ValueError("Приватний ключ зашифровано! Необхідно ввести PIN-код або пароль.") from e
        except ValueError as e:
            raise ValueError("Невірний PIN-код/пароль до закритого ключа або пошкоджений файл ключа.") from e

    @staticmethod
    def load_public_key(public_pem: bytes):
        try:
            return serialization.load_pem_public_key(public_pem)
        except Exception as e:
            raise ValueError(f"Помилка завантаження відкритого ключа: {e}") from e

    @classmethod
    def get_key_algorithm(cls, key_pem: bytes, password: Optional[str | bytes] = None) -> str:
        try:
            pub_key = cls.load_public_key(key_pem)
            if isinstance(pub_key, RSAPublicKey):
                return f"RSA-{pub_key.key_size}"
            elif isinstance(pub_key, EllipticCurvePublicKey):
                return f"ECDSA-{pub_key.curve.name}"
            elif isinstance(pub_key, Ed25519PublicKey):
                return "Ed25519"
        except Exception:
            pass

        priv_key = cls.load_private_key(key_pem, password=password)
        if isinstance(priv_key, RSAPrivateKey):
            return f"RSA-{priv_key.key_size}"
        elif isinstance(priv_key, EllipticCurvePrivateKey):
            return f"ECDSA-{priv_key.curve.name}"
        elif isinstance(priv_key, Ed25519PrivateKey):
            return "Ed25519"

        return "Unknown"

    @classmethod
    def sign_data(
        cls,
        data: bytes,
        private_pem: bytes,
        password: Optional[str | bytes] = None
    ) -> bytes:
        private_key = cls.load_private_key(private_pem, password=password)

        if isinstance(private_key, RSAPrivateKey):
            return private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(private_key, EllipticCurvePrivateKey):
            return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(private_key, Ed25519PrivateKey):
            return private_key.sign(data)
        else:
            raise TypeError(f"Непідтримуваний тип закритого ключа для підпису: {type(private_key).__name__}")

    @classmethod
    def verify_signature(
        cls,
        data: bytes,
        signature: bytes,
        public_pem: bytes
    ) -> bool:
        try:
            public_key = cls.load_public_key(public_pem)

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
