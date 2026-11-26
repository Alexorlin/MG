import hashlib
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import Integer, String, Text, Boolean, DateTime, ForeignKey, BigInteger
from sqlalchemy.orm import relationship, Mapped, mapped_column
from .database import Base


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


class User(Base):
    """ORM-модель користувача та його сертифіката X.509."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    public_key_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    key_algorithm: Mapped[Optional[str]] = mapped_column(String(32), default="RSA-2048", nullable=True)
    certificate_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cert_serial: Mapped[Optional[str]] = mapped_column(String(64), unique=True, index=True, nullable=True)
    cert_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=_utc_now_naive)

    documents: Mapped[List["Document"]] = relationship("Document", back_populates="owner")
    signatures: Mapped[List["Signature"]] = relationship("Signature", back_populates="user")
    revocations: Mapped[List["CertificateRevocation"]] = relationship("CertificateRevocation", back_populates="user")


class Document(Base):
    """ORM-модель електронного документа та маршруту колективного підписання."""
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    file_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    file_size: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    uploaded_at: Mapped[Optional[datetime]] = mapped_column(DateTime, default=_utc_now_naive)
    owner_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"))
    allowed_signers: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    multisig_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    owner: Mapped[Optional["User"]] = relationship("User", back_populates="documents")
    signatures: Mapped[List["Signature"]] = relationship("Signature", back_populates="document")


class Signature(Base):
    """ORM-модель запису підпису в журналі аудиту (Hash Chain + TSA)."""
    __tablename__ = "signatures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    document_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("documents.id"))
    user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"))
    algorithm: Mapped[str] = mapped_column(String(32), default="RSA-2048", nullable=False)
    signature_data: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utc_now_naive, nullable=False)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), default="0" * 64, nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), index=True, default="", nullable=False)
    tsa_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tsa_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    document: Mapped[Optional["Document"]] = relationship("Document", back_populates="signatures")
    user: Mapped[Optional["User"]] = relationship("User", back_populates="signatures")

    def calculate_record_hash(self) -> str:
        ts_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else ""
        payload = (
            f"{self.prev_hash}:"
            f"{self.document_id}:"
            f"{self.user_id}:"
            f"{self.algorithm}:"
            f"{self.signature_data}:"
            f"{ts_str}:"
            f"{self.tsa_token or ''}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CertificateRevocation(Base):
    """ORM-модель списку відкликаних сертифікатів (CRL)."""
    __tablename__ = "certificate_revocations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    certificate_serial: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now_naive, nullable=False)
    reason: Mapped[str] = mapped_column(String(64), default="KeyCompromise", nullable=False)

    user: Mapped[Optional["User"]] = relationship("User", back_populates="revocations")
