from typing import Tuple, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .models import Signature

GENESIS_HASH = "0" * 64


def get_latest_signature_hash(db: Session) -> str:
    last_sig = db.query(Signature).order_by(Signature.id.desc()).first()
    if last_sig and last_sig.record_hash:
        return last_sig.record_hash
    return GENESIS_HASH


def append_signature_to_chain(
    db: Session,
    document_id: int,
    user_id: int,
    signature_data: str,
    algorithm: str = "RSA-2048",
    is_valid: bool = True,
    tsa_token: Optional[str] = None,
    tsa_timestamp: Optional[datetime] = None
) -> Signature:
    """Додає новий запис підпису до геш-ланцюга аудиту із прив'язкою до попереднього блоку."""
    prev_hash = get_latest_signature_hash(db)
    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    tsa_ts_naive = tsa_timestamp.replace(tzinfo=None, microsecond=0) if tsa_timestamp else None

    new_sig = Signature(
        document_id=document_id,
        user_id=user_id,
        algorithm=algorithm,
        signature_data=signature_data,
        timestamp=now,
        is_valid=is_valid,
        prev_hash=prev_hash,
        tsa_token=tsa_token,
        tsa_timestamp=tsa_ts_naive
    )

    db.add(new_sig)
    db.flush()
    db.refresh(new_sig)

    new_sig.record_hash = new_sig.calculate_record_hash()
    db.commit()
    db.refresh(new_sig)

    return new_sig


def verify_chain_integrity(db: Session) -> Tuple[bool, str, Optional[int]]:
    """Перевіряє цілісність послідовності prev_hash та record_hash у таблиці signatures."""
    signatures = db.query(Signature).order_by(Signature.id.asc()).all()

    if not signatures:
        return True, "Журнал аудиту порожній. Цілісність не порушена.", None

    expected_prev = GENESIS_HASH

    for sig in signatures:
        if sig.prev_hash != expected_prev:
            return (
                False,
                f"КРИТИЧНО: Порушено зв'язок геш-ланцюжка на записі ID={sig.id}! "
                f"Очікувався prev_hash={expected_prev[:16]}..., а в базі={sig.prev_hash[:16]}...",
                sig.id
            )

        calculated_hash = sig.calculate_record_hash()
        if sig.record_hash != calculated_hash:
            return (
                False,
                f"КРИТИЧНО: Виявлено підміну даних усередині запису ID={sig.id}! "
                f"Хеш вмісту було змінено (модифікація підпису/часу/документа).",
                sig.id
            )

        expected_prev = sig.record_hash

    return True, f"Успіх: Всі {len(signatures)} записів аудит-логу верифіковані. Підмін не виявлено.", None
