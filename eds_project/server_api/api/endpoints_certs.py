from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from pydantic import BaseModel

from db import models
from core.ca_manager import get_ca
from api.endpoints_auth import get_current_user, get_db

router = APIRouter(prefix="/certs", tags=["Центр сертифікації (X.509 PKI)"])


class RevokeRequest(BaseModel):
    serial_number: str
    reason: Optional[str] = "KeyCompromise"


@router.get("/ca.crt", summary="Завантажити публічний кореневий сертифікат Root CA")
def get_root_ca_certificate():
    """Повертає кореневий сертифікат Root CA у форматі PEM."""
    ca = get_ca()
    pem_str = ca.get_root_certificate_pem()
    return Response(
        content=pem_str,
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=eds_root_ca.crt"}
    )


@router.get("/my-certificate", summary="Отримати власний сертифікат X.509")
def get_my_certificate(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Повертає поточний сертифікат X.509 авторизованого користувача та його статус у CRL."""
    if not current_user.certificate_pem:
        raise HTTPException(
            status_code=404,
            detail="Сертифікат ще не згенеровано. Надішліть відкритий ключ на /certs/issue"
        )

    is_revoked = False
    revocation = None
    if current_user.cert_serial:
        revocation = db.query(models.CertificateRevocation).filter(
            models.CertificateRevocation.certificate_serial == current_user.cert_serial
        ).first()
        is_revoked = revocation is not None

    return {
        "username": current_user.username,
        "serial_number": current_user.cert_serial,
        "certificate_pem": current_user.certificate_pem,
        "expires_at": current_user.cert_expires_at,
        "is_revoked": is_revoked,
        "revocation_reason": revocation.reason if revocation else None
    }


@router.post("/issue", tags=["Admin"], summary="Адміністративний перевипуск сертифіката X.509")
def issue_certificate_for_user(
    username: str,
    db: Session = Depends(get_db)
):
    """Випуск або перевипуск сертифіката X.509 для вказаного користувача адміністратором CA."""
    target_user = db.query(models.User).filter(models.User.username == username).first()
    if not target_user:
        raise HTTPException(
            status_code=404,
            detail=f"Користувача з логіном '{username}' не знайдено в базі даних."
        )

    if not target_user.public_key_pem:
        raise HTTPException(
            status_code=400,
            detail=f"У профілі користувача '{username}' відсутній відкритий ключ!"
        )

    ca = get_ca()
    try:
        cert_pem, serial_hex, expires_at = ca.issue_user_certificate(
            username=target_user.username,
            public_key_pem=target_user.public_key_pem,
            days_valid=365
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка випуску сертифіката: {e}")

    target_user.certificate_pem = cert_pem
    target_user.cert_serial = serial_hex
    target_user.cert_expires_at = expires_at.replace(tzinfo=None, microsecond=0) if expires_at else None

    db.commit()
    db.refresh(target_user)

    return {
        "status": "success",
        "message": f"✅ Сертифікат X.509 для користувача '{username}' успішно перевипущено адміністратором Root CA!",
        "username": target_user.username,
        "serial_number": serial_hex,
        "expires_at": expires_at.isoformat(),
        "certificate_pem": cert_pem
    }


@router.post("/revoke", summary="Відкликати скомпрометований сертифікат (CRL)")
def revoke_certificate(
    request: RevokeRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Анулювання сертифіката та внесення його серійного номера до реєстру CRL."""
    user_with_cert = db.query(models.User).filter(models.User.cert_serial == request.serial_number).first()
    if not user_with_cert:
        raise HTTPException(status_code=404, detail="Сертифікат з таким серійним номером не знайдено.")

    if user_with_cert.id != current_user.id:
        raise HTTPException(status_code=403, detail="Ви можете відкликати лише власний сертифікат!")

    existing = db.query(models.CertificateRevocation).filter(
        models.CertificateRevocation.certificate_serial == request.serial_number
    ).first()

    if existing:
        return {"status": "already_revoked", "message": "Сертифікат уже було відкликано раніше."}

    revocation = models.CertificateRevocation(
        certificate_serial=request.serial_number,
        user_id=current_user.id,
        revoked_at=datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0),
        reason=request.reason or "KeyCompromise"
    )
    db.add(revocation)
    db.commit()

    return {
        "status": "revoked",
        "message": f"🚨 Сертифікат {request.serial_number} успішно АНУЛЬОВАНО!",
        "reason": revocation.reason,
        "revoked_at": revocation.revoked_at.isoformat()
    }


@router.get("/crl", summary="Отримати офіційний список відкликаних сертифікатів (CRL)")
def get_crl(db: Session = Depends(get_db)):
    """Формує підписаний Root CA список відкликаних сертифікатів згідно з RFC 5280."""
    ca = get_ca()
    revocations = db.query(models.CertificateRevocation).all()

    revoked_items = [
        {"serial_number": r.certificate_serial, "revocation_date": r.revoked_at, "reason": r.reason}
        for r in revocations
    ]

    crl_pem = ca.generate_crl(revoked_items)
    return Response(
        content=crl_pem,
        media_type="application/pkix-crl",
        headers={"Content-Disposition": "attachment; filename=eds.crl"}
    )


@router.get("/status/{serial_number}", summary="Перевірити статус валідності сертифіката")
def check_certificate_status(serial_number: str, db: Session = Depends(get_db)):
    """Перевірка статусу сертифіката за серійним номером."""
    revocation = db.query(models.CertificateRevocation).filter(
        models.CertificateRevocation.certificate_serial == serial_number
    ).first()

    if revocation:
        return {
            "serial_number": serial_number,
            "status": "REVOKED",
            "is_valid": False,
            "revoked_at": revocation.revoked_at.isoformat(),
            "reason": revocation.reason
        }

    user = db.query(models.User).filter(models.User.cert_serial == serial_number).first()
    if not user:
        return {"serial_number": serial_number, "status": "NOT_FOUND", "is_valid": False}

    now = datetime.now(timezone.utc)
    if user.cert_expires_at and now > user.cert_expires_at.replace(tzinfo=timezone.utc):
        return {"serial_number": serial_number, "status": "EXPIRED", "is_valid": False}

    return {
        "serial_number": serial_number,
        "status": "ACTIVE",
        "is_valid": True,
        "owner": user.username,
        "expires_at": user.cert_expires_at.isoformat() if user.cert_expires_at else None
    }
