import os
import json
import base64
import hashlib
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from db.database import auto_migrate_schema
from db import models
from db.hash_chain import GENESIS_HASH, append_signature_to_chain, verify_chain_integrity
from core.verify_logic import verify_signature, verify_document_with_certificate, verify_multisignature
from core.tsa_service import get_tsa
from core.ca_manager import get_ca
from api.endpoints_auth import get_current_user, get_db

router = APIRouter(prefix="/docs", tags=["Документи, Підпис та Аудит"])


@router.post("/verify-and-save", summary="Перевірити підпис, отримати штамп TSA та зберегти в геш-ланцюг")
async def verify_and_save_document(
    file: UploadFile = File(...),
    signature_file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Верифікація відокремленого ЕЦП, формування позначки часу TSA та запис у геш-ланцюг БД."""
    doc_bytes = await file.read()
    sig_bytes = await signature_file.read()

    if not current_user.public_key_pem:
        raise HTTPException(status_code=400, detail="У вашому профілі відсутній відкритий ключ!")

    if current_user.cert_serial:
        revocation = db.query(models.CertificateRevocation).filter(
            models.CertificateRevocation.certificate_serial == current_user.cert_serial
        ).first()
        if revocation:
            raise HTTPException(
                status_code=400,
                detail=f"🚨 ВАШ СЕРТИФІКАТ (Serial: {current_user.cert_serial}) АНУЛЬОВАНО/ВІДКЛИКАНО ({revocation.reason})! Підписання заблоковано."
            )

    is_valid = verify_signature(doc_bytes, sig_bytes, current_user.public_key_pem)
    if not is_valid:
        raise HTTPException(status_code=400, detail="❌ ПІДПИС НЕДІЙСНИЙ або документ було змінено після підписання!")

    file_hash = hashlib.sha256(doc_bytes).hexdigest()
    sig_b64 = base64.b64encode(sig_bytes).decode('utf-8')
    algo = current_user.key_algorithm or "RSA-2048"
    tsa = get_tsa()

    db_doc = db.query(models.Document).filter(models.Document.file_hash == file_hash).first()

    if db_doc:
        existing_sig = db.query(models.Signature).filter(
            models.Signature.document_id == db_doc.id,
            models.Signature.user_id == current_user.id
        ).order_by(models.Signature.id.asc()).first()

        if existing_sig:
            if existing_sig.record_hash != existing_sig.calculate_record_hash():
                raise HTTPException(
                    status_code=400,
                    detail=f"🚨 ТРИВОГА БЕЗПЕКИ: Виявлено несанкціоновану модифікацію запису ID={existing_sig.id} у базі даних!"
                )

            orig_tsa_time = (
                existing_sig.tsa_timestamp.isoformat()
                if existing_sig.tsa_timestamp
                else (existing_sig.timestamp.isoformat() if existing_sig.timestamp else "")
            )
            return {
                "status": "already_verified",
                "message": (
                    f"✅ Документ '{file.filename}' ВЖЕ ЗАРЕЄСТРОВАНО в БД (Запис ID=#{existing_sig.id})!\n"
                    f"Новий запис не створювався — відображено первинний незмінний штамп часу затвердження."
                ),
                "document_id": db_doc.id,
                "signature_id": existing_sig.id,
                "algorithm": existing_sig.algorithm or algo,
                "record_hash": existing_sig.record_hash,
                "prev_hash": existing_sig.prev_hash,
                "tsa_timestamp": orig_tsa_time
            }

    tsa_token_b64, tsa_dt, _ = tsa.create_timestamp_token(sig_bytes)

    if not db_doc:
        db_doc = models.Document(
            filename=file.filename,
            file_hash=file_hash,
            file_size=len(doc_bytes),
            owner_id=current_user.id
        )
        db.add(db_doc)
        db.commit()
        db.refresh(db_doc)

    upload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, f"{db_doc.id}_{db_doc.filename}")
    if not os.path.exists(file_path):
        with open(file_path, "wb") as buffer:
            buffer.write(doc_bytes)

    new_sig = append_signature_to_chain(
        db=db,
        document_id=db_doc.id,
        user_id=current_user.id,
        signature_data=sig_b64,
        algorithm=algo,
        is_valid=True,
        tsa_token=tsa_token_b64,
        tsa_timestamp=tsa_dt
    )

    return {
        "status": "success",
        "message": f"✅ Документ '{file.filename}' вперше перевірено, засвідчено TSA та збережено в ланцюг аудиту!",
        "document_id": db_doc.id,
        "signature_id": new_sig.id,
        "algorithm": algo,
        "record_hash": new_sig.record_hash,
        "prev_hash": new_sig.prev_hash,
        "tsa_timestamp": tsa_dt.isoformat()
    }


@router.post("/multisig/sign", summary="Додати підпис до централізованого мультипідпису в БД (ACL)")
async def sign_multisig_on_server(
    file: UploadFile = File(...),
    signature_b64: str = Form(...),
    certificate_pem: str = Form(...),
    role: str = Form("Автор документа"),
    allowed_signers: Optional[str] = Form(None),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Додавання підпису учасника до колективного мультипідпису документа з перевіркою ACL, X.509 та CRL."""
    doc_bytes = await file.read()
    try:
        sig_bytes = base64.b64decode(signature_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Некоректний формат підпису Base64.")

    file_hash = hashlib.sha256(doc_bytes).hexdigest()
    try:
        db_doc = db.query(models.Document).filter(models.Document.file_hash == file_hash).first()
    except Exception:
        db.rollback()
        auto_migrate_schema()
        db_doc = db.query(models.Document).filter(models.Document.file_hash == file_hash).first()

    extra_signers = []
    if allowed_signers:
        for raw_name in allowed_signers.replace(";", ",").split(","):
            clean_name = raw_name.strip()
            if clean_name:
                extra_signers.append(clean_name)

    if db_doc and db_doc.allowed_signers:
        allowed_list = [x.strip() for x in db_doc.allowed_signers.split(",") if x.strip()]
        if db_doc.owner_id != current_user.id and current_user.username.lower() not in [x.lower() for x in allowed_list]:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"⛔ ВІДМОВА ДОСТУПУ (ACL): Автор документа дозволив мультипідпис лише для: "
                    f"[{', '.join(allowed_list)}]. Користувач '{current_user.username}' не включений до маршруту погодження!"
                )
            )

    revocations = db.query(models.CertificateRevocation.certificate_serial).all()
    revoked_set = {r[0] for r in revocations}

    ca = get_ca()
    tsa = get_tsa()
    active_cert_pem = certificate_pem
    if current_user.certificate_pem and current_user.cert_serial not in revoked_set:
        is_valid_test, _, _ = verify_document_with_certificate(
            data=doc_bytes,
            signature=sig_bytes,
            certificate_pem=certificate_pem,
            ca_instance=ca,
            revoked_serials=revoked_set
        )
        if not is_valid_test:
            active_cert_pem = current_user.certificate_pem

    is_valid, msg, details = verify_document_with_certificate(
        data=doc_bytes,
        signature=sig_bytes,
        certificate_pem=active_cert_pem,
        ca_instance=ca,
        revoked_serials=revoked_set
    )
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    cert_owner = details.get("subject", "")
    if cert_owner and cert_owner.lower() != current_user.username.lower():
        raise HTTPException(
            status_code=403,
            detail=f"⛔ Сертифікат X.509 належить '{cert_owner}', а ви авторизовані як '{current_user.username}'!"
        )

    if not db_doc:
        signers_list = [current_user.username]
        for s_name in extra_signers:
            if s_name.lower() not in [x.lower() for x in signers_list]:
                signers_list.append(s_name)

        db_doc = models.Document(
            filename=file.filename,
            file_hash=file_hash,
            file_size=len(doc_bytes),
            owner_id=current_user.id,
            allowed_signers=",".join(signers_list)
        )
        db.add(db_doc)
        db.commit()
        db.refresh(db_doc)
    else:
        if db_doc.allowed_signers:
            allowed_list = [x.strip() for x in db_doc.allowed_signers.split(",") if x.strip()]
            if db_doc.owner_id == current_user.id and extra_signers:
                for s_name in extra_signers:
                    if s_name.lower() not in [x.lower() for x in allowed_list]:
                        allowed_list.append(s_name)
                db_doc.allowed_signers = ",".join(allowed_list)

            if current_user.username.lower() not in [x.lower() for x in allowed_list]:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"⛔ ВІДМОВА ДОСТУПУ (ACL): Автор документа дозволив мультипідпис лише для: "
                        f"[{', '.join(allowed_list)}]. Користувач '{current_user.username}' не включений до маршруту погодження!"
                    )
                )
        else:
            signers_list = [current_user.username]
            for s_name in extra_signers:
                if s_name.lower() not in [x.lower() for x in signers_list]:
                    signers_list.append(s_name)
            db_doc.allowed_signers = ",".join(signers_list)

    upload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, f"{db_doc.id}_{db_doc.filename}")
    if not os.path.exists(file_path):
        with open(file_path, "wb") as buffer:
            buffer.write(doc_bytes)

    tsa_token_b64, tsa_dt, _ = tsa.create_timestamp_token(sig_bytes)

    container = None
    if db_doc.multisig_json:
        try:
            container = json.loads(db_doc.multisig_json)
        except Exception:
            container = None

    if not container or not isinstance(container, dict):
        container = {
            "version": "2.0",
            "hash_algorithm": "SHA-256",
            "document_hash": file_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "allowed_signers": [x.strip() for x in (db_doc.allowed_signers or "").split(",") if x.strip()],
            "signatures": []
        }
    else:
        container["allowed_signers"] = [x.strip() for x in (db_doc.allowed_signers or "").split(",") if x.strip()]

    new_sig_entry = {
        "signer_name": current_user.username,
        "role": role,
        "certificate_pem": active_cert_pem,
        "signature_b64": signature_b64,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "tsa_token_b64": tsa_token_b64
    }

    existing_sigs = container.get("signatures", [])
    already_signed = any(item.get("signer_name", "").lower() == current_user.username.lower() for item in existing_sigs)

    if not already_signed:
        existing_sigs.append(new_sig_entry)
        container["signatures"] = existing_sigs

    db_doc.multisig_json = json.dumps(container, indent=2, ensure_ascii=False)
    db.commit()
    db.refresh(db_doc)

    algo = details.get("algorithm") or current_user.key_algorithm or "RSA-2048"
    existing_chain_sig = db.query(models.Signature).filter(
        models.Signature.document_id == db_doc.id,
        models.Signature.user_id == current_user.id
    ).order_by(models.Signature.id.asc()).first()

    if existing_chain_sig:
        chain_sig = existing_chain_sig
    else:
        chain_sig = append_signature_to_chain(
            db=db,
            document_id=db_doc.id,
            user_id=current_user.id,
            signature_data=signature_b64,
            algorithm=f"{algo} (MultiSig)",
            is_valid=True,
            tsa_token=tsa_token_b64,
            tsa_timestamp=tsa_dt
        )

    allowed_all = [x.strip() for x in (db_doc.allowed_signers or "").split(",") if x.strip()]
    signed_users = [s.get("signer_name", "") for s in existing_sigs]
    pending_users = [u for u in allowed_all if u.lower() not in [su.lower() for su in signed_users]]

    return {
        "status": "success",
        "message": f"✅ Мультипідпис ({current_user.username} — {role}) перевірено через Root CA, засвідчено TSA та збережено в БД!",
        "document_id": db_doc.id,
        "signature_id": chain_sig.id,
        "total_signatures": len(existing_sigs),
        "signed_users": signed_users,
        "allowed_signers": allowed_all,
        "pending_signers": pending_users,
        "multisig_container": container
    }


@router.post("/verify-multisig", summary="Перевірити пакет колективного погодження")
async def verify_multisig_endpoint(
    file: UploadFile = File(...),
    multisig_file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    """Комплексна перевірка всіх підписів колективного погодження документа."""
    doc_bytes = await file.read()
    file_hash = hashlib.sha256(doc_bytes).hexdigest()

    db_doc = db.query(models.Document).filter(models.Document.file_hash == file_hash).first()

    multisig_raw = None
    if multisig_file is not None:
        raw_bytes = await multisig_file.read()
        if raw_bytes:
            multisig_raw = raw_bytes.decode("utf-8", errors="ignore")

    if db_doc and db_doc.multisig_json:
        if not multisig_raw:
            multisig_raw = db_doc.multisig_json
        else:
            try:
                local_cnt = len(json.loads(multisig_raw).get("signatures", []))
                db_cnt = len(json.loads(db_doc.multisig_json).get("signatures", []))
                if db_cnt >= local_cnt:
                    multisig_raw = db_doc.multisig_json
            except Exception:
                multisig_raw = db_doc.multisig_json

    if not multisig_raw:
        raise HTTPException(
            status_code=404,
            detail="Для цього документа ще не створено мультипідпису в БД і не передано файл .multisig.json."
        )

    revocations = db.query(models.CertificateRevocation.certificate_serial).all()
    revoked_set = {r[0] for r in revocations}

    all_valid, summary, reports = verify_multisignature(
        document_bytes=doc_bytes,
        multisig_package=multisig_raw,
        ca_instance=get_ca(),
        revoked_serials=revoked_set,
        tsa_instance=get_tsa()
    )

    allowed_all = []
    pending_users = []
    if db_doc and db_doc.allowed_signers:
        allowed_all = [x.strip() for x in db_doc.allowed_signers.split(",") if x.strip()]
        signed_names = [r.get("signer_name", "") for r in reports]
        pending_users = [u for u in allowed_all if u.lower() not in [sn.lower() for sn in signed_names]]
        if pending_users:
            summary += f" | ⏳ Очікується підпис від: {', '.join(pending_users)}"
        elif allowed_all:
            summary += f" | 🎉 Маршрут погодження виконано повністю ({len(reports)}/{len(allowed_all)})!"

    return {
        "all_valid": all_valid,
        "summary": summary,
        "reports": reports,
        "allowed_signers": allowed_all,
        "pending_signers": pending_users
    }


@router.get("/audit/verify-chain", summary="Перевірити цілісність журналу аудиту (Hash Chain)")
def audit_verify_chain(db: Session = Depends(get_db)):
    """Послідовна перевірка цілісності криптографічного геш-ланцюга записів у таблиці signatures."""
    is_valid, message, broken_id = verify_chain_integrity(db)
    return {
        "is_valid": is_valid,
        "message": message,
        "broken_record_id": broken_id
    }


@router.get("/my-documents", summary="Список документів користувача та призначених на мультипідпис")
def get_my_documents(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Повертає документи власника та документи, де користувача включено до списку співпідписантів."""
    all_docs = db.query(models.Document).order_by(models.Document.id.desc()).all()
    result = []
    for doc in all_docs:
        allowed_list = [x.strip() for x in (doc.allowed_signers or "").split(",") if x.strip()]
        is_owner = (doc.owner_id == current_user.id)
        is_allowed_cosigner = current_user.username.lower() in [x.lower() for x in allowed_list]

        if not (is_owner or is_allowed_cosigner):
            continue

        status_str = "✅ Перевірено"
        if doc.multisig_json:
            try:
                container = json.loads(doc.multisig_json)
                sigs = container.get("signatures", [])
                signed_names = [s.get("signer_name", "") for s in sigs]
                total_expected = max(len(allowed_list), len(signed_names))
                if current_user.username.lower() not in [sn.lower() for sn in signed_names]:
                    status_str = f"⏳ Очікує вашого мультипідпису ({len(signed_names)}/{total_expected}): {', '.join(signed_names)}"
                else:
                    status_str = f"🤝 Мультипідпис ({len(signed_names)}/{total_expected}): {', '.join(signed_names)}"
            except Exception:
                pass

        result.append({
            "id": doc.id,
            "filename": doc.filename,
            "uploaded_at": doc.uploaded_at.strftime("%d.%m.%Y %H:%M") if doc.uploaded_at else "Невідомо",
            "file_size": doc.file_size,
            "status": status_str
        })
    return result


@router.delete("/{doc_id}", summary="Видалити документ")
def delete_document(
    doc_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Видалення документа власником та оновлення геш-ланцюга."""
    doc = db.query(models.Document).filter(
        models.Document.id == doc_id,
        models.Document.owner_id == current_user.id
    ).first()

    if not doc:
        raise HTTPException(status_code=404, detail="Документ не знайдено або немає доступу.")

    db.query(models.Signature).filter(models.Signature.document_id == doc_id).delete()
    db.delete(doc)
    db.flush()

    remaining_sigs = db.query(models.Signature).order_by(models.Signature.id.asc()).all()
    prev = GENESIS_HASH
    for s in remaining_sigs:
        s.prev_hash = prev
        s.record_hash = s.calculate_record_hash()
        prev = s.record_hash

    db.commit()

    upload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
    file_path = os.path.join(upload_dir, f"{doc.id}_{doc.filename}")
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception:
            pass

    return {"message": "Документ успішно видалено."}


@router.get("/download/{doc_id}", summary="Завантажити документ")
def download_document(
    doc_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Завантаження файлу документа власником або співпідписантом."""
    doc = db.query(models.Document).filter(models.Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Документ не знайдено.")

    allowed_list = [x.strip().lower() for x in (doc.allowed_signers or "").split(",") if x.strip()]
    if doc.owner_id != current_user.id and current_user.username.lower() not in allowed_list:
        raise HTTPException(status_code=403, detail="У вас немає доступу до цього документа.")

    upload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
    file_path = os.path.join(upload_dir, f"{doc.id}_{doc.filename}")

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Файл відсутній на сервері.")

    return FileResponse(path=file_path, filename=doc.filename, media_type="application/octet-stream")
