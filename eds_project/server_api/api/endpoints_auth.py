from typing import Optional
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization

from db import models
from db.database import SessionLocal
from db.hash_chain import GENESIS_HASH
from core import security
from core.ca_manager import get_ca
from core.verify_logic import get_key_algorithm_name

router = APIRouter(prefix="/auth", tags=["Автентифікація та Користувачі"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


class UserCreate(BaseModel):
    username: str
    password: str
    public_key_pem: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> models.User:
    try:
        payload = jwt.decode(token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Невалідний токен автентифікації")
    except Exception:
        raise HTTPException(status_code=401, detail="Невалідний або прострочений токен")

    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Користувача не знайдено")
    return user


@router.post("/register", status_code=status.HTTP_201_CREATED, summary="Реєстрація нового користувача та випуск X.509")
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """Реєстрація облікового запису та автоматичний випуск персонального X.509 сертифіката."""
    db_user = db.query(models.User).filter(models.User.username == user_data.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Користувач з таким логіном вже існує")

    hashed_pwd = security.get_password_hash(user_data.password)

    cert_pem = None
    serial_hex = None
    expires_at = None
    algo = "RSA-2048"

    if user_data.public_key_pem:
        try:
            pub_key = serialization.load_pem_public_key(user_data.public_key_pem.encode('utf-8'))
            algo = get_key_algorithm_name(pub_key)
            ca = get_ca()
            cert_pem, serial_hex, expires_at = ca.issue_user_certificate(
                username=user_data.username,
                public_key_pem=user_data.public_key_pem,
                days_valid=365
            )
        except Exception:
            pass

    new_user = models.User(
        username=user_data.username,
        password_hash=hashed_pwd,
        public_key_pem=user_data.public_key_pem,
        key_algorithm=algo,
        certificate_pem=cert_pem,
        cert_serial=serial_hex,
        cert_expires_at=expires_at.replace(tzinfo=None, microsecond=0) if expires_at else None
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "status": "success",
        "message": "Користувача успішно зареєстровано",
        "user_id": new_user.id,
        "key_algorithm": algo,
        "cert_serial": serial_hex
    }


@router.post("/login", response_model=Token, summary="Авторизація та отримання JWT токена")
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Перевірка облікових даних та видача JWT токена доступу."""
    user = db.query(models.User).filter(models.User.username == form_data.username).first()

    if not user or not security.verify_password(form_data.password, str(user.password_hash)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невірний логін або пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = security.create_access_token(data={"sub": str(user.username)})
    return {"access_token": access_token, "token_type": "bearer"}


@router.delete("/users/{user_id}", tags=["Admin"], summary="Видалення користувача")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    """Адміністративне видалення користувача та пов'язаних записів із перерахунком геш-ланцюга."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Користувача не знайдено")

    user_docs = db.query(models.Document.id).filter(models.Document.owner_id == user_id).all()
    user_doc_ids = [d[0] for d in user_docs]

    if user_doc_ids:
        db.query(models.Signature).filter(models.Signature.document_id.in_(user_doc_ids)).delete(synchronize_session=False)

    db.query(models.Signature).filter(models.Signature.user_id == user_id).delete(synchronize_session=False)
    db.query(models.Document).filter(models.Document.owner_id == user_id).delete(synchronize_session=False)
    db.query(models.CertificateRevocation).filter(models.CertificateRevocation.user_id == user_id).delete(synchronize_session=False)

    db.delete(user)
    db.flush()

    remaining_sigs = db.query(models.Signature).order_by(models.Signature.id.asc()).all()
    prev = GENESIS_HASH
    for s in remaining_sigs:
        s.prev_hash = prev
        s.record_hash = s.calculate_record_hash()
        prev = s.record_hash

    db.commit()

    return {"message": f"Користувача з ID {user_id} та всі його дані успішно видалено, геш-ланцюг оновлено."}
