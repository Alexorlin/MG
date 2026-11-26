import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

_DB_PASSWORD = os.environ.get("EDS_DB_PASSWORD", "")
_DEFAULT_DB_URL = f"postgresql://postgres:{_DB_PASSWORD}@localhost:5432/eds_db"
SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL", _DEFAULT_DB_URL)

connect_args = {"check_same_thread": False} if "sqlite" in SQLALCHEMY_DATABASE_URL else {}

try:
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=connect_args)
    with engine.connect():
        pass
except Exception:
    SQLALCHEMY_DATABASE_URL = "sqlite:///eds_local.db"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
    print("\n[INFO] Служба PostgreSQL недоступна. Використовується локальна база eds_local.db\n")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def auto_migrate_schema():
    """Перевірка та синхронізація схеми таблиць бази даних."""
    migrations = [
        ("users", "key_algorithm", "VARCHAR(32) DEFAULT 'RSA-2048'"),
        ("users", "certificate_pem", "TEXT"),
        ("users", "cert_serial", "VARCHAR(64)"),
        ("users", "cert_expires_at", "TIMESTAMP"),
        ("users", "created_at", "TIMESTAMP"),
        ("documents", "file_size", "BIGINT"),
        ("documents", "allowed_signers", "TEXT"),
        ("documents", "multisig_json", "TEXT"),
        ("signatures", "algorithm", "VARCHAR(32) DEFAULT 'RSA-2048'"),
        ("signatures", "prev_hash", "VARCHAR(64) DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'"),
        ("signatures", "record_hash", "VARCHAR(64) DEFAULT ''"),
        ("signatures", "tsa_token", "TEXT"),
        ("signatures", "tsa_timestamp", "TIMESTAMP"),
    ]

    try:
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        table_cols = {
            t: {c["name"] for c in inspector.get_columns(t)}
            for t in existing_tables
        }

        for table_name, col_name, col_type in migrations:
            if table_name in existing_tables and col_name not in table_cols.get(table_name, set()):
                try:
                    with engine.begin() as conn:
                        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}"))
                    table_cols[table_name].add(col_name)
                except Exception:
                    pass
    except Exception:
        pass

    try:
        from .models import Signature
        from .hash_chain import GENESIS_HASH, verify_chain_integrity

        db = SessionLocal()
        try:
            sigs = db.query(Signature).order_by(Signature.id.asc()).all()
            seen_pairs = set()
            removed_dups = False
            kept_sigs = []
            for s in sigs:
                pair_key = (s.document_id, s.user_id)
                if s.document_id is not None and s.user_id is not None and pair_key in seen_pairs:
                    db.delete(s)
                    removed_dups = True
                else:
                    seen_pairs.add(pair_key)
                    kept_sigs.append(s)

            if removed_dups:
                db.flush()
                sigs = kept_sigs

            is_valid, _, _ = verify_chain_integrity(db)
            if sigs and (removed_dups or any(not s.record_hash for s in sigs) or not is_valid):
                prev = GENESIS_HASH
                for s in sigs:
                    if not s.algorithm:
                        s.algorithm = "RSA-2048"
                    if not s.timestamp:
                        s.timestamp = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
                    elif s.timestamp.tzinfo is not None:
                        s.timestamp = s.timestamp.replace(tzinfo=None, microsecond=0)
                    s.prev_hash = prev
                    s.record_hash = s.calculate_record_hash()
                    prev = s.record_hash
                db.commit()
        finally:
            db.close()
    except Exception:
        pass
