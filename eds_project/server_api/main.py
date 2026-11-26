import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from db.database import engine, Base, auto_migrate_schema
from db import models  # noqa: F401
from api.endpoints_auth import router as auth_router
from api.endpoints_docs import router as docs_router
from api.endpoints_certs import router as certs_router

Base.metadata.create_all(bind=engine)
auto_migrate_schema()

app = FastAPI(
    title="API Сервер СЕД",
    description="Бекенд системи електронного документообігу (X.509 PKI, TSA RFC 3161, ACL мультипідпис, Hash-Chain аудит)",
    version="2.0.0"
)

app.include_router(auth_router)
app.include_router(docs_router)
app.include_router(certs_router)


@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    return RedirectResponse(url="/docs")


@app.get("/health", summary="Перевірка працездатності сервера")
async def health_check():
    return {
        "status": "online",
        "system": "EDS Security Core",
        "version": "2.0.0",
        "features": [
            "Multi-Algorithm EDS (RSA, ECDSA, Ed25519)",
            "Local X.509 Certificate Authority (Root CA)",
            "RFC 3161 Time-Stamping Authority (TSA)",
            "Tamper-Evident Hash Chain Audit Log",
            "Multi-Signature Collective Signoff"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
