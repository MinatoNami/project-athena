from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from athena import __version__
from athena.api.deps import db

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "version": __version__}


@router.get("/readyz")
def readyz(session: Session = Depends(db)) -> dict:
    session.execute(text("SELECT 1"))
    return {"status": "ready", "version": __version__}
