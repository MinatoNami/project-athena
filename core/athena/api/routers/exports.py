from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.audit import record
from athena.db.models import Asset
from athena.export import sbom_for, vex_document

router = APIRouter(tags=["exports"])


def is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _download(document: dict[str, Any], filename: str, media_type: str) -> JSONResponse:
    return JSONResponse(
        content=document,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/assets/{asset_id}/sbom")
def asset_sbom(
    asset_id: str,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> JSONResponse:
    asset = session.get(Asset, asset_id) if is_uuid(asset_id) else None
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such asset")
    document = sbom_for(session, asset)
    record(
        session,
        actor=principal.actor,
        action="SBOM_EXPORTED",
        subject=f"asset:{asset.id}",
        detail={"components": len(document["components"]), "format": "cyclonedx-1.6"},
    )
    safe = "".join(
        c if (c.isascii() and c.isalnum()) or c in "-_." else "-" for c in asset.display_name
    )[:60]
    return _download(document, f"{safe or 'asset'}.cdx.json", "application/vnd.cyclonedx+json")


@router.get("/export/openvex")
def export_openvex(
    asset_id: str | None = None,
    vulnerability_id: str | None = None,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> JSONResponse:
    if asset_id is not None and (not is_uuid(asset_id) or session.get(Asset, asset_id) is None):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such asset")
    document = vex_document(session, asset_id=asset_id, vulnerability_id=vulnerability_id)
    counts: dict[str, int] = {}
    for statement in document["statements"]:
        counts[statement["status"]] = counts.get(statement["status"], 0) + 1
    record(
        session,
        actor=principal.actor,
        action="VEX_EXPORTED",
        subject=f"asset:{asset_id}" if asset_id else "estate",
        detail={"statements": counts, "vulnerability_id": vulnerability_id},
    )
    return _download(document, "athena.openvex.json", "application/json")
