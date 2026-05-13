"""ShieldYONO — Awareness router (placeholder).

Provides basic endpoints to match frontend expectations.
"""

from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="Awareness status")
def status():
    return {"status": "ok", "module": "awareness"}

