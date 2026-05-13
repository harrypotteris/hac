"""ShieldYONO — Device sentinel router (placeholder).

Main health endpoint references device_sentinel and awareness modules.
This provides basic endpoints to prevent 404s/import errors.
"""

from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="Device sentinel status")
def status():
    return {"status": "ok", "module": "device_sentinel"}

