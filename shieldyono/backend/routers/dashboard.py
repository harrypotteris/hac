"""ShieldYONO — Dashboard router.

Provides simulated dashboard stats.
"""

from fastapi import APIRouter

from services.ml_engine import get_threat_summary


router = APIRouter()


@router.get("/", summary="Dashboard threat summary")
def summary():
    return get_threat_summary()

