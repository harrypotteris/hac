"""ShieldYONO — Health endpoints.

Separated to avoid main.py importing non-existent routers.
"""

from fastapi import APIRouter


router = APIRouter()


@router.get("/", tags=["Health"])
async def root():
    return {"status": "online", "service": "ShieldYONO API", "version": "1.0.0"}


@router.get("/api/health", tags=["Health"])
async def health():
    return {
        "status": "healthy",
        "modules": ["apk_scanner", "link_scanner", "device_sentinel", "awareness"],
    }

