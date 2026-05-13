"""ShieldYONO — Alerts router.

This project snapshot includes DB models for alerts, but the router was missing.
This minimal implementation prevents import/runtime failures.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db, Alert


router = APIRouter()


@router.get("/", summary="List alerts")
def list_alerts(limit: int = 20, resolved: Optional[bool] = None, db: Session = Depends(get_db)):
    q = db.query(Alert).order_by(Alert.created_at.desc())
    if resolved is not None:
        q = q.filter(Alert.is_resolved == resolved)
    return q.limit(limit).all()

