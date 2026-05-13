"""ShieldYONO — Education router.

Returns education modules stored in DB.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional

from database import get_db, EducationModule


router = APIRouter()


@router.get("/", summary="List education modules")
def list_modules(category: Optional[str] = None, limit: int = 50, db: Session = Depends(get_db)):
    q = db.query(EducationModule).order_by(EducationModule.created_at.desc())
    if category:
        q = q.filter(EducationModule.category == category)
    return q.limit(limit).all()

