"""
ShieldYONO — APK Scanner Router
Endpoints for APK fingerprinting and fake-app detection.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from database import get_db, APKScan, Alert, ThreatIntel
from services.ml_engine import analyse_apk


router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────

class APKScanRequest(BaseModel):
    filename:     str
    package_name: Optional[str] = None
    cert_issuer:  Optional[str] = None
    sha256_hash:  Optional[str] = None

class APKScanResponse(BaseModel):
    scan_id:       int
    filename:      str
    verdict:       str
    risk_score:    float
    is_fake:       bool
    signals:       List[str]
    recommendation: str
    ui_similarity: float
    cert_claimed:  str
    cert_actual:   str
    sha256_match:  bool
    created_at:    datetime


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post("/scan", response_model=APKScanResponse, summary="Scan an APK for malicious indicators")
def scan_apk(request: APKScanRequest, db: Session = Depends(get_db)):
    """
    Runs the ML-based APK fingerprinting pipeline:
    - Package name verification
    - Certificate hash comparison
    - UI similarity scoring (YOLO-based, simulated)
    - Known-malicious hash lookup
    """
    result = analyse_apk(
        filename=request.filename,
        package_name=request.package_name,
        cert_issuer=request.cert_issuer,
        sha256=request.sha256_hash,
    )

    scan = APKScan(
        filename=request.filename,
        package_name=request.package_name,
        cert_claimed=result["cert_claimed"],
        cert_actual=result["cert_actual"],
        sha256_hash=request.sha256_hash,
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        is_fake=result["is_fake"],
        scan_details=str(result["signals"]),
    )
    db.add(scan)
    db.flush()

    # Auto-generate alert for malicious APKs
    if result["verdict"] in ("malicious", "suspicious"):
        severity = "critical" if result["verdict"] == "malicious" else "high"
        alert = Alert(
            alert_type="apk",
            severity=severity,
            title=f"{'Malicious' if result['is_fake'] else 'Suspicious'} APK Detected: {request.filename}",
            description=f"Risk score {result['risk_score']:.0%}. Signals: {'; '.join(result['signals'][:3])}",
            source_ref=str(scan.id),
        )
        db.add(alert)

        # Add to threat intel if malicious
        if result["verdict"] == "malicious" and request.sha256_hash:
            existing = db.query(ThreatIntel).filter_by(ioc_value=request.sha256_hash).first()
            if not existing:
                ti = ThreatIntel(
                    ioc_type="apk_hash",
                    ioc_value=request.sha256_hash,
                    description=f"Fake YONO APK: {request.filename}",
                    source="shieldyono_scanner",
                )
                db.add(ti)

    db.commit()
    db.refresh(scan)

    return APKScanResponse(
        scan_id=scan.id,
        filename=scan.filename,
        verdict=scan.verdict,
        risk_score=scan.risk_score,
        is_fake=scan.is_fake,
        signals=result["signals"],
        recommendation=result["recommendation"],
        ui_similarity=result["ui_similarity"],
        cert_claimed=scan.cert_claimed,
        cert_actual=scan.cert_actual,
        sha256_match=result["sha256_match"],
        created_at=scan.created_at,
    )


@router.get("/history", summary="Get recent APK scan history")
def get_scan_history(limit: int = 20, db: Session = Depends(get_db)):
    scans = db.query(APKScan).order_by(APKScan.created_at.desc()).limit(limit).all()
    return scans


@router.get("/stats", summary="APK scanner statistics")
def get_apk_stats(db: Session = Depends(get_db)):
    total    = db.query(APKScan).count()
    malicious = db.query(APKScan).filter_by(verdict="malicious").count()
    suspicious = db.query(APKScan).filter_by(verdict="suspicious").count()
    safe     = db.query(APKScan).filter_by(verdict="safe").count()
    return {
        "total_scans": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "safe": safe,
        "detection_rate": round((malicious + suspicious) / total, 3) if total else 0,
    }


@router.get("/demo-samples", summary="Get demo APK samples for testing")
def get_demo_samples():
    """Returns pre-built test cases for UI demonstration."""
    return [
        {
            "label": "✅ Official YONO App",
            "filename": "YONO_SBI_v3.2.1.apk",
            "package_name": "com.sbi.lotusintouch",
            "cert_issuer": "State Bank of India",
            "sha256_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        },
        {
            "label": "⛔ Fake YONO APK (Malicious)",
            "filename": "YONO_SBI_update_v2.apk",
            "package_name": "com.sbiyono0.unofficial",
            "cert_issuer": "Unknown CA — Self-signed",
            "sha256_hash": "a3f4b2c1d5e6f7a8b9c0d1e2",
        },
        {
            "label": "⚠️ Suspicious SBI App",
            "filename": "SBI_Mobile_Banking_New.apk",
            "package_name": "com.sbi.mobile.v2",
            "cert_issuer": "DigiCert (Unverified)",
            "sha256_hash": "x9y8z7a6b5c4d3e2f1",
        },
    ]