"""
ShieldYONO — Link/URL Scanner Router
Real-time phishing link detection integrated with TRAI DLT API simulation.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from database import get_db, LinkScan, Alert, ThreatIntel
from services.ml_engine import analyse_url


router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────

class LinkScanRequest(BaseModel):
    url:    str
    source: Optional[str] = "manual"   # sms | whatsapp | manual

class BulkLinkScanRequest(BaseModel):
    urls:   List[str]
    source: Optional[str] = "sms"

class LinkScanResponse(BaseModel):
    scan_id:         int
    url:             str
    verdict:         str
    risk_score:      float
    blocked:         bool
    domain:          str
    is_blacklisted:  bool
    has_ssl:         bool
    domain_age_days: int
    signals:         List[str]
    recommendation:  str
    created_at:      datetime


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post("/scan", response_model=LinkScanResponse, summary="Scan a URL for phishing")
def scan_link(request: LinkScanRequest, db: Session = Depends(get_db)):
    """
    Analyses a URL using:
    - Domain blacklist (TRAI DLT + internal)
    - SSL certificate status
    - Domain age estimation
    - SBI lookalike detection
    - Keyword toxicity scoring
    """
    result = analyse_url(request.url, request.source)

    scan = LinkScan(
        url=request.url,
        source=request.source,
        domain_age=result["domain_age_days"],
        has_ssl=result["has_ssl"],
        is_blacklisted=result["is_blacklisted"],
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        blocked=result["blocked"],
    )
    db.add(scan)
    db.flush()

    # Auto-alert on phishing detection
    if result["verdict"] in ("malicious", "suspicious"):
        severity = "critical" if result["verdict"] == "malicious" else "medium"
        alert = Alert(
            alert_type="link",
            severity=severity,
            title=f"Phishing Link Detected: {result['domain']}",
            description=f"Source: {request.source} | Risk: {result['risk_score']:.0%} | "
                        f"Signals: {'; '.join(result['signals'][:2])}",
            source_ref=str(scan.id),
        )
        db.add(alert)

        # Update threat intel
        if result["is_blacklisted"] or result["verdict"] == "malicious":
            existing = db.query(ThreatIntel).filter_by(ioc_value=request.url).first()
            if not existing:
                ti = ThreatIntel(
                    ioc_type="url",
                    ioc_value=request.url,
                    description=f"Phishing URL detected via {request.source}",
                    source="shieldyono_link_scanner",
                )
                db.add(ti)

    db.commit()
    db.refresh(scan)

    return LinkScanResponse(
        scan_id=scan.id,
        url=scan.url,
        verdict=scan.verdict,
        risk_score=scan.risk_score,
        blocked=scan.blocked,
        domain=result["domain"],
        is_blacklisted=scan.is_blacklisted,
        has_ssl=scan.has_ssl,
        domain_age_days=scan.domain_age,
        signals=result["signals"],
        recommendation=result["recommendation"],
        created_at=scan.created_at,
    )


@router.post("/scan/bulk", summary="Scan multiple URLs at once")
def scan_bulk(request: BulkLinkScanRequest, db: Session = Depends(get_db)):
    results = []
    for url in request.urls[:50]:   # cap at 50 per batch
        result = analyse_url(url, request.source)
        scan = LinkScan(
            url=url, source=request.source,
            domain_age=result["domain_age_days"],
            has_ssl=result["has_ssl"],
            is_blacklisted=result["is_blacklisted"],
            risk_score=result["risk_score"],
            verdict=result["verdict"],
            blocked=result["blocked"],
        )
        db.add(scan)
        results.append({"url": url, "verdict": result["verdict"], "risk_score": result["risk_score"]})
    db.commit()
    return {"total": len(results), "results": results}


@router.get("/history", summary="Get recent link scan history")
def get_link_history(limit: int = 20, db: Session = Depends(get_db)):
    scans = db.query(LinkScan).order_by(LinkScan.created_at.desc()).limit(limit).all()
    return scans


@router.get("/stats", summary="Link scanner statistics")
def get_link_stats(db: Session = Depends(get_db)):
    total     = db.query(LinkScan).count()
    malicious = db.query(LinkScan).filter_by(verdict="malicious").count()
    suspicious = db.query(LinkScan).filter_by(verdict="suspicious").count()
    blocked   = db.query(LinkScan).filter_by(blocked=True).count()
    return {
        "total_scans": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "blocked": blocked,
        "safe": total - malicious - suspicious,
    }


@router.get("/demo-samples", summary="Demo phishing links for testing")
def get_demo_links():
    return [
        {"label": "✅ Official SBI Site",         "url": "https://onlinesbi.com/personal/login.htm", "source": "manual"},
        {"label": "⛔ Known Phishing Domain",      "url": "http://sbi-yono-secure.xyz/login",          "source": "sms"},
        {"label": "⚠️ Suspicious KYC Update Link", "url": "https://yono-kyc-update.in/verify",         "source": "whatsapp"},
        {"label": "⚠️ Reward Claim Scam",          "url": "http://sbi-reward-claim.co/claim?ref=123",  "source": "sms"},
        {"label": "✅ HTTPS Official SBI",          "url": "https://sbi.co.in/web/personal-banking",   "source": "manual"},
    ]