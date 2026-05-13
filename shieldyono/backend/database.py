"""
ShieldYONO — Database layer (SQLite via SQLAlchemy)
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./shieldyono.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── ORM Models ──────────────────────────────────────────────────────────────

class APKScan(Base):
    __tablename__ = "apk_scans"
    id            = Column(Integer, primary_key=True, index=True)
    filename      = Column(String, nullable=False)
    package_name  = Column(String, nullable=True)
    cert_claimed  = Column(String, nullable=True)
    cert_actual   = Column(String, nullable=True)
    sha256_hash   = Column(String, nullable=True)
    risk_score    = Column(Float, default=0.0)
    verdict       = Column(String, default="safe")   # safe | suspicious | malicious
    is_fake       = Column(Boolean, default=False)
    scan_details  = Column(Text, nullable=True)
    created_at    = Column(DateTime, default=datetime.utcnow)


class LinkScan(Base):
    __tablename__ = "link_scans"
    id            = Column(Integer, primary_key=True, index=True)
    url           = Column(String, nullable=False)
    source        = Column(String, default="manual")   # sms | whatsapp | manual
    domain_age    = Column(Integer, nullable=True)     # days
    has_ssl       = Column(Boolean, default=False)
    is_blacklisted = Column(Boolean, default=False)
    risk_score    = Column(Float, default=0.0)
    verdict       = Column(String, default="safe")
    blocked       = Column(Boolean, default=False)
    created_at    = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    id            = Column(Integer, primary_key=True, index=True)
    alert_type    = Column(String, nullable=False)     # apk | link | device | system
    severity      = Column(String, default="medium")   # low | medium | high | critical
    title         = Column(String, nullable=False)
    description   = Column(Text, nullable=True)
    source_ref    = Column(String, nullable=True)      # apk_scan id or link_scan id
    is_resolved   = Column(Boolean, default=False)
    reported_to_cert = Column(Boolean, default=False)
    created_at    = Column(DateTime, default=datetime.utcnow)
    resolved_at   = Column(DateTime, nullable=True)


class ThreatIntel(Base):
    __tablename__ = "threat_intel"
    id            = Column(Integer, primary_key=True, index=True)
    ioc_type      = Column(String, nullable=False)     # url | apk_hash | domain | ip
    ioc_value     = Column(String, nullable=False, unique=True)
    threat_actor  = Column(String, nullable=True)
    description   = Column(Text, nullable=True)
    confidence    = Column(Float, default=0.8)
    source        = Column(String, default="internal")
    created_at    = Column(DateTime, default=datetime.utcnow)


class EducationModule(Base):
    __tablename__ = "education_modules"
    id            = Column(Integer, primary_key=True, index=True)
    title         = Column(String, nullable=False)
    language      = Column(String, default="en")
    category      = Column(String, nullable=False)  # phishing | apk | password | general
    content       = Column(Text, nullable=False)
    difficulty    = Column(String, default="beginner")
    points        = Column(Integer, default=10)
    created_at    = Column(DateTime, default=datetime.utcnow)


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    _seed_threat_intel()
    _seed_education_modules()


def _seed_threat_intel():
    """Pre-populate known malicious IOCs"""
    db = SessionLocal()
    if db.query(ThreatIntel).count() > 0:
        db.close()
        return
    iocs = [
        ThreatIntel(ioc_type="domain", ioc_value="sbi-yono-secure.xyz",       description="Phishing domain impersonating YONO"),
        ThreatIntel(ioc_type="domain", ioc_value="sbiyono-login.net",          description="Credential harvesting site"),
        ThreatIntel(ioc_type="domain", ioc_value="yono-kyc-update.in",         description="Fake KYC update page"),
        ThreatIntel(ioc_type="domain", ioc_value="sbi-reward-claim.co",        description="Reward scam landing page"),
        ThreatIntel(ioc_type="domain", ioc_value="sbibank-verify.online",      description="Account verification scam"),
        ThreatIntel(ioc_type="apk_hash", ioc_value="a3f4b2c1d5e6f7a8b9c0d1e2", description="Fake YONO APK v2.1"),
        ThreatIntel(ioc_type="apk_hash", ioc_value="b5e6c7d8e9f0a1b2c3d4e5f6", description="Fake SBI Mobile APK"),
        ThreatIntel(ioc_type="url",    ioc_value="http://sbi-yono-secure.xyz/login", description="Phishing login page"),
    ]
    db.add_all(iocs)
    db.commit()
    db.close()


def _seed_education_modules():
    db = SessionLocal()
    if db.query(EducationModule).count() > 0:
        db.close()
        return
    modules = [
        EducationModule(title="Spot a Phishing SMS", language="en", category="phishing",
            content="Fraudsters send fake SMS pretending to be SBI. Look for: urgency words (URGENT, EXPIRE), unofficial domains, requests for OTP/PIN. SBI will NEVER ask for your password via SMS.",
            difficulty="beginner", points=10),
        EducationModule(title="APK Side-Loading Dangers", language="en", category="apk",
            content="Installing apps from outside Play Store bypasses Google's security checks. Fake YONO APKs steal your login credentials and OTPs. Always download YONO only from Google Play or App Store.",
            difficulty="beginner", points=10),
        EducationModule(title="Verify App Authenticity", language="en", category="apk",
            content="Before logging into YONO: 1) Check publisher is 'State Bank of India' 2) Verify 50M+ downloads 3) Look for verified badge 4) Never share OTP with anyone, including 'SBI executives'.",
            difficulty="intermediate", points=20),
        EducationModule(title="फ़िशिंग SMS की पहचान", language="hi", category="phishing",
            content="धोखेबाज़ SBI के नाम पर नकली SMS भेजते हैं। देखें: जल्दबाज़ी के शब्द, अनजान वेबसाइट, OTP/PIN मांगना। SBI कभी भी SMS पर पासवर्ड नहीं मांगता।",
            difficulty="beginner", points=10),
        EducationModule(title="Social Engineering Defence", language="en", category="general",
            content="Fraudsters create panic: 'Account will be blocked in 2 hours!' This is social engineering. Real banks never demand immediate action via unsolicited calls/SMS. Always call SBI's official helpline 1800-11-2211.",
            difficulty="intermediate", points=20),
        EducationModule(title="QR Code Verification", language="en", category="general",
            content="Use ShieldYONO's QR scanner to verify official SBI app links before downloading. Our QR codes are cryptographically signed and verified against our official registry.",
            difficulty="beginner", points=10),
    ]
    db.add_all(modules)
    db.commit()
    db.close()