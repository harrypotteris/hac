"""
ShieldYONO — ML Engine Service
Simulates CNN+LSTM APK fingerprinting and BERT URL toxicity classification.
In production, replace with actual trained model inference.
"""

import hashlib
import re
import random
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse


# ── Known malicious indicators (ground-truth lookup) ─────────────────────────

MALICIOUS_DOMAINS = {
    "sbi-yono-secure.xyz", "sbiyono-login.net", "yono-kyc-update.in",
    "sbi-reward-claim.co", "sbibank-verify.online", "sbiyono-apk.com",
    "sbi-secure-login.tk", "yono-sbi-update.ml", "sbi-kyc-expire.ga",
}

SUSPICIOUS_KEYWORDS_URL = [
    "kyc", "expire", "update", "login", "verify", "secure", "reward",
    "claim", "otp", "mpin", "password", "account", "suspend", "block",
    "urgent", "immediately", "confirm", "validate",
]

OFFICIAL_SBI_DOMAINS = {"onlinesbi.com", "sbi.co.in", "sbiyono.in", "retail.onlinesbi.com"}

SUSPICIOUS_APK_INDICATORS = [
    "unofficial", "mod", "hack", "cracked", "update_v", "yono_sbi",
    "sbi_yono_new", "sbiyono2", "fake", "clone",
]

MALICIOUS_PACKAGE_PREFIXES = [
    "com.sbi.yono.unofficial", "com.sbiyono0", "com.yono.sbi.fake",
    "org.sbi.yono", "net.sbi.yono",
]

OFFICIAL_PACKAGE_NAME = "com.sbi.lotusintouch"
OFFICIAL_CERT_ISSUER  = "State Bank of India"
OFFICIAL_CERT_SHA256  = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"


# ── APK Analysis ─────────────────────────────────────────────────────────────

def analyse_apk(filename: str, package_name: str = None,
                cert_issuer: str = None, sha256: str = None) -> Dict[str, Any]:
    """
    Simulates multi-signal APK risk scoring:
      - Package name check
      - Certificate issuer validation
      - SHA-256 hash against known-malicious list
      - Filename heuristics
      - YOLO-based UI similarity score (simulated)
    Returns a structured result dict.
    """
    signals = []
    risk = 0.0

    # 1. Filename heuristics
    fname_lower = filename.lower().replace(" ", "_")
    for indicator in SUSPICIOUS_APK_INDICATORS:
        if indicator in fname_lower:
            risk += 0.25
            signals.append(f"Suspicious filename pattern: '{indicator}'")

    # 2. Package name check
    if package_name:
        if package_name == OFFICIAL_PACKAGE_NAME:
            signals.append("Package name matches official YONO app ✓")
        else:
            for prefix in MALICIOUS_PACKAGE_PREFIXES:
                if package_name.startswith(prefix):
                    risk += 0.35
                    signals.append(f"Package name matches known malicious prefix: {prefix}")
                    break
            else:
                if "sbi" in package_name.lower() or "yono" in package_name.lower():
                    risk += 0.20
                    signals.append(f"Package name impersonates SBI/YONO but is unofficial: {package_name}")

    # 3. Certificate validation
    if cert_issuer:
        if cert_issuer.strip().lower() == OFFICIAL_CERT_ISSUER.lower():
            signals.append("Certificate issuer matches SBI ✓")
        else:
            risk += 0.30
            signals.append(f"Certificate mismatch — claimed: '{cert_issuer}', expected: '{OFFICIAL_CERT_ISSUER}'")
            if "self-signed" in cert_issuer.lower() or "unknown" in cert_issuer.lower():
                risk += 0.10
                signals.append("Self-signed certificate detected — high risk indicator")

    # 4. SHA-256 hash check
    if sha256:
        if sha256.lower() == OFFICIAL_CERT_SHA256:
            signals.append("SHA-256 hash matches official build ✓")
        else:
            # Simulate known-bad hash lookup
            risk += 0.10
            signals.append(f"SHA-256 hash not in verified allowlist")

    # 5. Simulated YOLO UI similarity score
    ui_similarity = round(random.uniform(0.60, 0.97) if risk > 0.2 else random.uniform(0.05, 0.20), 2)
    if ui_similarity > 0.70:
        risk += 0.15
        signals.append(f"UI similarity score {ui_similarity:.0%} — screen layout closely mimics real YONO")
    else:
        signals.append(f"UI similarity score {ui_similarity:.0%} — UI fingerprint does not match YONO")

    # Normalise risk to [0,1]
    risk = min(risk, 1.0)

    verdict = "safe"
    if risk >= 0.70:
        verdict = "malicious"
    elif risk >= 0.35:
        verdict = "suspicious"

    return {
        "risk_score":    round(risk, 2),
        "verdict":       verdict,
        "is_fake":       verdict == "malicious",
        "ui_similarity": ui_similarity,
        "signals":       signals,
        "cert_claimed":  cert_issuer or "Not provided",
        "cert_actual":   OFFICIAL_CERT_ISSUER,
        "sha256_match":  sha256 == OFFICIAL_CERT_SHA256 if sha256 else False,
        "recommendation": _apk_recommendation(verdict),
    }


def _apk_recommendation(verdict: str) -> str:
    if verdict == "malicious":
        return "⛔ DO NOT INSTALL. This APK has been flagged as fraudulent. Report to CERT-In immediately."
    if verdict == "suspicious":
        return "⚠️ Proceed with caution. This APK shows risk signals. Verify from official SBI channels."
    return "✅ APK appears legitimate. Always download YONO from Google Play Store / App Store."


# ── URL / Link Analysis ───────────────────────────────────────────────────────

def analyse_url(url: str, source: str = "manual") -> Dict[str, Any]:
    """
    Simulates multi-signal URL risk scoring:
      - Domain blacklist lookup
      - SSL certificate check
      - Domain age estimation
      - Keyword analysis
      - Lookalike domain detection
    """
    signals = []
    risk = 0.0

    parsed    = urlparse(url if url.startswith("http") else f"http://{url}")
    domain    = parsed.netloc.lower().replace("www.", "")
    path      = parsed.path.lower()
    full_text = (domain + path).lower()

    # 1. Blacklist check
    if domain in MALICIOUS_DOMAINS:
        risk += 0.70
        signals.append(f"Domain '{domain}' is in ShieldYONO blacklist ✗")
        is_blacklisted = True
    else:
        is_blacklisted = False

    # 2. Official domain check
    if domain in OFFICIAL_SBI_DOMAINS:
        signals.append(f"Domain '{domain}' is an official SBI domain ✓")
        return {
            "risk_score": 0.01, "verdict": "safe", "blocked": False,
            "domain": domain, "is_blacklisted": False, "has_ssl": True,
            "domain_age_days": 7300, "signals": ["Official SBI domain verified ✓"],
            "recommendation": "✅ This is an official SBI domain. Safe to proceed.",
        }

    # 3. SSL check
    has_ssl = url.startswith("https://")
    if not has_ssl:
        risk += 0.20
        signals.append("No SSL/TLS — connection is unencrypted ✗")
    else:
        signals.append("SSL/TLS present ✓")

    # 4. Suspicious keyword in URL
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS_URL if kw in full_text]
    if keyword_hits:
        risk += min(len(keyword_hits) * 0.08, 0.30)
        signals.append(f"Suspicious keywords detected: {', '.join(keyword_hits)}")

    # 5. Lookalike SBI domain detection
    sbi_lookalike_patterns = [
        r"sbi[^.]*\.", r"yono[^.]*\.", r"onlinesbi[^.]*\.", r"sbiyono[^.]*\."
    ]
    for pattern in sbi_lookalike_patterns:
        if re.search(pattern, domain):
            risk += 0.25
            signals.append(f"Domain '{domain}' appears to impersonate SBI/YONO branding")
            break

    # 6. Simulated domain age (newer = more suspicious)
    domain_age_days = random.randint(1, 30) if risk > 0.3 else random.randint(365, 5000)
    if domain_age_days < 30:
        risk += 0.15
        signals.append(f"Domain registered only {domain_age_days} day(s) ago — very new, high risk")
    elif domain_age_days < 180:
        risk += 0.05
        signals.append(f"Domain age: {domain_age_days} days — relatively new")
    else:
        signals.append(f"Domain age: {domain_age_days} days ✓")

    # 7. Free TLD check
    free_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".online", ".site"]
    for tld in free_tlds:
        if domain.endswith(tld):
            risk += 0.15
            signals.append(f"Free/suspicious TLD '{tld}' — commonly used in phishing")
            break

    risk = min(risk, 1.0)
    verdict = "safe"
    if risk >= 0.65:
        verdict = "malicious"
    elif risk >= 0.30:
        verdict = "suspicious"

    return {
        "risk_score":      round(risk, 2),
        "verdict":         verdict,
        "blocked":         verdict == "malicious",
        "domain":          domain,
        "is_blacklisted":  is_blacklisted,
        "has_ssl":         has_ssl,
        "domain_age_days": domain_age_days,
        "signals":         signals,
        "recommendation":  _url_recommendation(verdict, domain),
    }


def _url_recommendation(verdict: str, domain: str) -> str:
    if verdict == "malicious":
        return f"⛔ BLOCKED. '{domain}' is a known phishing domain. Do not click or share this link."
    if verdict == "suspicious":
        return f"⚠️ WARNING. '{domain}' shows phishing indicators. Avoid entering any personal details."
    return f"✅ '{domain}' appears safe. Always verify you're on official SBI channels before transacting."


# ── Dashboard Stats ───────────────────────────────────────────────────────────

def get_threat_summary() -> Dict[str, Any]:
    """Returns simulated real-time threat intelligence stats for the dashboard."""
    return {
        "total_scans_today":    random.randint(42000, 50000),
        "flagged_today":        random.randint(10000, 14000),
        "blocked_today":        random.randint(8000,  12000),
        "safe_today":           random.randint(28000, 36000),
        "phishing_urls_month":  12_043,
        "fake_apks_detected":   random.randint(340, 420),
        "cert_in_reports":      random.randint(18, 30),
        "avg_takedown_hrs":     round(random.uniform(1.2, 1.9), 1),
        "users_protected":      "800M+",
        "threat_types": {
            "phishing_sms":  random.randint(55, 65),
            "rogue_apk":     random.randint(40, 50),
            "fake_domain":   random.randint(35, 45),
            "social_eng":    random.randint(20, 30),
            "apk_repackage": random.randint(10, 18),
        },
        "hourly_attacks": [
            random.randint(80, 400) for _ in range(24)
        ],
        "top_attack_origins": [
            {"country": "India",         "code": "IN", "count": random.randint(8000, 9500)},
            {"country": "China",         "code": "CN", "count": random.randint(1800, 2500)},
            {"country": "Russia",        "code": "RU", "count": random.randint(700, 1000)},
            {"country": "United States", "code": "US", "count": random.randint(350, 500)},
            {"country": "Pakistan",      "code": "PK", "count": random.randint(200, 400)},
        ],
    }