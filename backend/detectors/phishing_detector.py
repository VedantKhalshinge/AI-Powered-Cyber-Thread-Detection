# ==============================================================================
# Copyright (c) 2026 Vedant Khalshinge. All Rights Reserved.
# 
# This file is part of the AI-Powered Cyber Threat Detection System.
# Unauthorized copying of this file, via any medium, is strictly prohibited.
# Proprietary and confidential.
# ==============================================================================

"""
Phishing Detector — Inference
TF-IDF + Random Forest pipeline + handcrafted features
"""

import os
import re
import joblib
from datetime import datetime, timezone

SAVED_DIR = os.path.join(os.path.dirname(__file__), '..', 'models', 'saved')

URGENT_KEYWORDS = [
    'urgent', 'immediately', 'action required', 'verify now', 'suspended',
    'expires', 'limited time', 'final notice', 'confirm identity',
    'account locked', 'winner', 'claim', 'prize', 'free'
]

IP_URL_PATTERN = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}')
URL_PATTERN = re.compile(r'https?://\S+')
HTML_TAG_PATTERN = re.compile(r'<[a-zA-Z][^>]*>')


def extract_handcrafted_features(text: str) -> dict:
    urls = URL_PATTERN.findall(text)
    ip_urls = IP_URL_PATTERN.findall(text)
    lower = text.lower()
    urgent = sum(1 for kw in URGENT_KEYWORDS if kw in lower)
    has_html = bool(HTML_TAG_PATTERN.search(text))

    return {
        "url_count":         len(urls),
        "ip_based_urls":     len(ip_urls),
        "urgent_keywords":   urgent,
        "has_html":          int(has_html),
    }


class PhishingDetector:
    def __init__(self):
        model_path = os.path.join(SAVED_DIR, 'phishing_pipeline.pkl')
        self.pipeline = joblib.load(model_path)

    def predict(self, text: str, sender_domain: str = "") -> dict:
        proba = self.pipeline.predict_proba([text])[0]
        phishing_conf = float(proba[1])

        hc = extract_handcrafted_features(text)

        # Boost score from handcrafted signals
        boost = 0.0
        if hc['ip_based_urls'] > 0:
            boost += 0.15
        if hc['urgent_keywords'] >= 2:
            boost += 0.10
        if hc['has_html']:
            boost += 0.05
        if hc['url_count'] > 3:
            boost += 0.05

        final_score = float(min(phishing_conf + boost, 1.0))
        result = "Phishing" if final_score >= 0.5 else "Legitimate"

        # Build indicators
        indicators = []
        if hc['ip_based_urls'] > 0:
            indicators.append(f"IP-based URLs detected ({hc['ip_based_urls']})")
        if hc['urgent_keywords'] > 0:
            indicators.append(f"Urgent language keywords ({hc['urgent_keywords']} found)")
        if hc['has_html']:
            indicators.append("HTML tags present in email body")
        if hc['url_count'] > 3:
            indicators.append(f"High URL count ({hc['url_count']})")
        if phishing_conf > 0.6:
            indicators.append(f"ML model high phishing probability ({phishing_conf:.0%})")
        if not indicators:
            indicators = ["No obvious phishing signals detected"]

        return {
            "engine":     "phishing_detection",
            "result":     result,
            "confidence": round(final_score, 4),
            "score":      round(final_score, 4),
            "indicators": indicators[:5],
            "timestamp":  datetime.now(timezone.utc).isoformat(),
        }


_detector = None


def get_detector():
    global _detector
    if _detector is None:
        _detector = PhishingDetector()
    return _detector
