# ==============================================================================
# Copyright (c) 2026 Vedant Khalshinge. All Rights Reserved.
# 
# This file is part of the AI-Powered Cyber Threat Detection System.
# Unauthorized copying of this file, via any medium, is strictly prohibited.
# Proprietary and confidential.
# ==============================================================================

"""
NLP Alert Engine
Uses Groq LLM (llama3-8b-8192) for alert summarization.
Falls back to template-based generation if API key absent.
"""

import os
from datetime import datetime, timezone

try:
    from groq import Groq
    _GROQ_AVAILABLE = True
except ImportError:
    _GROQ_AVAILABLE = False

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

SEVERITY_MAP = {
    "network_anomaly":   {"HIGH": 0.7,  "CRITICAL": 0.85},
    "malware_detection": {"HIGH": 0.65, "CRITICAL": 0.85},
    "phishing_detection":{"HIGH": 0.6,  "CRITICAL": 0.80},
}

TEMPLATE_SUMMARIES = {
    "network_anomaly": {
        "LOW":      ("Low-level network irregularity detected.",
                     "A minor deviation from normal traffic patterns was observed. Continue routine monitoring."),
        "MEDIUM":   ("Suspicious network traffic pattern identified.",
                     "Abnormal connection behavior detected that may indicate reconnaissance or misuse. Investigate source IP and connection frequency."),
        "HIGH":     ("High anomaly score in network traffic.",
                     "Significant deviation from baseline network behavior detected, possibly indicating an intrusion or data exfiltration attempt. Isolate affected system and review firewall rules."),
        "CRITICAL": ("Critical network anomaly — possible active attack.",
                     "Extreme network anomaly detected consistent with DDoS, port scanning, or active data breach. Immediately block suspicious IPs and escalate to security team."),
    },
    "malware_detection": {
        "LOW":      ("Low malware risk file analyzed.",
                     "File exhibits minor suspicious characteristics. Run additional sandbox analysis to confirm safety."),
        "MEDIUM":   ("File shows moderate malware indicators.",
                     "Multiple PE characteristics suggest potential malicious intent. Quarantine the file and run full AV scan."),
        "HIGH":     ("High-confidence malware signature detected.",
                     "File demonstrates strong indicators of malicious code including packing, high entropy, and suspicious API calls. Quarantine immediately and trace origin."),
        "CRITICAL": ("Critical — malware with high confidence score.",
                     "File is almost certainly malicious with multiple confirmed threat indicators. Do not execute. Quarantine, forensic analysis required, and incident report must be filed."),
    },
    "phishing_detection": {
        "LOW":      ("Email shows minor phishing signals.",
                     "The email contains a small number of suspicious elements. Treat with caution and do not click any links."),
        "MEDIUM":   ("Moderate phishing probability detected.",
                     "Email contains suspicious URLs and urgent language typical of social engineering. Do not click links or provide credentials."),
        "HIGH":     ("High-confidence phishing email identified.",
                     "Email contains multiple phishing indicators including IP-based URLs and urgency triggers. Block sender and report to IT security."),
        "CRITICAL": ("Critical phishing attack — credential harvesting likely.",
                     "Email is a sophisticated phishing attempt designed to steal credentials or install malware. Block sender domain, alert all staff, and review mail gateway rules."),
    },
}


def _get_severity(engine: str, score: float) -> str:
    thresholds = SEVERITY_MAP.get(engine, {"HIGH": 0.7, "CRITICAL": 0.85})
    if score >= thresholds["CRITICAL"]:
        return "CRITICAL"
    elif score >= thresholds["HIGH"]:
        return "HIGH"
    elif score >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"


def _template_alert(detection: dict) -> dict:
    engine = detection.get("engine", "")
    score = detection.get("score", 0.0)
    severity = _get_severity(engine, score)

    if engine in TEMPLATE_SUMMARIES and severity in TEMPLATE_SUMMARIES[engine]:
        title, body = TEMPLATE_SUMMARIES[engine][severity]
    else:
        title = f"{severity} security alert from {engine}"
        body = "A threat was detected. Please review the detection details and take appropriate action."

    indicators = detection.get("indicators", [])
    indicators_text = "; ".join(indicators[:3]) if indicators else "N/A"
    action = f"Review indicators: {indicators_text}"

    return {
        "severity": severity,
        "summary":  f"{title} {body}",
        "action":   action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "engine":   engine,
        "score":    round(score, 4),
        "source":   "template",
    }


def _groq_alert(detection: dict, client: "Groq") -> dict:
    engine = detection.get("engine", "")
    score = detection.get("score", 0.0)
    result = detection.get("result", "")
    indicators = detection.get("indicators", [])
    severity = _get_severity(engine, score)

    prompt = f"""You are a cybersecurity analyst. A detection engine produced this result:
Engine: {engine}
Result: {result}
Confidence: {score:.2%}
Severity: {severity}
Indicators: {', '.join(indicators) if indicators else 'None'}

Respond with EXACTLY this JSON format (no markdown, no extra text):
{{"severity": "{severity}", "summary": "<one sentence plain English alert>", "action": "<one recommended action>"}}"""

    response = client.chat.completions.create(
        model="llama3-8b-8192",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=200,
        temperature=0.3,
    )

    import json
    content = response.choices[0].message.content.strip()

    # Strip markdown code fences if present
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]

    parsed = json.loads(content)
    parsed["timestamp"] = datetime.now(timezone.utc).isoformat()
    parsed["engine"] = engine
    parsed["score"] = round(score, 4)
    parsed["source"] = "groq"
    return parsed


def generate_alert(detection: dict) -> dict:
    """
    Main entry point. Returns alert dict with severity, summary, action.
    """
    if _GROQ_AVAILABLE and GROQ_API_KEY:
        try:
            client = Groq(api_key=GROQ_API_KEY)
            return _groq_alert(detection, client)
        except Exception as e:
            print(f"[!] Groq alert failed ({e}), using template fallback")

    return _template_alert(detection)


def should_alert(detection: dict) -> bool:
    """Return True if the detection result warrants an alert."""
    engine = detection.get("engine", "")
    score = detection.get("score", 0.0)

    thresholds = {
        "network_anomaly":   float(os.getenv("ALERT_THRESHOLD_ANOMALY",   0.7)),
        "malware_detection": float(os.getenv("ALERT_THRESHOLD_MALWARE",   0.8)),
        "phishing_detection":float(os.getenv("ALERT_THRESHOLD_PHISHING",  0.75)),
    }

    return score >= thresholds.get(engine, 0.7)
