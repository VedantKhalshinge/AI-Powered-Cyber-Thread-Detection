# AI-Powered Cybersecurity Intelligence Platform

A full-stack, real-time cybersecurity platform combining ML-based threat detection and SIEM monitoring.

## Features

### Detection Engines
| Engine | Algorithm | Input |
|--------|-----------|-------|
| **Network Anomaly** | PyTorch Autoencoder + Isolation Forest | Traffic flow features |
| **Malware Detection** | Gradient Boosting (PE features) | PE file metadata |
| **Phishing Detection** | TF-IDF + Random Forest + handcrafted signals | Email text |

### SIEM Dashboard
- **Live System Metrics** — CPU, RAM, Disk I/O, GPU (60s rolling charts)
- **Network Packet Monitor** — Real-time packet stream with threat flagging
- **Event Log Feed** — System log tailing with severity color-coding
- **NLP Alert Engine** — Groq LLM (`llama3-8b-8192`) with template fallback

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
copy .env.example .env
# Edit .env — add GROQ_API_KEY if you want LLM-powered alerts
```

### 3. Run the Platform
```bash
python backend/app.py
```

> Models are **auto-trained on synthetic data** at first launch. No manual training step needed.

### 4. Open Dashboard
Navigate to: **http://localhost:5000**

---

## Project Structure
```
project/
├── backend/
│   ├── app.py                    # Flask + SocketIO entrypoint
│   ├── models/
│   │   ├── train_anomaly.py      # Autoencoder + Isolation Forest
│   │   ├── train_malware.py      # Gradient Boosting on PE features
│   │   ├── train_phishing.py     # TF-IDF + Random Forest
│   │   └── saved/                # Serialized model files (.pkl, .pt)
│   ├── detectors/
│   │   ├── network_detector.py
│   │   ├── malware_detector.py
│   │   └── phishing_detector.py
│   ├── siem/
│   │   ├── metrics_collector.py  # psutil monitoring
│   │   ├── packet_monitor.py     # Packet capture / simulation
│   │   └── log_monitor.py        # System log tailing
│   └── alerts/
│       └── nlp_alert_engine.py   # Groq LLM + template fallback
├── frontend/
│   ├── index.html                # 4-panel dashboard
│   └── static/
│       ├── dashboard.css         # Dark cyberpunk theme
│       ├── dashboard.js          # Socket.IO + detector logic
│       └── charts.js             # Chart.js live charts
├── data/
│   └── generate_synthetic.py     # Training data generator
├── requirements.txt
├── .env.example
└── README.md
```

---

## API Reference

### Detection Endpoints (REST)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/detect/network` | Network anomaly detection |
| POST | `/api/detect/malware` | Malware PE feature detection |
| POST | `/api/detect/phishing` | Phishing email detection |
| GET  | `/api/status` | Platform health check |
| GET  | `/api/metrics/history` | Historical metrics |

### Unified Response Schema
```json
{
  "engine": "network_anomaly | malware_detection | phishing_detection",
  "result": "Anomalous | Normal | Malicious | Benign | Phishing | Legitimate",
  "confidence": 0.94,
  "score": 0.94,
  "indicators": ["High entropy (packed/encrypted)", "..."],
  "timestamp": "2025-01-01T00:00:00Z"
}
```

### Socket.IO Namespaces
| Namespace | Event | Description |
|-----------|-------|-------------|
| `/metrics` | `metrics_update` | CPU/RAM/Disk every 2s |
| `/packets` | `packet_update` | New network packet |
| `/logs` | `log_update` | New log event |
| `/alerts` | `new_alert` | NLP alert triggered |

---

## Alert Schema (NLP Engine)
```json
{
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "summary": "Plain-English explanation of the threat.",
  "action": "Recommended remediation step.",
  "timestamp": "...",
  "engine": "...",
  "score": 0.92,
  "source": "groq | template"
}
```

---

## Graceful Degradation
- **No Groq API key** → Template-based alert generation
- **No pynvml** → GPU metrics silently skipped
- **No scapy / no root** → Packet simulation mode
- **No saved models** → Auto-trains on synthetic data at startup

---

## Tech Stack
- **Backend**: Python 3.11+, Flask 3, Flask-SocketIO, Flask-CORS
- **ML**: scikit-learn, PyTorch, joblib
- **System**: psutil, scapy (optional), pynvml (optional)
- **NLP**: Groq SDK (`llama3-8b-8192`)
- **Frontend**: Vanilla JS, Chart.js 4, Socket.IO client
- **Design**: Minimal Professional Light Theme, Inter Font, Lucide Icons

---

## Credits & Copyright

**Created by Vedant Khalshinge**

&copy; 2026 Vedant Khalshinge. All Rights Reserved.

This project is proprietary and confidential. Unauthorized copying of this file, via any medium, is strictly prohibited. You may not reproduce, distribute, or create derivative works from this project without explicit written permission. See the `LICENSE` file for more details.
