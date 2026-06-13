"""
AI-Powered Cybersecurity Intelligence Platform
Flask + Flask-SocketIO backend entrypoint
"""

import os
import sys
import threading
from dotenv import load_dotenv

load_dotenv()

# Ensure project root is importable
ROOT = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.dirname(ROOT)
sys.path.insert(0, PROJ_ROOT)

from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS

app = Flask(__name__, static_folder=os.path.join(PROJ_ROOT, 'frontend', 'static'),
            template_folder=os.path.join(PROJ_ROOT, 'frontend'))
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'cyber-secret-2025')

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading',
                    namespaces=['/metrics', '/packets', '/logs', '/alerts'])

# ── Lazy model loading ──────────────────────────────────────────────────────

def _ensure_models():
    """Train all models on synthetic data if not already saved."""
    from backend.models.train_anomaly import train as train_anomaly
    from backend.models.train_malware import train as train_malware
    from backend.models.train_phishing import train as train_phishing

    # Ensure synthetic data exists
    data_dir = os.path.join(PROJ_ROOT, 'data')
    for fname in ['network_traffic.csv', 'malware_features.csv', 'phishing_emails.csv']:
        if not os.path.exists(os.path.join(data_dir, fname)):
            print(f"[*] Generating synthetic dataset: {fname}")
            from data.generate_synthetic import (
                generate_network_traffic, generate_malware_features, generate_phishing_emails
            )
            generate_network_traffic()
            generate_malware_features()
            generate_phishing_emails()
            break

    train_anomaly()
    train_malware()
    train_phishing()


# ── SIEM background services ────────────────────────────────────────────────

from backend.siem.metrics_collector import MetricsCollector
from backend.siem.packet_monitor import PacketMonitor
from backend.siem.log_monitor import LogMonitor

metrics_collector = MetricsCollector(socketio)
packet_monitor = PacketMonitor(socketio)
log_monitor = LogMonitor(socketio)


# ── REST Endpoints ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    from flask import send_from_directory
    return send_from_directory(os.path.join(PROJ_ROOT, 'frontend'), 'index.html')


@app.route('/api/detect/network', methods=['POST'])
def detect_network():
    data = request.get_json(force=True)
    try:
        from backend.detectors.network_detector import get_detector
        detector = get_detector()
        result = detector.predict(data)
        _maybe_emit_alert(result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/detect/malware', methods=['POST'])
def detect_malware():
    data = request.get_json(force=True)
    try:
        from backend.detectors.malware_detector import get_detector
        detector = get_detector()
        result = detector.predict(data)
        _maybe_emit_alert(result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/detect/phishing', methods=['POST'])
def detect_phishing():
    data = request.get_json(force=True)
    try:
        from backend.detectors.phishing_detector import get_detector
        detector = get_detector()
        text = data.get('text', '')
        sender = data.get('sender_domain', '')
        result = detector.predict(text, sender)
        _maybe_emit_alert(result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/metrics/history')
def metrics_history():
    return jsonify(metrics_collector.get_history())


@app.route('/api/logs/recent')
def recent_logs():
    return jsonify(log_monitor.get_recent())


@app.route('/api/status')
def status():
    return jsonify({
        "status": "online",
        "models": ["network_anomaly", "malware_detection", "phishing_detection"],
        "siem":   ["metrics", "packets", "logs"],
    })


def _maybe_emit_alert(detection: dict):
    """Generate and emit NLP alert if threshold crossed."""
    from backend.alerts.nlp_alert_engine import should_alert, generate_alert
    if should_alert(detection):
        def _emit():
            alert = generate_alert(detection)
            socketio.emit('new_alert', alert, namespace='/alerts')
        threading.Thread(target=_emit, daemon=True).start()


# ── Socket.IO Events ────────────────────────────────────────────────────────

@socketio.on('connect', namespace='/metrics')
def on_metrics_connect():
    print("[WS] Client connected to /metrics")

@socketio.on('connect', namespace='/packets')
def on_packets_connect():
    print("[WS] Client connected to /packets")

@socketio.on('connect', namespace='/logs')
def on_logs_connect():
    print("[WS] Client connected to /logs")

@socketio.on('connect', namespace='/alerts')
def on_alerts_connect():
    print("[WS] Client connected to /alerts")


# ── Startup ─────────────────────────────────────────────────────────────────

def startup():
    print("=" * 60)
    print("  AI Cybersecurity Intelligence Platform")
    print("=" * 60)
    print("[*] Pre-training models if needed...")
    _ensure_models()
    print("[*] Starting SIEM background services...")
    metrics_collector.start()
    packet_monitor.start()
    log_monitor.start()
    print("[OK] All services running. Dashboard -> http://localhost:5000")
    print("=" * 60)


if __name__ == '__main__':
    startup()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
