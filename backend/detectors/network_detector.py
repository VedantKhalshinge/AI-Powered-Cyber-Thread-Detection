"""
Network Anomaly Detector
Ensemble: PyTorch Autoencoder + Isolation Forest
"""

import os
import sys
import numpy as np
import joblib
import torch
import torch.nn as nn
from datetime import datetime, timezone

SAVED_DIR = os.path.join(os.path.dirname(__file__), '..', 'models', 'saved')
FEATURES = ['src_bytes', 'dst_bytes', 'duration', 'num_connections',
            'packet_rate', 'protocol_type', 'flag']


class NetworkAutoencoder(nn.Module):
    def __init__(self, input_dim=7):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16), nn.ReLU(),
            nn.Linear(16, 8), nn.ReLU(),
            nn.Linear(8, 4), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8), nn.ReLU(),
            nn.Linear(8, 16), nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


class NetworkAnomalyDetector:
    def __init__(self):
        self._load_models()

    def _load_models(self):
        ae_path = os.path.join(SAVED_DIR, 'network_autoencoder.pt')
        scaler_path = os.path.join(SAVED_DIR, 'network_scaler.pkl')
        iso_path = os.path.join(SAVED_DIR, 'isolation_forest.pkl')
        threshold_path = os.path.join(SAVED_DIR, 'ae_threshold.npy')

        self.scaler = joblib.load(scaler_path)
        self.iso = joblib.load(iso_path)
        self.threshold = float(np.load(threshold_path))

        self.ae = NetworkAutoencoder(input_dim=len(FEATURES))
        self.ae.load_state_dict(torch.load(ae_path, map_location='cpu'))
        self.ae.eval()

    def predict(self, features: dict) -> dict:
        """
        features: dict with keys matching FEATURES list
        Returns unified detection JSON schema
        """
        x_raw = np.array([[features.get(f, 0) for f in FEATURES]], dtype=np.float64)
        x_scaled = self.scaler.transform(x_raw)

        # Autoencoder reconstruction error
        x_tensor = torch.tensor(x_scaled, dtype=torch.float32)
        with torch.no_grad():
            recon = self.ae(x_tensor)
            ae_error = float(torch.mean((recon - x_tensor) ** 2).item())

        ae_score = min(ae_error / (self.threshold * 2), 1.0)  # Normalize to 0-1

        # Isolation Forest score (-1 = anomaly, 1 = normal)  -> convert to 0-1
        iso_raw = self.iso.decision_function(x_scaled)[0]
        iso_score = float(np.clip(1 - (iso_raw + 0.5), 0, 1))

        # Ensemble
        combined_score = float(0.6 * ae_score + 0.4 * iso_score)

        # Classification
        if combined_score < 0.35:
            result = "Normal"
        elif combined_score < 0.65:
            result = "Suspicious"
        else:
            result = "Anomalous"

        # Feature contribution (deviation from mean in scaled space)
        feature_means = self.scaler.mean_
        feature_stds = self.scaler.scale_
        contributions = []
        for i, fname in enumerate(FEATURES):
            raw_val = x_raw[0][i]
            z = abs((raw_val - feature_means[i]) / (feature_stds[i] + 1e-8))
            contributions.append((fname, round(float(z), 3)))
        contributions.sort(key=lambda x: x[1], reverse=True)
        indicators = [f"{name}: deviation={z}" for name, z in contributions[:3]]

        return {
            "engine":     "network_anomaly",
            "result":     result,
            "confidence": round(combined_score, 4),
            "score":      round(combined_score, 4),
            "indicators": indicators,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "details": {
                "ae_score":  round(ae_score, 4),
                "iso_score": round(iso_score, 4),
                "ae_reconstruction_error": round(ae_error, 6),
                "ae_threshold": round(self.threshold, 6),
            }
        }


_detector = None


def get_detector():
    global _detector
    if _detector is None:
        _detector = NetworkAnomalyDetector()
    return _detector
