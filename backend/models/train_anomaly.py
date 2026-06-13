"""
Network Anomaly Detection Model Training
Ensemble: Autoencoder (PyTorch) + Isolation Forest
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

SAVED_DIR = os.path.join(os.path.dirname(__file__), 'saved')
DATA_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'network_traffic.csv')

FEATURES = ['src_bytes', 'dst_bytes', 'duration', 'num_connections',
            'packet_rate', 'protocol_type', 'flag']


class NetworkAutoencoder(nn.Module):
    def __init__(self, input_dim=7):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 4),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


def train(force=False):
    os.makedirs(SAVED_DIR, exist_ok=True)

    ae_path = os.path.join(SAVED_DIR, 'network_autoencoder.pt')
    scaler_path = os.path.join(SAVED_DIR, 'network_scaler.pkl')
    iso_path = os.path.join(SAVED_DIR, 'isolation_forest.pkl')
    threshold_path = os.path.join(SAVED_DIR, 'ae_threshold.npy')

    if not force and all(os.path.exists(p) for p in [ae_path, scaler_path, iso_path, threshold_path]):
        print("[OK] Network anomaly models already exist, skipping training.")
        return

    print("[*] Training Network Anomaly Detection models...")

    # Generate data if missing
    if not os.path.exists(DATA_PATH):
        from data.generate_synthetic import generate_network_traffic
        generate_network_traffic()

    df = pd.read_csv(DATA_PATH)
    X = df[FEATURES].values
    y = df['label'].values

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, scaler_path)

    # Train Isolation Forest on full data
    iso = IsolationForest(n_estimators=200, contamination=0.2, random_state=42)
    iso.fit(X_scaled)
    joblib.dump(iso, iso_path)

    # Train Autoencoder on NORMAL traffic only
    X_normal = X_scaled[y == 0]
    X_tensor = torch.tensor(X_normal, dtype=torch.float32)

    model = NetworkAutoencoder(input_dim=len(FEATURES))
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()

    model.train()
    for epoch in range(60):
        optimizer.zero_grad()
        output = model(X_tensor)
        loss = criterion(output, X_tensor)
        loss.backward()
        optimizer.step()
        if (epoch + 1) % 20 == 0:
            print(f"    Epoch {epoch+1}/60  Loss: {loss.item():.6f}")

    torch.save(model.state_dict(), ae_path)

    # Compute threshold = 95th percentile of reconstruction error on normal data
    model.eval()
    with torch.no_grad():
        recon = model(X_tensor)
        errors = torch.mean((recon - X_tensor) ** 2, dim=1).numpy()
    threshold = float(np.percentile(errors, 95))
    np.save(threshold_path, threshold)

    print(f"[OK] Network anomaly models saved. AE threshold: {threshold:.6f}")


if __name__ == "__main__":
    train(force=True)
