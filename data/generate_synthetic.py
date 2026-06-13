"""
Synthetic Data Generator for AI-Powered Cybersecurity Platform
Generates training data for: Network Anomaly, Malware, and Phishing detectors
"""

import numpy as np
import pandas as pd
import os

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

DATA_DIR = os.path.dirname(os.path.abspath(__file__))


def generate_network_traffic(n_normal=8000, n_anomalous=2000):
    """Generate synthetic network traffic data for anomaly detection."""
    print("[*] Generating network traffic data...")

    # Normal traffic
    normal = pd.DataFrame({
        "src_bytes":       np.random.lognormal(6, 1.5, n_normal).astype(int),
        "dst_bytes":       np.random.lognormal(7, 1.5, n_normal).astype(int),
        "duration":        np.random.exponential(30, n_normal),
        "num_connections": np.random.randint(1, 50, n_normal),
        "packet_rate":     np.random.uniform(1, 200, n_normal),
        "protocol_type":   np.random.choice([0, 1, 2], n_normal, p=[0.6, 0.3, 0.1]),  # tcp, udp, icmp
        "flag":            np.random.choice([0, 1, 2, 3], n_normal, p=[0.7, 0.15, 0.1, 0.05]),
        "label":           0,  # Normal
    })

    # Anomalous traffic (port scans, DDoS, exfiltration)
    anomalous = pd.DataFrame({
        "src_bytes":       np.random.lognormal(3, 3, n_anomalous).astype(int),
        "dst_bytes":       np.random.lognormal(10, 3, n_anomalous).astype(int),
        "duration":        np.random.exponential(0.5, n_anomalous),
        "num_connections": np.random.randint(100, 10000, n_anomalous),
        "packet_rate":     np.random.uniform(500, 50000, n_anomalous),
        "protocol_type":   np.random.choice([0, 1, 2], n_anomalous, p=[0.3, 0.2, 0.5]),
        "flag":            np.random.choice([0, 1, 2, 3], n_anomalous, p=[0.1, 0.2, 0.3, 0.4]),
        "label":           1,  # Anomalous
    })

    df = pd.concat([normal, anomalous], ignore_index=True).sample(frac=1, random_state=RANDOM_SEED)
    path = os.path.join(DATA_DIR, "network_traffic.csv")
    df.to_csv(path, index=False)
    print(f"    Saved {len(df)} records -> {path}")
    return df


def generate_malware_features(n_benign=6000, n_malicious=4000):
    """Generate synthetic PE file feature dataset."""
    print("[*] Generating malware PE feature data...")

    benign = pd.DataFrame({
        "file_size":           np.random.lognormal(13, 1.5, n_benign).astype(int),
        "num_sections":        np.random.randint(3, 8, n_benign),
        "num_imports":         np.random.randint(10, 200, n_benign),
        "num_exports":         np.random.randint(0, 50, n_benign),
        "has_overlay":         np.random.choice([0, 1], n_benign, p=[0.9, 0.1]),
        "entropy":             np.random.uniform(4.0, 6.5, n_benign),
        "virtual_size":        np.random.lognormal(14, 1.2, n_benign).astype(int),
        "suspicious_api_calls":np.random.randint(0, 5, n_benign),
        "packer_detected":     np.random.choice([0, 1], n_benign, p=[0.95, 0.05]),
        "label":               0,  # Benign
    })

    malicious = pd.DataFrame({
        "file_size":           np.random.lognormal(11, 2.5, n_malicious).astype(int),
        "num_sections":        np.random.randint(1, 20, n_malicious),
        "num_imports":         np.random.randint(1, 500, n_malicious),
        "num_exports":         np.random.randint(0, 10, n_malicious),
        "has_overlay":         np.random.choice([0, 1], n_malicious, p=[0.4, 0.6]),
        "entropy":             np.random.uniform(6.5, 8.0, n_malicious),
        "virtual_size":        np.random.lognormal(12, 2.5, n_malicious).astype(int),
        "suspicious_api_calls":np.random.randint(5, 50, n_malicious),
        "packer_detected":     np.random.choice([0, 1], n_malicious, p=[0.3, 0.7]),
        "label":               1,  # Malicious
    })

    df = pd.concat([benign, malicious], ignore_index=True).sample(frac=1, random_state=RANDOM_SEED)
    path = os.path.join(DATA_DIR, "malware_features.csv")
    df.to_csv(path, index=False)
    print(f"    Saved {len(df)} records -> {path}")
    return df


def generate_phishing_emails(n_legit=5000, n_phishing=5000):
    """Generate synthetic email text dataset for phishing detection."""
    print("[*] Generating phishing email data...")

    legit_subjects = [
        "Your invoice is ready", "Meeting rescheduled", "Project update",
        "Weekly report", "Team lunch tomorrow", "Quarterly review",
        "Your order has shipped", "Subscription renewed", "New feature release",
        "Welcome to the team"
    ]
    phishing_subjects = [
        "URGENT: Verify your account", "Your account has been suspended",
        "Action required: Update billing", "Security alert - login attempt",
        "Claim your reward NOW", "Your package could not be delivered",
        "Final notice: Payment overdue", "Unusual sign-in activity",
        "Confirm your identity immediately", "Limited time offer expires soon"
    ]

    legit_bodies = [
        "Please find attached the latest report for your review.",
        "We wanted to update you on the project progress this week.",
        "Your subscription has been successfully renewed.",
        "The team meeting has been moved to Thursday at 3 PM.",
        "Here is the summary of our quarterly performance metrics.",
        "Your shipment is on its way and will arrive by Friday.",
        "Welcome aboard! We are excited to have you on the team.",
        "A new feature has been released in the latest product update.",
        "Please review the attached invoice and let us know if you have questions.",
        "Looking forward to seeing you at the team lunch tomorrow.",
    ]
    phishing_bodies = [
        "Click here immediately to verify your account or it will be suspended: http://192.168.1.100/verify",
        "URGENT: Your account has been compromised. Update your password NOW at http://secure-login.xyz",
        "You have won a $500 gift card! Click now to claim before it expires: http://bit.ly/win500",
        "Dear customer, your payment failed. Update billing info here: http://paypal-update.net",
        "Your Apple ID has been locked. Verify at http://apple-id-verify.com immediately.",
        "Suspicious login detected from Russia. Confirm your identity: http://login-verify.info",
        "Your package is held at customs. Pay $2 handling fee: http://track-pkg.xyz/pay",
        "Final warning: Your account will be deleted unless you login NOW: http://10.0.0.1/login",
        "Congratulations! You are selected for a free iPhone. Just click and enter your details!",
        "Your bank account shows unauthorized access. Call 1-800-FAKE or visit http://bank-alert.net",
    ]

    legit_data = []
    for i in range(n_legit):
        subject = np.random.choice(legit_subjects)
        body = np.random.choice(legit_bodies)
        legit_data.append({
            "text": f"{subject} {body}",
            "label": 0
        })

    phish_data = []
    for i in range(n_phishing):
        subject = np.random.choice(phishing_subjects)
        body = np.random.choice(phishing_bodies)
        phish_data.append({
            "text": f"{subject} {body}",
            "label": 1
        })

    df = pd.concat([pd.DataFrame(legit_data), pd.DataFrame(phish_data)], ignore_index=True)
    df = df.sample(frac=1, random_state=RANDOM_SEED)
    path = os.path.join(DATA_DIR, "phishing_emails.csv")
    df.to_csv(path, index=False)
    print(f"    Saved {len(df)} records -> {path}")
    return df


if __name__ == "__main__":
    print("=" * 60)
    print("  Synthetic Cybersecurity Dataset Generator")
    print("=" * 60)
    generate_network_traffic()
    generate_malware_features()
    generate_phishing_emails()
    print("\n[OK] All datasets generated successfully.")
