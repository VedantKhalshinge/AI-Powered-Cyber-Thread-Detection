# ==============================================================================
# Copyright (c) 2026 Vedant Khalshinge. All Rights Reserved.
# 
# This file is part of the AI-Powered Cyber Threat Detection System.
# Unauthorized copying of this file, via any medium, is strictly prohibited.
# Proprietary and confidential.
# ==============================================================================

"""
Phishing Detection Model Training
TF-IDF (unigrams+bigrams) + Random Forest
"""

import os
import sys
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

SAVED_DIR = os.path.join(os.path.dirname(__file__), 'saved')
DATA_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'phishing_emails.csv')


def train(force=False):
    os.makedirs(SAVED_DIR, exist_ok=True)

    model_path = os.path.join(SAVED_DIR, 'phishing_pipeline.pkl')

    if not force and os.path.exists(model_path):
        print("[OK] Phishing model already exists, skipping training.")
        return

    print("[*] Training Phishing Detection model...")

    # Generate data if missing
    if not os.path.exists(DATA_PATH):
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
        from data.generate_synthetic import generate_phishing_emails
        generate_phishing_emails()

    df = pd.read_csv(DATA_PATH)
    X = df['text'].values
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words='english',
            min_df=2,
        )),
        ('clf', RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            random_state=42,
            n_jobs=-1,
        )),
    ])

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    joblib.dump(pipeline, model_path)
    print(f"[OK] Phishing model saved -> {model_path}")


if __name__ == "__main__":
    train(force=True)
