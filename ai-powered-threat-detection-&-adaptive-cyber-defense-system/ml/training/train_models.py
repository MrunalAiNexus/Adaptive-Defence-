"""
Model Training Script for Classical Machine Learning
Compares Logistic Regression (Baseline) vs Random Forest Ensemble
Honours Computer Science Major Project
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

from ml.preprocessing.preprocess import load_and_clean_data, preprocess_pipeline

def train_and_evaluate(dataset_path='ml/data/KDDTrain+.txt', output_dir='ml/saved_models'):
    print("[*] Starting Model Training Pipeline...")
    df = load_and_clean_data(dataset_path)
    X_train, X_test, y_train, y_test = preprocess_pipeline(df, output_dir=output_dir)

    # 1. Baseline Model: Logistic Regression
    print("\n--- Training Model 1: Logistic Regression (L2 Baseline) ---")
    lr_model = LogisticRegression(max_iter=1000, multi_class='ovr', solver='lbfgs', random_state=42)
    lr_model.fit(X_train, y_train)
    lr_preds = lr_model.predict(X_test)
    lr_acc = accuracy_score(y_test, lr_preds)
    print(f"[+] Logistic Regression Accuracy: {lr_acc * 100:.2f}%")
    print(classification_report(y_test, lr_preds, zero_division=0))
    joblib.dump(lr_model, os.path.join(output_dir, 'logistic_regression_baseline.joblib'))

    # 2. Selected Model: Random Forest Ensemble (100 Trees)
    print("\n--- Training Model 2: Random Forest Classifier (Ensemble) ---")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        criterion='gini',
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    rf_acc = accuracy_score(y_test, rf_preds)
    print(f"[+] Random Forest Accuracy: {rf_acc * 100:.2f}%")
    print(classification_report(y_test, rf_preds, zero_division=0))
    joblib.dump(rf_model, os.path.join(output_dir, 'random_forest_model.joblib'))

    # Extract Feature Importances
    feature_names = list(X_train.columns)
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    print("\n--- Top Feature Importances (Gini-Splitting) ---")
    for rank, idx in enumerate(indices[:8]):
        print(f"{rank + 1}. {feature_names[idx]}: {importances[idx] * 100:.2f}%")

    print(f"\n[+] Both models trained and exported into {output_dir}")

if __name__ == '__main__':
    train_and_evaluate()
