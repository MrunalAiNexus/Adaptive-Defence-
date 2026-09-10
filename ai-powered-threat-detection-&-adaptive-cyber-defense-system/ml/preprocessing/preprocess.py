"""
NSL-KDD Dataset Preprocessing Script
Honours Computer Science Major Project
"""

import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

# Canonical NSL-KDD Feature Names
FEATURE_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty_level'
]

# Mapping NSL-KDD specific attack names to primary 5 classes
ATTACK_MAPPING = {
    'normal': 'BENIGN',
    # DoS
    'neptune': 'DOS', 'back': 'DOS', 'land': 'DOS', 'pod': 'DOS', 'smurf': 'DOS',
    'teardrop': 'DOS', 'mailbomb': 'DOS', 'apache2': 'DOS', 'processtable': 'DOS', 'udpstorm': 'DOS',
    # Probe
    'ipsweep': 'PROBE', 'nmap': 'PROBE', 'portsweep': 'PROBE', 'satan': 'PROBE', 'mscan': 'PROBE', 'saint': 'PROBE',
    # R2L (Remote to Local / Brute Force)
    'ftp_write': 'BRUTE_FORCE', 'guess_passwd': 'BRUTE_FORCE', 'imap': 'BRUTE_FORCE',
    'multihop': 'BRUTE_FORCE', 'phf': 'BRUTE_FORCE', 'spy': 'BRUTE_FORCE', 'warezclient': 'BRUTE_FORCE',
    'warezmaster': 'BRUTE_FORCE', 'sendmail': 'BRUTE_FORCE', 'named': 'BRUTE_FORCE', 'snmpgetattack': 'BRUTE_FORCE',
    'snmpguess': 'BRUTE_FORCE', 'xlock': 'BRUTE_FORCE', 'xsnoop': 'BRUTE_FORCE', 'httptunnel': 'BRUTE_FORCE',
    # U2R (User to Root / Bot / Buffer Overflow)
    'buffer_overflow': 'BOT', 'loadmodule': 'BOT', 'perl': 'BOT', 'rootkit': 'BOT',
    'ps': 'BOT', 'sqlattack': 'BOT', 'xterm': 'BOT'
}

def load_and_clean_data(file_path: str) -> pd.DataFrame:
    """Loads dataset from CSV, assigning standard NSL-KDD column names."""
    print(f"[*] Loading dataset from: {file_path}")
    if not os.path.exists(file_path):
        print(f"[!] Warning: File {file_path} not found. Generating synthetic NSL-KDD compliant benchmark data.")
        return generate_synthetic_nsl_kdd(2500)

    df = pd.read_csv(file_path, names=FEATURE_NAMES, header=None)
    # Map attack types to standard threat classes
    df['threat_class'] = df['attack_type'].map(lambda a: ATTACK_MAPPING.get(str(a).strip().lower(), 'OTHER_MALICIOUS'))
    return df

def generate_synthetic_nsl_kdd(num_samples=2500) -> pd.DataFrame:
    """Generates synthetic NSL-KDD formatted sample to enable zero-setup execution."""
    np.random.seed(42)
    classes = ['BENIGN'] * 1500 + ['DOS'] * 500 + ['PROBE'] * 300 + ['BRUTE_FORCE'] * 150 + ['BOT'] * 50
    np.random.shuffle(classes)

    data = {
        'duration': np.random.exponential(12.0, num_samples),
        'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], num_samples, p=[0.8, 0.15, 0.05]),
        'service': np.random.choice(['http', 'ssh', 'ftp', 'dns', 'other'], num_samples),
        'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTO'], num_samples, p=[0.75, 0.15, 0.08, 0.02]),
        'src_bytes': np.random.lognormal(6.5, 1.8, num_samples),
        'dst_bytes': np.random.lognormal(7.2, 1.5, num_samples),
        'num_failed_logins': [np.random.choice([0, 1, 3, 5], p=[0.96, 0.02, 0.01, 0.01]) if c != 'BRUTE_FORCE' else np.random.choice([3, 5, 8]) for c in classes],
        'count': [np.random.randint(1, 60) if c != 'DOS' else np.random.randint(200, 512) for c in classes],
        'dst_host_count': [np.random.randint(1, 100) if c != 'PROBE' else np.random.randint(180, 255) for c in classes],
        'dst_host_srv_count': np.random.randint(1, 255, num_samples),
        'threat_class': classes
    }
    return pd.DataFrame(data)

def preprocess_pipeline(df: pd.DataFrame, output_dir: str = 'ml/saved_models'):
    os.makedirs(output_dir, exist_ok=True)
    
    # Categorical encoding
    encoders = {}
    for col in ['protocol_type', 'service', 'flag']:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le
            
    # Numerical scaling
    num_cols = ['duration', 'src_bytes', 'dst_bytes', 'num_failed_logins', 'count', 'dst_host_count', 'dst_host_srv_count']
    scaler = StandardScaler()
    df[num_cols] = scaler.fit_transform(df[num_cols])
    
    # Save transformers
    joblib.dump(scaler, os.path.join(output_dir, 'scaler.joblib'))
    joblib.dump(encoders, os.path.join(output_dir, 'encoders.joblib'))
    print(f"[+] Transformers successfully saved in {output_dir}")
    
    X = df[num_cols + ['protocol_type', 'service', 'flag']]
    y = df['threat_class']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    return X_train, X_test, y_train, y_test

if __name__ == '__main__':
    df = load_and_clean_data('ml/data/KDDTrain+.txt')
    X_train, X_test, y_train, y_test = preprocess_pipeline(df)
    print(f"[+] Preprocessed dataset ready. Training shape: {X_train.shape}, Test shape: {X_test.shape}")
