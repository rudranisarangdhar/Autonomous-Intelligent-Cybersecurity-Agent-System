import numpy as np
import pandas as pd
import random
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from datetime import datetime, timedelta

random.seed(42)
np.random.seed(42)


# ================================================================
# ADVANCED CYBER ATTACK + NORMAL TRAFFIC GENERATOR (2025 LEVEL)
# ================================================================
def generate_advanced_flow(n_samples=6000):
    data = []

    attack_types = [
        "benign",
        "dos_flood",
        "dos_slowloris",
        "port_scan",
        "ssh_bruteforce",
        "http_bruteforce",
        "botnet_cnc",
        "data_exfiltration",
        "sql_injection",
        "xss",
        "ransomware_encryption",
        "probe_sweep",
        "syn_flood"
    ]

    weights = [40, 10, 4, 6, 5, 3, 3, 4, 2, 2, 3, 5, 13]

    for i in range(n_samples):

        attack = random.choices(attack_types, weights=weights, k=1)[0]

        # ---------------------------------------------------------
        # BASE NORMAL TRAFFIC FEATURES
        # ---------------------------------------------------------
        duration = np.random.exponential(scale=2)
        src_bytes = int(abs(np.random.normal(500, 300)))
        dst_bytes = int(abs(np.random.normal(400, 200)))
        flag = random.randint(0, 3)
        failed_logins = random.randint(0, 1)
        same_srv_rate = np.random.uniform(0.2, 0.5)
        hot = random.randint(0, 2)
        packets = np.random.randint(2, 20)
        timestamp = datetime.now() + timedelta(seconds=i)

        label = 0  # normal traffic default

        # ================================================================
        # REALISTIC ATTACK SIGNATURES
        # ================================================================

        if attack == "dos_flood":
            src_bytes = np.random.randint(3000, 8000)
            packets = np.random.randint(500, 3000)
            same_srv_rate = np.random.uniform(0.8, 1.0)
            label = 1

        elif attack == "syn_flood":
            dst_bytes = 0
            src_bytes = np.random.randint(5, 100)
            packets = np.random.randint(500, 3000)
            flag = 2
            label = 1

        elif attack == "dos_slowloris":
            duration = np.random.uniform(5, 40)
            packets = np.random.randint(100, 500)
            src_bytes = np.random.randint(10, 50)
            dst_bytes = np.random.randint(5, 20)
            label = 1

        elif attack == "port_scan":
            packets = np.random.randint(200, 600)
            src_bytes = np.random.randint(20, 80)
            dst_bytes = np.random.randint(10, 30)
            hot = np.random.randint(5, 15)
            label = 1

        elif attack == "ssh_bruteforce":
            failed_logins = np.random.randint(5, 20)
            src_bytes = np.random.randint(100, 200)
            dst_bytes = np.random.randint(30, 80)
            label = 1

        elif attack == "http_bruteforce":
            failed_logins = np.random.randint(3, 12)
            hot = np.random.randint(6, 14)
            label = 1

        elif attack == "botnet_cnc":
            src_bytes = np.random.randint(1500, 4000)
            same_srv_rate = np.random.uniform(0.7, 0.95)
            packets = np.random.randint(60, 150)
            label = 1

        elif attack == "data_exfiltration":
            src_bytes = np.random.randint(3000, 15000)
            dst_bytes = np.random.randint(5000, 30000)
            packets = np.random.randint(200, 800)
            label = 1

        elif attack == "sql_injection":
            hot = np.random.randint(10, 25)
            dst_bytes = np.random.randint(600, 1500)
            label = 1

        elif attack == "xss":
            hot = np.random.randint(6, 10)
            dst_bytes = np.random.randint(400, 900)
            label = 1

        elif attack == "ransomware_encryption":
            src_bytes = np.random.randint(5000, 60000)
            dst_bytes = np.random.randint(8000, 70000)
            packets = np.random.randint(400, 2000)
            label = 1

        elif attack == "probe_sweep":
            packets = np.random.randint(300, 700)
            src_bytes = np.random.randint(30, 80)
            hot = np.random.randint(10, 20)
            label = 1

        # ================================================================
        # 🔥 ADVANCED NOISE + STEALTH ATTACKS
        # ================================================================

        # 15% chance: attack pretends to be normal
        if attack != "benign" and random.random() < 0.15:
            label = 0

        # 10% chance: normal traffic looks like an anomaly
        if label == 0 and random.random() < 0.10:
            hot += np.random.randint(4, 12)
            src_bytes += np.random.randint(200, 1000)

        # 5% feature corruption
        if random.random() < 0.05:
            src_bytes = np.random.randint(0, 100)
            dst_bytes = np.random.randint(0, 150)
            hot = np.random.randint(0, 3)

        # 8% mislabeling noise
        if random.random() < 0.08:
            label = 1 - label

        # Non-linear behavioral interaction (makes ML harder)
        interaction = src_bytes * same_srv_rate
        packets += int(interaction % 20)

        # ================================================================
        # FINAL RECORD
        # ================================================================
        data.append([
            duration, src_bytes, dst_bytes, flag, failed_logins,
            hot, same_srv_rate, packets, label, attack, timestamp
        ])

    df = pd.DataFrame(data, columns=[
        "duration", "src_bytes", "dst_bytes", "flag",
        "failed_logins", "hot", "same_srv_rate", "packets",
        "label", "attack_type", "timestamp"
    ])
    return df


# ================================================================
# ML evaluation + saving
# ================================================================
def evaluate_model(model, X_test, y_test):
    preds = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, preds, zero_division=0))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, preds))
    return model.score(X_test, y_test)


def save_model(model, path="model.joblib"):
    joblib.dump(model, path)
