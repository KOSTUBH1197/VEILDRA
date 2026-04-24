import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os

class MLThreatDetector:
    def __init__(self):
        self.model = None
        self.features = [
            'Flow Packets/s',
            'Flow Bytes/s',
            'Packet Length Mean',
            'Packet Length Std',
            'Flow IAT Mean',
            'Flow IAT Std',
            'Fwd Packets/s',
            'Total Fwd Packets',
            'ACK Flag Count',
            'PSH Flag Count'
        ]
        self.model_path = '/home/kostubh/veildra/data/veildra_model.pkl'
        self.threshold = 0.3

    def load_data(self, csv_path, sample_size=200000):
        print("[ML] Loading dataset...")
        df = pd.read_csv(csv_path, nrows=sample_size, low_memory=False)
        print(f"[ML] Loaded {len(df)} rows")
        print(f"[ML] Attack types: {df['Attack Type'].value_counts().to_dict()}")
        return df

    def prepare_features(self, df):
        print("[ML] Preparing features...")
        available = [f for f in self.features if f in df.columns]
        X = df[available].copy()
        y = (df['Attack Type'] != 'Normal Traffic').astype(int)
        # Remove duplicate rows to prevent data leakage
        combined = X.copy()
        combined['label'] = y.values
        combined = combined.drop_duplicates()
        X = combined.drop('label', axis=1)
        y = combined['label']
        print(f"[ML] After deduplication: {len(X)} samples")
        X = X.fillna(0)
        X = X.replace([np.inf, -np.inf], 0)
        print(f"[ML] Features used: {available}")
        print(f"[ML] Normal samples: {sum(y==0)}, Attack samples: {sum(y==1)}")
        return X, y

    def train(self, csv_path):
        print("\n[ML] Starting VEILDRA ML Model Training")
        print("=" * 50)
        df = self.load_data(csv_path)
        X, y = self.prepare_features(df)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        print(f"[ML] Training on {len(X_train)} samples...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\n[ML] Training Complete!")
        print(f"[ML] Accuracy: {round(accuracy * 100, 2)}%")
        print(f"\n[ML] Classification Report:")
        print(classification_report(y_test, y_pred,
              target_names=['Normal', 'Attack']))
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"\n[ML] Model saved to {self.model_path}")
        return accuracy

    def load_model(self):
        if os.path.exists(self.model_path):
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            print("[ML] Model loaded successfully")
            return True
        return False

    def predict(self, flow_features):
        if self.model is None:
            return False, 0.0
        features_df = pd.DataFrame([[
            flow_features.get('flow_packets_per_sec', 0),
            flow_features.get('flow_bytes_per_sec', 0),
            flow_features.get('packet_length_mean', 0),
            flow_features.get('packet_length_std', 0),
            flow_features.get('flow_iat_mean', 0),
            flow_features.get('flow_iat_std', 0),
            flow_features.get('fwd_packets_per_sec', 0),
            flow_features.get('total_fwd_packets', 0),
            flow_features.get('ack_flag_count', 0),
            flow_features.get('psh_flag_count', 0)
        ]], columns=[
            'Flow Packets/s',
            'Flow Bytes/s',
            'Packet Length Mean',
            'Packet Length Std',
            'Flow IAT Mean',
            'Flow IAT Std',
            'Fwd Packets/s',
            'Total Fwd Packets',
            'ACK Flag Count',
            'PSH Flag Count'
        ])
        probability = self.model.predict_proba(features_df)[0][1]
        is_attack = probability > self.threshold
        return bool(is_attack), float(probability)


if __name__ == "__main__":
    detector = MLThreatDetector()
    csv_path = '/home/kostubh/veildra/data/cicids2017/cicids2017_cleaned.csv'
    accuracy = detector.train(csv_path)

    print("\n[ML] Testing with sample flows...")

    normal_flow = {
        'flow_packets_per_sec': 5.0,
        'flow_bytes_per_sec': 1200.0,
        'packet_length_mean': 800.0,
        'packet_length_std': 200.0,
        'flow_iat_mean': 50000.0,
        'flow_iat_std': 10000.0,
        'fwd_packets_per_sec': 2.5,
        'total_fwd_packets': 10,
        'ack_flag_count': 5,
        'psh_flag_count': 2
    }

    is_attack, prob = detector.predict(normal_flow)
    print(f"\nNormal traffic test: Attack={is_attack}, Probability={round(prob, 3)}")

    attack_flow = {
        'flow_packets_per_sec': 2.190772903,
        'flow_bytes_per_sec': 421.6242032,
        'packet_length_mean': 176.4166667,
        'packet_length_std': 317.4711034,
        'flow_iat_mean': 502105.9,
        'flow_iat_std': 1568379.157,
        'fwd_packets_per_sec': 1.194967038,
        'total_fwd_packets': 6,
        'ack_flag_count': 0,
        'psh_flag_count': 1
    }

    is_attack, prob = detector.predict(attack_flow)
    print(f"Attack traffic test: Attack={is_attack}, Probability={round(prob, 3)}")
