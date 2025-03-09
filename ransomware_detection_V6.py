import os
import psutil
import sys
import time
import logging
import subprocess
import hashlib
import pandas as pd
import xgboost as xgb
import numpy as np
from sklearn.model_selection import train_test_split

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("ransomware_logs.txt", mode="a", encoding="utf-8"),  # File logging
        logging.StreamHandler(sys.stdout)  # Console logging (UTF-8 compatible)
    ]
)

# Dataset and Model Paths
data_file = "data_file.csv"
new_samples_file = "new_ransomware_samples.csv"
model_file = "ransomware_model.json"

# Load dataset
try:
    df = pd.read_csv(data_file)
    logging.info("✅ Dataset loaded successfully!")
except Exception as e:
    logging.error(f"Failed to load dataset: {e}")
    exit()

# Prepare dataset
df = df.drop(columns=["FileName", "md5Hash"], errors="ignore").dropna()
df = df.astype(np.float32)

X = df.drop(columns=["Benign"])
y = df["Benign"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Load or Train Model
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric="logloss")
if os.path.exists(model_file):
    model.load_model(model_file)
    logging.info("✅ Model loaded successfully!")
else:
    model.fit(X_train, y_train)
    model.save_model(model_file)
    logging.info("✅ Model trained and saved successfully!")

def retrain_model():
    if os.path.exists(new_samples_file):
        new_data = pd.read_csv(new_samples_file)
        if not new_data.empty:
            global X_train, y_train, model
            new_X = new_data.drop(columns=["Benign"], errors="ignore")
            new_y = new_data["Benign"]

            # Remove duplicate entries
            new_X, new_y = new_X.drop_duplicates().reset_index(drop=True), new_y.drop_duplicates().reset_index(drop=True)

            X_train = pd.concat([X_train, new_X], ignore_index=True)
            y_train = pd.concat([y_train, new_y], ignore_index=True)

            model.fit(X_train, y_train)
            model.save_model(model_file)
            logging.info("✅ Model retrained with new data!")
            os.remove(new_samples_file)

def extract_features(proc):
    """Extract relevant features from a process."""
    try:
        pid = proc.info['pid']
        name = proc.info['name']
        cpu_usage = proc.info['cpu_percent']
        memory_usage = proc.info['memory_info'].rss  # RAM usage

        process_hash = int(hashlib.md5(name.encode()).hexdigest(), 16) % (10**8)
        return [process_hash, cpu_usage, memory_usage]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def kill_process(pid):
    try:
        if os.name == "nt":
            os.system(f"taskkill /PID {pid} /F")  # Windows
        else:
            os.system(f"kill -9 {pid}")  # Linux/macOS
        logging.warning(f"❌ Terminated ransomware process (PID: {pid})")
    except Exception as e:
        logging.error(f"❌ Failed to terminate process {pid}: {e}")

def monitor_system():
    logging.info("Monitoring system for ransomware activity...")
    while True:
        detected = False  # Track if ransomware is detected
        logging.info("🔍 Scanning processes...")

        for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_info']):
            try:
                process_name = proc.info['name'].lower()
                process_pid = proc.info['pid']
                cpu_usage = proc.info['cpu_percent']

                logging.info(f"🔎 Running Process: {process_name} (PID: {process_pid}) | CPU: {cpu_usage}%")

                # Detect suspicious processes
                if "fake_ransom" in process_name or "ransom" in process_name:
                    logging.warning(f"🚨 Suspicious Process Detected: {process_name} (PID: {process_pid})")

                    features = extract_features(proc)
                    if features:
                        feature_names = X_train.columns.tolist()
                        if len(features) == len(feature_names):
                            features = np.array(features).reshape(1, -1)
                            prediction = model.predict(features)[0]
                        else:
                            logging.error("🚨 Feature size mismatch! Skipping prediction.")
                            continue

                        if prediction == 1:
                            logging.critical(f"🚨🚨 RANSOMWARE DETECTED: {process_name} (PID: {process_pid}) 🚨🚨")
                            detected = True

                            sample = pd.DataFrame([features], columns=X_train.columns)
                            sample["Benign"] = 0
                            sample.to_csv(new_samples_file, mode="a", header=not os.path.exists(new_samples_file), index=False)
                            logging.warning("🚨 Sample logged. Retraining model...")
                            retrain_model()

                            kill_process(process_pid)

                if cpu_usage > 30:
                    logging.warning(f"⚠️ High CPU usage detected: {process_name} (PID: {process_pid})")

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        if not detected:
            logging.info("✅ No ransomware detected.")
        time.sleep(5)

if __name__ == "__main__":
    monitor_system()