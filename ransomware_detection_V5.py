import os
import psutil
import time
import logging
import subprocess
import smtplib
import pandas as pd
import xgboost as xgb
import numpy as np
from email.mime.text import MIMEText
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
            new_X = new_data.drop(columns=["Benign"])
            new_y = new_data["Benign"]
            
            X_train = pd.concat([X_train, new_X], ignore_index=True)
            y_train = pd.concat([y_train, new_y], ignore_index=True)
            
            model.fit(X_train, y_train)
            model.save_model(model_file)
            logging.info("✅ Model retrained with new data!")
            os.remove(new_samples_file)

def extract_features():
    return np.random.rand(X_train.shape[1])  # Dummy feature extractor

def monitor_files():
    global last_detection_time
    while True:
        features = extract_features()
        prediction = model.predict([features])[0]
        logging.info(f"Model Prediction: {prediction}")
        
        if prediction == 1:
            sample = pd.DataFrame([features], columns=X_train.columns)
            sample["Benign"] = 0
            sample.to_csv(new_samples_file, mode="a", header=not os.path.exists(new_samples_file), index=False)
            logging.warning("🚨 Ransomware detected! Sample logged.")
            retrain_model()
        
        time.sleep(5)

if __name__ == "__main__":
    logging.info("🚀 Starting Ransomware Detection System...")
    monitor_files()
