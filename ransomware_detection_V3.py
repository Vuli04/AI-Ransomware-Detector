import os
import psutil
import time
import logging
import subprocess
import smtplib
from email.mime.text import MIMEText
import xgboost as xgb
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from scipy.stats import entropy

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ✅ Generate a dummy .exe file if it doesn't exist
exe_file_path = "test.exe"
if not os.path.exists(exe_file_path):
    with open(exe_file_path, "wb") as f:
        f.write(b"\x4D\x5A")  # Writes "MZ" (signature of an EXE file)
    print("✅ Dummy EXE file created!")

# Load dataset
try:
    df = pd.read_csv("data_file.csv")
    logging.info("✅ Dataset loaded successfully!")
    print(df.head())  # Show first few rows
except Exception as e:
    logging.error(f"Failed to load dataset: {e}")
    exit()

# Ensure correct column names
logging.info(f"Dataset columns: {df.columns.tolist()}")

# Check if the label column exists
label_column = "Benign"
if label_column not in df.columns:
    logging.error(f"Column '{label_column}' not found in dataset!")
    exit()

# Drop non-numeric columns (Modify based on your dataset)
df = df.drop(columns=["FileName", "md5Hash"], errors="ignore")

# Handle missing values
df = df.dropna()

# Reduce dataset size (Optional)
df = df.sample(n=min(5000, len(df)), random_state=42)

# Convert to float32 for lower memory usage
df = df.astype(np.float32)

# Split into features (X) and labels (y)
X = df.drop(columns=[label_column])
y = df[label_column]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and train model
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric="logloss")
model.fit(X_train, y_train)

# Save model
model.save_model("ransomware_model.json")
logging.info("✅ Model saved successfully!")

# Load trained model
model.load_model("ransomware_model.json")
logging.info("✅ Model loaded successfully!")

# Evaluate model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
logging.info(f"✅ Model Accuracy: {accuracy * 100:.2f}%")

# Detection system state variables
last_detection_time = 0
cooldown_period = 15  # 15 seconds cooldown
network_disabled = False

def disable_network():
    """Disables network to prevent ransomware communication."""
    global network_disabled
    if not network_disabled:
        logging.warning("🚨 Ransomware Detected! Disabling network.")
        try:
            if os.name == "nt":  # Windows
                subprocess.run("ipconfig /release", shell=True)
            else:  # Linux/macOS
                subprocess.run(["nmcli", "radio", "wifi", "off"], check=True)
            network_disabled = True
            logging.info("🔴 Network disabled to stop further communication.")
        except Exception as e:
            logging.error(f"Failed to disable network: {e}")
    else:
        logging.info("Network already disabled, skipping action.")

def terminate_suspicious_processes():
    """Kills processes with high CPU/Disk usage to stop ransomware activity."""
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'io_counters']):
        try:
            cpu_usage = proc.info['cpu_percent']
            io_counters = proc.info['io_counters']
            disk_usage = io_counters.write_bytes if io_counters else 0

            if cpu_usage > 50 or disk_usage > 10**7:  # High CPU & Disk usage
                logging.warning(f"Suspicious Process: {proc.info['name']} (PID: {proc.info['pid']}) | CPU: {cpu_usage}% | Disk: {disk_usage} bytes")
                proc.kill()
                logging.info(f"Killed {proc.info['name']} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def send_alert(email, subject, message):
    """Sends an email alert when ransomware is detected."""
    sender_email = os.getenv("EMAIL_USER")
    sender_password = os.getenv("EMAIL_PASS")
    
    if not sender_email or not sender_password:
        logging.error("Email credentials not set in environment variables!")
        return

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = email
    
    try:
        server = smtplib.SMTP("smtp.example.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
        logging.info("🔔 Alert email sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def extract_features(file_path):
    try:
        # Extract relevant features (dummy values for testing)
        features = {
            "Machine": 34404,  # Example architecture type
            "DebugSize": 0,  # No debug symbols
            "DebugRVA": 0,
            "MajorImageVersion": 0,
            "MajorOSVersion": 6,  # Common OS version
            "ExportRVA": 0,
            "ExportSize": 0,
            "IatVRA": 4096,
            "MajorLinkerVersion": 14,
            "MinorLinkerVersion": 16,
            "NumberOfSections": 4,
            "SizeOfStackReserve": 1048576,
            "DllCharacteristics": 33088,
            "ResourceSize": 4096,
            "BitcoinAddresses": 0  # No bitcoin addresses in dummy file
        }
        
        # Convert dictionary values to list (keeping order same as dataset)
        feature_values = [features[col] for col in [
            "Machine", "DebugSize", "DebugRVA", "MajorImageVersion", "MajorOSVersion",
            "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion", "MinorLinkerVersion",
            "NumberOfSections", "SizeOfStackReserve", "DllCharacteristics", "ResourceSize",
            "BitcoinAddresses"
        ]]
        
        return feature_values

    except Exception as e:
        logging.error(f"Error extracting features: {e}")
        return [0] * 15  # Return dummy values in case of error


def monitor_files():
    """Continuously monitors files for ransomware activity."""
    global last_detection_time
    while True:
        file_path = "test.exe"
        
        if not os.path.exists(file_path):
            logging.warning(f"File '{file_path}' not found. Skipping...")
            time.sleep(5)
            continue
        
        extracted_features = extract_features(file_path)
        
        if len(extracted_features) != X_train.shape[1]:
            logging.error("Feature mismatch! Check feature extraction process.")
            return
        
        prediction = model.predict([extracted_features])[0]
        
        logging.info(f"Extracted Features: {extracted_features}")
        logging.info(f"Model Prediction: {prediction}")
        
        if prediction == 1:
            current_time = time.time()
            if current_time - last_detection_time > cooldown_period:
                disable_network()
                terminate_suspicious_processes()
                send_alert("admin@example.com", "🚨 Ransomware Detected!", "Immediate action taken on suspicious activity.")
                last_detection_time = current_time
            else:
                logging.info("Cooldown active, skipping duplicate detection.")
        
        time.sleep(5)  # Adjust as needed

if __name__ == "__main__":
    logging.info("🚀 Starting Ransomware Detection System...")
    monitor_files()
