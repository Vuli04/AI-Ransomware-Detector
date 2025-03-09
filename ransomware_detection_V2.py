import os
import psutil
import shutil
import time
import joblib
import logging
import xgboost as xgb
import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from sklearn.preprocessing import StandardScaler
from scapy.all import sniff

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Load trained model and scaler
model = joblib.load("ransomware_xgb_model.pkl")
scaler = joblib.load("scaler.pkl")

# Honeypot file path
HONEYPOT_DIR = "C:\\Users\\Mathobela Vuli\\CYBERSECURITY_TOOLS\\honeypots"

def create_honeypot():
    """Creates a decoy honeypot file to detect unauthorized modifications."""
    if not os.path.exists(HONEYPOT_DIR):
        os.makedirs(HONEYPOT_DIR)
    honeypot_file = os.path.join(HONEYPOT_DIR, "honeypot.txt")
    with open(honeypot_file, "w") as f:
        f.write("This is a protected honeypot file. Unauthorized modifications will trigger alerts.")
    return honeypot_file

HONEYPOT_FILE = create_honeypot()

class FileChangeHandler(FileSystemEventHandler):
    def __init__(self):
        self.file_changes = 0

    def on_modified(self, event):
        if event.src_path == HONEYPOT_FILE:
            logging.warning("⚠️ Honeypot file modified! Possible ransomware detected!")
            auto_response()
        else:
            self.file_changes += 1
            logging.info(f"File modified: {event.src_path}")

    def on_created(self, event):
        self.file_changes += 1
        logging.info(f"File created: {event.src_path}")

    def get_file_changes(self):
        return self.file_changes

# Initialize the file system monitor
def init_file_monitor(path="."):
    handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    logging.info(f"Started file monitor for: {path}")
    return handler, observer

def extract_features(file_monitor_handler):
    """Extracts system and file monitoring features."""
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    file_changes = file_monitor_handler.get_file_changes()
    network_io = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
    process_count = len(list(psutil.process_iter()))
    return [cpu_usage, memory_usage, disk_usage, file_changes, network_io, process_count]

def detect_ransomware(features):
    """Modify prediction threshold to increase sensitivity"""
    scaled_features = scaler.transform([features])
    prediction = model.predict(scaled_features)
    
    # If file changes exceed 5 and model is unsure, treat it as ransomware
    if features[3] > 5 or prediction[0] == 1:
        return 1  # Force ransomware detection
    
    return prediction[0]

def backup_important_files():
    """Automatically backs up important files if ransomware is detected."""
    backup_folder = "C:\\Users\\Mathobela Vuli\\CYBERSECURITY_TOOLS\\backup"
    if not os.path.exists(backup_folder):
        os.makedirs(backup_folder)
    shutil.copytree("C:\\Users\\Mathobela Vuli\\Documents", backup_folder, dirs_exist_ok=True)
    logging.info("✅ Files backed up successfully.")

import shutil
import os

def backup_important_files():
    source_folder = r"C:\Users\Mathobela Vuli\Documents"
    backup_folder = r"C:\Users\Mathobela Vuli\CYBERSECURITY_TOOLS\backup"

    # Create backup folder if it doesn't exist
    os.makedirs(backup_folder, exist_ok=True)

    # List of folders to ignore
    ignore_folders = {"My Music", "My Pictures", "My Videos"}

    for item in os.listdir(source_folder):
        src_path = os.path.join(source_folder, item)
        dst_path = os.path.join(backup_folder, item)

        if item in ignore_folders:
            print(f"Skipping protected folder: {item}")
            continue  # Skip protected folders

        try:
            if os.path.isdir(src_path):
                shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
            else:
                shutil.copy2(src_path, dst_path)
        except PermissionError:
            print(f"Permission denied: {src_path}")

def backup_important_files():
    source_folder = r"C:\Users\Mathobela Vuli\Documents"
    backup_folder = r"C:\Users\Mathobela Vuli\CYBERSECURITY_TOOLS\backup"

    os.makedirs(backup_folder, exist_ok=True)

    allowed_extensions = {".txt", ".pdf", ".docx", ".jpg", ".png"}  # Add more if needed

    for root, _, files in os.walk(source_folder):
        for file in files:
            if any(file.endswith(ext) for ext in allowed_extensions):
                src_path = os.path.join(root, file)
                dst_path = os.path.join(backup_folder, os.path.relpath(src_path, source_folder))

                os.makedirs(os.path.dirname(dst_path), exist_ok=True)

                try:
                    shutil.copy2(src_path, dst_path)
                    print(f"Backed up: {src_path} -> {dst_path}")
                except PermissionError:
                    print(f"Permission denied: {src_path}")


def kill_suspicious_processes():
    """Terminates ransomware-like processes."""
    for proc in psutil.process_iter(['pid', 'name']):
        if any(word in proc.info['name'].lower() for word in ["encrypt", "ransom", "locker"]):
            logging.warning(f"🚨 Killing suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
            psutil.Process(proc.info['pid']).terminate()

def network_monitor(packet):
    """Monitors network traffic for unusual connections."""
    if packet.haslayer('IP'):
        dest_ip = packet['IP'].dst
        if dest_ip in known_malicious_ips:
            logging.warning(f"⚠️ Detected suspicious connection to {dest_ip}. Blocking network access.")
            auto_response()

def auto_response():
    """Automatic response if ransomware is detected."""
    logging.critical("🚨 Ransomware Detected! Taking Immediate Action!")
    backup_important_files()
    kill_suspicious_processes()
    disable_network()

def disable_network():
    """Disables network to prevent ransomware from communicating externally."""
    os.system("ipconfig /release")
    logging.warning("🔌 Network disabled to stop further communication.")

# Start File System Monitor
path_to_monitor = r"C:\Users\Mathobela Vuli\CYBERSECURITY TOOLS AND MONETIZATION"
file_monitor_handler, observer = init_file_monitor(path_to_monitor)

# Monitor system for ransomware
while True:
    features = extract_features(file_monitor_handler)
    prediction = detect_ransomware(features)
    
    print(f"Extracted Features: {features}")
    print(f"Model Prediction: {prediction}")  # ✅ See what the AI thinks

    if prediction == 1:
        auto_response()
    
    time.sleep(1)
