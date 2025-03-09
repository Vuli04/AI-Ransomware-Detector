import psutil
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from sklearn.model_selection import train_test_split, RandomizedSearchCV
import joblib
from sklearn.preprocessing import StandardScaler
import logging
import xgboost as xgb
from imblearn.over_sampling import SMOTE
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# File system change handler
class FileChangeHandler(FileSystemEventHandler):
    def __init__(self):
        self.file_changes = 0

    def on_modified(self, event):
        if not event.is_directory:
            self.file_changes += 1
            logging.info(f"File modified: {event.src_path}")

    def on_created(self, event):
        if not event.is_directory:
            self.file_changes += 1
            logging.info(f"File created: {event.src_path}")

    def get_file_changes(self):
        return self.file_changes

# Initialize file monitor
def init_file_monitor(path="."):
    handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    logging.info(f"Started file monitor for: {path}")
    return handler, observer

# Feature extraction
def extract_features(file_monitor_handler):
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    file_changes = file_monitor_handler.get_file_changes()
    network_io = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
    process_count = len(list(psutil.process_iter()))

    logging.info(f"Extracted Features - CPU: {cpu_usage}, Memory: {memory_usage}, Disk: {disk_usage}, File Changes: {file_changes}, Network I/O: {network_io}, Process Count: {process_count}")
    return [cpu_usage, memory_usage, disk_usage, file_changes, network_io, process_count]

# Monitoring path
path_to_monitor = r'C:\Users\Mathobela Vuli\CYBERSECURITY TOOLS AND MONETIZATION'
file_monitor_handler, observer = init_file_monitor(path_to_monitor)

# Collecting 500 samples for better training
data_samples = []
labels = []
for _ in range(500):
    data_samples.append(extract_features(file_monitor_handler))
    labels.append(np.random.choice([0, 1], p=[0.7, 0.3]))  # Simulated label distribution
    time.sleep(0.5)

X = np.array(data_samples)
y = np.array(labels)

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Standardize features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Apply SMOTE for balancing
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_train_scaled, y_train)

# XGBoost model tuning with RandomizedSearchCV
xgb_model = xgb.XGBClassifier(scale_pos_weight=len(y_resampled[y_resampled == 0]) / len(y_resampled[y_resampled == 1]))

param_dist = {
    'max_depth': [3, 5, 7],
    'learning_rate': np.linspace(0.01, 0.2, 5),
    'n_estimators': [50, 100, 200],
    'subsample': [0.5, 0.7, 1.0],
    'colsample_bytree': [0.5, 0.7, 1.0],
}

random_search = RandomizedSearchCV(xgb_model, param_distributions=param_dist, n_iter=10, cv=5, scoring='accuracy', random_state=42)
random_search.fit(X_resampled, y_resampled)

# Best Model
best_xgb_model = random_search.best_estimator_
logging.info(f"Best Parameters: {random_search.best_params_}")
logging.info(f"Best Score: {random_search.best_score_}")

# Evaluate model
y_pred = best_xgb_model.predict(X_test_scaled)
logging.info("Classification Report:")
logging.info(classification_report(y_test, y_pred, zero_division=1))
logging.info("Confusion Matrix:")
logging.info(str(confusion_matrix(y_test, y_pred)))

# Save Model and Scaler
joblib.dump(best_xgb_model, 'ransomware_xgb_model.pkl')
joblib.dump(scaler, 'scaler.pkl')

logging.info("Updated model and scaler saved successfully.")

