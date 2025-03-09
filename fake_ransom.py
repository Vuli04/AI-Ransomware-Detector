import os
import time
import random
import multiprocessing
from cryptography.fernet import Fernet

# Generate a fake encryption key
key = Fernet.generate_key()
cipher = Fernet(key)

# Create a dummy file
file_name = "test_victim_file.txt"
with open(file_name, "w") as f:
    f.write("This is a test file for ransomware simulation.")

# Fake encryption (simulate ransomware behavior)
def encrypt_file():
    with open(file_name, "rb") as f:
        data = f.read()
    encrypted_data = cipher.encrypt(data)
    with open(file_name, "wb") as f:
        f.write(encrypted_data)
    print("🔒 Fake Ransomware: File Encrypted!")

# Simulate high CPU usage indefinitely
def high_cpu_usage():
    while True:
        _ = [random.random() ** 10000 for _ in range(100000)]

if __name__ == "__main__":
    print("🚨 Fake Ransomware Running...")

    # Run encryption and high CPU usage in separate processes
    encrypt_file()
    
    # Rename process for better detection
    multiprocessing.current_process().name = "fake_ransom"

    # Start high CPU process
    cpu_process = multiprocessing.Process(target=high_cpu_usage, name="fake_ransom")
    cpu_process.start()

    cpu_process.join()  # Keep it running
