import os
import time

folder = r"C:\Users\Mathobela Vuli\CYBERSECURITY TOOLS AND MONETIZATION"
test_file = os.path.join(folder, "ransomware_test.txt")

with open(test_file, "w") as f:
    f.write("This is a test file for ransomware detection.")

for i in range(10):
    with open(test_file, "a") as f:
        f.write("\nNew line added.")
    os.rename(test_file, os.path.join(folder, f"encrypted_file_{i}.locked"))
    time.sleep(1)
