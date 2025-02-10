import subprocess
import time

while True:
    subprocess.run(["python3", "src/main.py"])
    time.sleep(3600)