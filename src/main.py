import subprocess
import time

while True:
    subprocess.run(["python3", "port_scanner/port_scanner.py"])
    time.sleep(3600)