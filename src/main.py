from port_scanner.port_scanner import run_scanner
import time
import subprocess

if __name__ == "__main__":
    while True:
        try:
            subprocess.run(["python3", "src/packet_sniffer/packet_sniffer.py"])
            run_scanner()
            print("Scanning completed successfully. Next scan in 1 hour...")
            time.sleep(3600)
        except KeyboardInterrupt:
            print("Exiting program...")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)
            continue