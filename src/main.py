from port_scanner.port_scanner import run_scanner
from packet_sniffer.packet_sniffer import main as run_packet_sniffer
import time
import subprocess
from threading import Thread

def run_packet_sniffer():
    try:
        run_packet_sniffer()
    except subprocess.CalledProcessError as e:
        print(f"Packet sniffer error: {e}")
    except KeyboardInterrupt:
        print("Packet sniffer stopping...")

def run_port_scanner():
    while True:
        try:
            run_scanner()
            print("Scanning completed successfully. Next scan in 1 hour...")
            time.sleep(3600)
        except KeyboardInterrupt:
            print("Port scanner stopping...")
            break
        except Exception as e:
            print(f"Port Scanner Error: {e}")
            time.sleep(5)
            continue

if __name__ == "__main__":
    try:
        # Packet sniffer'ı ayrı bir thread'de başlat
        sniffer_thread = Thread(target=run_packet_sniffer)
        sniffer_thread.daemon = True  # Ana program kapandığında thread'i otomatik sonlandır
        sniffer_thread.start()
        
        # Port scanner'ı ana thread'de çalıştır
        run_port_scanner()
        
    except KeyboardInterrupt:
        print("\nMain program stopping...")