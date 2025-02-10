from port_scanner.port_scanner import run_scanner
import time
from multiprocessing import Process
from packet_sniffer.packet_sniffer import main as run_sniffer

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
        sniffer_process = Process(target=run_sniffer)
        sniffer_process.start()
        
        run_port_scanner()
        
    except KeyboardInterrupt:
        print("Main program stopping...")
    finally:
        if 'sniffer_process' in locals():
            sniffer_process.terminate()
            sniffer_process.join()