from port_scanner.port_scanner import run_scanner
import time
from multiprocessing import Process
from packet_sniffer.packet_sniffer import main as run_sniffer

def run_port_scanner():
    print("Port scanner started...")
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
    processes = []
    try:
        # Start packet sniffer
        sniffer_process = Process(target=run_sniffer)
        sniffer_process.start()
        processes.append(sniffer_process)
        
        # Start port scanner
        scanner_process = Process(target=run_port_scanner)
        scanner_process.start()
        processes.append(scanner_process)
        
        # Wait for processes to complete
        for process in processes:
            process.join()
            
    except KeyboardInterrupt:
        print("\nMain program stopping...")
    finally:
        # Terminate all processes
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join()