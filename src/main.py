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
        print("Starting packet sniffer process...")
        sniffer_process = Process(target=run_sniffer)
        sniffer_process.start()
        processes.append(sniffer_process)
        print("Packet sniffer process started successfully")
        
        # Port scanner'ı başlatmadan önce kısa bir bekleme ekleyelim
        time.sleep(2)
        
        print("Starting port scanner process...")
        scanner_process = Process(target=run_port_scanner)
        scanner_process.start()
        processes.append(scanner_process)
        print("Port scanner process started successfully")
        
        # Process'leri bekle
        for process in processes:
            process.join()
            
    except KeyboardInterrupt:
        print("\nMain program received keyboard interrupt...")
    except Exception as e:
        print(f"\nMain program error: {e}")
    finally:
        print("Cleaning up processes...")
        for process in processes:
            if process.is_alive():
                print(f"Terminating process {process.name}...")
                process.terminate()
                process.join()
                print(f"Process {process.name} terminated")
        print("All processes cleaned up")