import sys
import socket
from datetime import datetime
import ipaddress
from port_scanner.populer_ports import POPULAR_PORTS
from ip_discover.ip_discover import main as ip_discover
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple
import json

with open("config.json", "r") as f:
    config_file = json.load(f)


def scan_port(target_port: Tuple[str, int]) -> Tuple[int, bool, str]:
    target, port = target_port
    for _ in range(2):  # Her portu 2 kez kontrol et
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1.0)  # Timeout süresini 1 saniyeye çıkardım
            result = s.connect_ex((target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                    s.close()
                    return port, True, service
                except:
                    s.close()
                    return port, True, "unknown"
            s.close()
        except:
            try:
                s.close()
            except:
                pass
            continue
    return port, False, None

def run_scanner():
    MAX_WORKERS = config_file["scanner"]["thread_count"]  # Thread sayısını dengeli bir değere ayarladım
    BATCH_SIZE = config_file["scanner"]["batch_size"]  # Batch size'ı dengeli bir değere ayarladım
    
    scan_type = str(config_file["scanner"]["scan_type"])

    if scan_type not in ['1', '2']:
        print("Please enter a valid option (1 or 2)")
        sys.exit()

    if scan_type == '1':
        target = str(config_file["scanner"]["target"])
        try:
            ipaddress.ip_address(target)
            targets = [target]
        except ValueError:
            print("Invalid IP address")
            sys.exit()
    else:
        target_range = str(config_file["scanner"]["target_range"])
        try:
            # ip_network = ipaddress.ip_network(target_range)
            # targets = list(ip_network.hosts())
            targets = ip_discover(target_range)
        except ValueError:
            print("Invalid IP range format. Please use CIDR notation (example: 192.168.1.0/24)")
            sys.exit()

    print("-" * 50)
    print("Scan started at: " + str(datetime.now()))
    print("Scanning target(s): " + (target if scan_type == '1' else target_range))
    print("-" * 50)

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for ip in targets:
                target = str(ip)
                print(f"\nScanning target: {target}")
                print("Scanning ports 1-10000...")
                
                open_ports = []
                scan_tasks = []

                common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
                for port in common_ports:
                    scan_tasks.append((target, port))
                
                if config_file["scanner"]["port_range_type"] == "1":
                    for port in range(1, 10001):
                        if port not in common_ports:
                            scan_tasks.append((target, port))
                elif config_file["scanner"]["port_range_type"] == "2":
                    for port in POPULAR_PORTS:
                        if port not in common_ports:
                            scan_tasks.append((target, port))

                other_common_ports = [10010, 32768, 32771, 49152, 49153, 49154, 49155, 49156, 49157, 50000,62078]
                for iport in other_common_ports:
                    if port not in common_ports:
                        scan_tasks.append((target, port))

                for i in range(0, len(scan_tasks), BATCH_SIZE):
                    batch = scan_tasks[i:i + BATCH_SIZE]
                    results = executor.map(scan_port, batch)
                    
                    for result in results:
                        if result[1]:
                            open_ports.append(result)
                
                if open_ports:
                    print(f"\nOpen ports for {target}:")
                    for port, _, service in sorted(open_ports):
                        print("Port {:<6} | State: open | Protocol: TCP | Service: {}".format(port, service))
                else:
                    print(f"\nNo open ports found for {target}")
                
                print("\n"+"-" * 50)
                
    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit()
    except socket.error:
        print("\nCould not connect to the target IP")
        sys.exit()

if __name__ == "__main__":
    run_scanner()