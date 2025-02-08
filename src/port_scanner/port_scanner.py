import sys
import socket
from datetime import datetime
import ipaddress
from port_scanner.populer_ports import POPULAR_PORTS
import threading
import queue

def scan_port(target, port):
    for _ in range(2): 
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(2.0)
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
    port_scan_type = 2
    max_threads = 25 

    scan_type = input("Scan type (1 for single IP, 2 for IP range): ")

    if scan_type not in ['1', '2']:
        print("Please enter a valid option (1 or 2)")
        sys.exit()

    if scan_type == '1':
        target = input("Enter target IP: ")
        try:
            ipaddress.ip_address(target)
            targets = [target]
        except ValueError:
            print("Invalid IP address")
            sys.exit()
    else:
        target_range = input("Target IP range (example: 192.168.1.0/24): ")
        try:
            ip_network = ipaddress.ip_network(target_range)
            targets = list(ip_network.hosts())
        except ValueError:
            print("Invalid IP range format. Please use CIDR notation (example: 192.168.1.0/24)")
            sys.exit()

    print("-" * 50)
    print("Scan started at: " + str(datetime.now()))
    print("Scanning target(s): " + (target if scan_type == '1' else target_range))
    print("-" * 50)

    try:
        for ip in targets:
            target = str(ip)
            print(f"\nScanning target: {target}")
            
            if port_scan_type == 1:
                ports_to_scan = POPULAR_PORTS
                print("Scanning popular ports...")
            else:
                ports_to_scan = range(1, 10001)
                print("Scanning ports 1-10000...")
            
            open_ports = []
            q = queue.Queue()

            def worker():
                while True:
                    port = q.get()
                    result = scan_port(target, port)
                    if result[1]:
                        open_ports.append(result)
                    q.task_done()

            for _ in range(max_threads):
                t = threading.Thread(target=worker)
                t.daemon = True
                t.start()

            for port in ports_to_scan:
                q.put(port)

            q.join()

            for port, _, service in open_ports:
                print("Port {:<6} | State: open | Protocol: TCP | Service: {}".format(port, service))
                
            print("-" * 50)
    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit()
    except socket.error:
        print("\nCould not connect to the target IP")
        sys.exit()

if __name__ == "__main__":
    run_scanner()