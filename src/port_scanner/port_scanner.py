import sys
import socket
from datetime import datetime
import ipaddress
from populer_ports import POPULAR_PORTS, POPULER_UDP_PORTS
import threading
from queue import Queue

port_scan_type = 2  # 1: Popüler portlar, 2: Geniş port taraması

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

# Thread sayısını belirle
thread_count = 100
queue = Queue()

def tcp_port_scan(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = "unknown"
            print("Port {:<6} | State: open | Protocol: TCP | Service: {}".format(port, service))
        s.close()
    except:
        pass

def udp_port_scan(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socket.setdefaulttimeout(1)
        s.sendto(b"", (target, port))
        data, addr = s.recvfrom(1024)
        try:
            service = socket.getservbyport(port, 'udp')
        except:
            service = "unknown"
        print("Port {:<6} | State: open | Protocol: UDP | Service: {}".format(port, service))
        s.close()
    except:
        pass

def threader(target):
    while True:
        port_info = queue.get()
        if port_info is None:
            break
        
        protocol, port = port_info
        if protocol == "TCP":
            tcp_port_scan(target, port)
        else:
            udp_port_scan(target, port)
        queue.task_done()

try:
    for ip in targets:
        target = str(ip)
        print("-" * 50)
        print(f"\nScanning target: {target}")
        
        # Port tarama aralığını belirle
        if port_scan_type == 1:
            ports_to_scan = POPULAR_PORTS
            print("Scanning popular ports...")
        else:
            ports_to_scan = range(1, 10001)
            print("Scanning ports 1-10000...")

        # Thread havuzu oluştur
        threads = []
        for _ in range(thread_count):
            t = threading.Thread(target=threader, args=(target,))
            t.daemon = True
            t.start()
            threads.append(t)

        # TCP portlarını kuyruğa ekle
        print("\nStarting port scan...")
        for port in ports_to_scan:
            queue.put(("TCP", port))

        # UDP portlarını kuyruğa ekle
        for port in POPULER_UDP_PORTS:
            queue.put(("UDP", port))

        # Thread'leri sonlandır
        for _ in range(thread_count):
            queue.put(None)

        # Tüm thread'lerin bitmesini bekle
        for t in threads:
            t.join()

except KeyboardInterrupt:
    print("\nExiting program.")
    sys.exit()
except socket.error as e:
    print(f"\nCould not connect to the target IP: {e}")
    sys.exit()

print("\nScan completed!")