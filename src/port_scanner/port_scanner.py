import sys
import socket
from datetime import datetime
import ipaddress

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
        
        for port in range(1, 9000):
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
except KeyboardInterrupt:
    print("\nExiting program.")
    sys.exit()
except socket.error:
    print("\nCould not connect to the target IP")
    sys.exit()