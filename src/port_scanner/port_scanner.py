import sys
import socket
from datetime import datetime

target = input(str("Target IP: "))

if target == "":
    print("Please enter a target IP")
    sys.exit()
    
print("-" * 50)
print("Scanning target: " + target)
print("Scan started at: " + str(datetime.now()))
print("-" * 50)

try:
    for port in range(1, 65535):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)

        result = s.connect_ex((target, port))
        if result == 0:
            print("Port {} is open".format(port))
        s.close()
except KeyboardInterrupt:
    print("\nExiting program.")
    sys.exit()
except socket.error:
    print("\nCould not connect to the target IP")
    sys.exit()