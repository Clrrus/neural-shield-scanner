import subprocess
import re
from typing import Optional

def get_default_interface() -> Optional[str]:
    try:
        output = subprocess.check_output("ip route | grep default", shell=True, text=True)
        interface = re.search(r"dev\s+(\S+)", output)
        if interface:
            return interface.group(1)
    except subprocess.CalledProcessError:
        pass
    
    try:
        output = subprocess.check_output("route -n | grep '^0.0.0.0'", shell=True, text=True)
        interface = output.strip().split()[-1]
        return interface
    except subprocess.CalledProcessError:
        return None

def get_mac_address() -> Optional[str]:
    interface = get_default_interface()
    if not interface:
        return None

    try:
        output = subprocess.check_output(f"ip addr show {interface}", shell=True, text=True)
        mac_match = re.search(r"link/\S+\s+([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", output)
        if mac_match:
            return mac_match.group(1).upper()
    except subprocess.CalledProcessError:
        pass

    try:
        output = subprocess.check_output(f"ifconfig {interface}", shell=True, text=True)
        mac_match = re.search(r"ether\s+([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", output)
        if mac_match:
            return mac_match.group(1).upper()
    except subprocess.CalledProcessError:
        pass

    return None

def main():
    mac_address = get_mac_address()
    if mac_address:
        return mac_address
    else:
        print("MAC address not found!")