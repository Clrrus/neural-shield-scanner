import os
import time
import sys
from scapy.all import ARP, Ether, srp
import json

with open("config.json", "r") as f:
    config = json.load(f)

TARGET_RANGE = config["scanner"]["target_range"]
SCAN_INTERVAL = 60

KNOWN_DEVICES_FILE = "trusted_ips.json"

def load_known_devices():
    try:
        if not os.path.exists(KNOWN_DEVICES_FILE):
            print(f"[!] Warning: {KNOWN_DEVICES_FILE} file not found!")
            return []
        
        with open(KNOWN_DEVICES_FILE, "r") as f:
            try:
                data = json.load(f)
                if not data.get('known_devices'):
                    print("[!] Warning: 'known_devices' list is empty or not found!")
                return data.get('known_devices', [])
            except json.JSONDecodeError as e:
                print(f"[!] JSON read error: {e}")
                return []
    except Exception as e:
        print(f"[!] File read error: {e}")
        return []

def scan_network(target_range):
    arp = ARP(pdst=target_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=False)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def main():
    try:
        if os.geteuid() != 0:
            print("[!] This program requires root permissions.")
            print("Please run with 'sudo python src/unusual_ip_finder/unusual_ip_finder.py'")
            sys.exit(1)
        print("[*] Unusual IP Finder starting...")
        
        approved_devices = load_known_devices()
        print(f"[*] Approved devices: {approved_devices}")
        
        while True:
            print("[*] Scanning network...")
            scanned_devices = scan_network(TARGET_RANGE)
            print(f"[*] {len(scanned_devices)} devices found.")
            
            for device in scanned_devices:
                ip = device['ip']
                if ip not in approved_devices:
                    alert_message = f"[ALERT] Suspicious new device detected! IP: {ip} | MAC: {device['mac']}"
                    print(alert_message)
            
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("[*] Unusual IP Finder stopped.")
    except Exception as e:
        print(f"[!] Error: {e}")
        time.sleep(5)
        main()

if __name__ == "__main__":
    main()
