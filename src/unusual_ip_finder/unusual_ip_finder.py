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
LOG_FILE = "logs/trusted_ip_finder_logs/tursted_ip_logs.txt"

def write_log(message):
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(f"{message}\n")
    except Exception as e:
        print(f"[!] Log writing error: {e}")

def load_known_devices():
    try:
        if not os.path.exists(KNOWN_DEVICES_FILE):
            write_log(f"[!] Warning: {KNOWN_DEVICES_FILE} file not found!")
            return []
        
        with open(KNOWN_DEVICES_FILE, "r") as f:
            try:
                data = json.load(f)
                if not data.get('known_devices'):
                    write_log("[!] Warning: 'known_devices' list is empty or not found!")
                return data.get('known_devices', [])
            except json.JSONDecodeError as e:
                write_log(f"[!] JSON read error: {e}")
                return []
    except Exception as e:
        write_log(f"[!] File read error: {e}")
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
            write_log("[!] This program requires root permissions.")
            write_log("Please run with 'sudo python src/unusual_ip_finder/unusual_ip_finder.py'")
            sys.exit(1)
            
        write_log("[*] Unusual IP Finder starting...")
        
        approved_devices = load_known_devices()
        write_log(f"[*] Approved devices: {approved_devices}")
        
        while True:
            write_log("[*] Scanning network...")
            scanned_devices = scan_network(TARGET_RANGE)
            write_log(f"[*] {len(scanned_devices)} devices found.")
            
            for device in scanned_devices:
                ip = device['ip']
                if ip not in approved_devices:
                    alert_message = f"[ALERT] Suspicious new device detected! IP: {ip} | MAC: {device['mac']}"
                    write_log(alert_message)
            
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        write_log("[*] Unusual IP Finder stopped.")
    except Exception as e:
        write_log(f"[!] Error: {e}")
        time.sleep(5)
        main()

if __name__ == "__main__":
    main()
