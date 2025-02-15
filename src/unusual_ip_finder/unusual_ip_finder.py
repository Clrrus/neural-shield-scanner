from ip_discover.ip_discover import discover_active_ips
import json
import time
import datetime

with open("trusted_ips.json", "r") as f:
    trusted_ips = json.load(f)

with open("config.json", "r") as f:
    config = json.load(f)

SCAN_INTERVAL = int(config["unusual_ip_finder"]["scan_interval"])

def log_unusual_ips(unusual_ips):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp}: Unusual IP's detected: {', '.join(unusual_ips)}\n"
        
        with open("logs/trusted_ip_finder_logs/tursted_ip_logs.txt", 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Log file could not be written: {str(e)}")

def log_message(message):
    try:
        with open("logs/trusted_ip_finder_logs/tursted_ip_logs.txt", 'a') as f:
            f.write(message + "")
    except Exception as e:
        print(f"Log file could not be written: {str(e)}")

def main(target_range=config["scanner"]["target_range"]):
    try:
        while True:
            log_message("[*] Unusual IP Finder starting...\n")
            active_ips = discover_active_ips(target_range)
            unusual_ips = [ip for ip in active_ips if ip not in trusted_ips["known_devices"]]

            if unusual_ips:
                log_message("[*] Unusual IPs detected:\n")
                log_unusual_ips(unusual_ips)
                log_message(f"[*] {len(unusual_ips)} unusual ip found. Reported to the administrator.\n")
            else:
                log_message("All active ips are trusted devices.\n")
            time.sleep(SCAN_INTERVAL)
    except Exception as e:
        log_message(f"[!] Error: {str(e)}\n")

if __name__ == "__main__":
    main()