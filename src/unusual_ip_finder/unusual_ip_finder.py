from ip_discover.ip_discover import discover_active_ips
import json
import time
import datetime
import os
import psycopg2
from psycopg2 import Error

with open("trusted_ips.json", "r") as f:
    trusted_ips = json.load(f)

with open("config.json", "r") as f:
    config = json.load(f)

def get_trusted_ips_from_db(company_id):
    try:
        connection = psycopg2.connect(
            host=config["trusted_ips_database"]["host"],
            port=config["trusted_ips_database"]["port"],
            database=config["trusted_ips_database"]["database"],
            user=config["trusted_ips_database"]["user"],
            password=config["trusted_ips_database"]["password"]
        )
        cursor = connection.cursor()
        select_query = f"SELECT ip FROM trustedips WHERE companyid = {company_id}"
        cursor.execute(select_query)
        records = cursor.fetchall()
        return [record[0] for record in records]
    except (Exception,Error) as e:
        packet_data = {
            "message": f"Error getting trusted IPs from database: {str(e)}"
        }
        write_to_json(packet_data)
    finally:
        if connection:
            cursor.close()
            connection.close()

SCAN_INTERVAL = int(config["unusual_ip_finder"]["scan_interval"])

def write_to_json(packet_data):
    file_path = 'logs/unusual_ip_finder_logs/unusual_ip_logs.json'
    
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            json.dump([], f)
    
    with open(file_path, 'r') as f:
        try:
            existing_data = json.load(f)
        except json.JSONDecodeError:
            existing_data = []
    
    existing_data.append(packet_data)
    
    with open(file_path, 'w') as f:
        json.dump(existing_data, f, indent=2)

def log_unusual_ips(unusual_ips):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"Unusual IP's detected: {', '.join(unusual_ips)}"
        packet_data = {
            "date": timestamp,
            "message": log_entry
        }
        write_to_json(packet_data)
        # with open("logs/unusual_ip_finder_logs/unusual_ip_logs.txt", 'a') as f:
        #     f.write(log_entry)

    except Exception as e:
        print(f"Log file could not be written: {str(e)}")

def log_message(message):
    try:
        # with open("logs/unusual_ip_finder_logs/unusual_ip_logs.txt", 'a') as f:
        #     f.write(message + "")
        packet_data = {
            "message": message
        }
        write_to_json(packet_data)
    except Exception as e:
        print(f"Log file could not be written: {str(e)}")

def main(target_range=config["scanner"]["target_range"]):
    try:
        while True:
            log_message("[*] Unusual IP Finder starting...\n")
            active_ips = discover_active_ips(target_range)
            if config["trusted_ips_database"]["get_from_db"] == "false":
                unusual_ips = [ip for ip in active_ips if ip not in trusted_ips["known_devices"]]
            elif config["trusted_ips_database"]["get_from_db"] == "true":
                unusual_ips = [ip for ip in active_ips if ip not in get_trusted_ips_from_db(config["trusted_ips_database"]["company_id"])]
            else:
                log_message("[!] Invalid get_from_db value. Please check config.json\n")
                break
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