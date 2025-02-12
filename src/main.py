from port_scanner.port_scanner import run_scanner
from packet_sniffer.packet_sniffer import main as packet_sniffer_main
import time
import subprocess
from threading import Thread
import json
import os

def get_sudo_password():
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            return config.get('sudo_password')
    except Exception as e:
        print(f"Config file read error: {e}")
        return None

def run_packet_sniffer():
    sudo_password = get_sudo_password()
    if not sudo_password:
        print("Sudo password not found!")
        return

    try:
        # Python yorumlayıcısının tam yolunu al
        python_path = subprocess.check_output(['which', 'python3']).decode().strip()
        
        # Packet sniffer script'inin tam yolunu oluştur
        script_path = os.path.join(os.path.dirname(__file__), 'packet_sniffer/packet_sniffer.py')
        
        # Sudo komutu oluştur
        command = f'sudo -S {python_path} {script_path}'
        
        # Subprocess ile çalıştır
        process = subprocess.Popen(
            command.split(),
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Sudo şifresini gönder
        process.stdin.write(f"{sudo_password}\n")
        process.stdin.flush()
        
        # Prosesi bekle
        process.communicate()
        
    except subprocess.CalledProcessError as e:
        print(f"Packet sniffer error: {e}")
    except KeyboardInterrupt:
        print("Packet sniffer stopping...")

def run_port_scanner():
    while True:
        try:
            run_scanner()
            print("Scanning completed successfully. Next scan in 1 hour...")
            time.sleep(3600)
        except KeyboardInterrupt:
            print("Port scanner stopping...")
            break
        except Exception as e:
            print(f"Port Scanner Error: {e}")
            time.sleep(5)
            continue

if __name__ == "__main__":
    try:
        sniffer_thread = Thread(target=run_packet_sniffer)
        sniffer_thread.daemon = True
        sniffer_thread.start()
        
        run_port_scanner()
        
    except KeyboardInterrupt:
        print("\nMain program stopping...")