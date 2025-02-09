import platform
import subprocess
from ipaddress import IPv4Network
from concurrent.futures import ThreadPoolExecutor
from typing import List

def ping_ip(ip: str) -> bool:
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', str(ip)]
    
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=1)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

def discover_active_ips(network: str, max_workers: int = 50) -> List[str]:
    active_ips = []
    network = IPv4Network(network)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(ping_ip, [str(ip) for ip in network.hosts()])
        
        for ip, is_active in zip(network.hosts(), results):
            if is_active:
                active_ips.append(str(ip))
    
    return active_ips

def main(target_range):
    # network = input("Ağ aralığını CIDR formatında girin (örn: 192.168.1.0/24): ")
    print(f"\n{target_range} ağında IP taraması başlatılıyor...")
    
    active_ips = discover_active_ips(target_range)
    
    print("\nAktif IP'ler:")
    for ip in active_ips:
        print(f"- {ip}")
    print(f"\nToplam {len(active_ips)} aktif IP bulundu.")

    if active_ips:
        print("\nIP adresleri port taramasına gönderiliyor...")
        return active_ips
    else:
        print("\nAktif IP adresi bulunamadı.")
        return []

# if __name__ == "__main__":
#     main()