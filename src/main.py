import subprocess
from port_scanner.port_scanner import run_scanner

def open_sniffer_terminal():
    try:
        # Yeni terminal penceresi açıp packet sniffer'ı çalıştır
        subprocess.Popen(['gnome-terminal', '--', 'python3', 'src/packet_sniffer/packet_sniffer.py'])
    except FileNotFoundError:
        # Eğer gnome-terminal yoksa xterm'i dene
        try:
            subprocess.Popen(['xterm', '-e', 'python3', 'src/packet_sniffer/packet_sniffer.py'])
        except FileNotFoundError:
            print("Hata: Terminal uygulaması bulunamadı (gnome-terminal veya xterm gerekli)")

if __name__ == "__main__":
    # Önce packet sniffer'ı ayrı pencerede başlat
    open_sniffer_terminal()
    # Sonra port tarayıcıyı çalıştır
    run_scanner()
