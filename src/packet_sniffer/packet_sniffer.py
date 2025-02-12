"""
Bu Kod MacOs Cihazlarda çalışmaz çünkü AF_PACKET soket türü Macos Cihazlarda desteklenmiyor. 
Kod öalıştırılacaksa Linux cihazlarda çalışır anca.

Packet Sniffer loglarının yazıldığı dosya: logs/packet_sniffer_logs/sniffer_logs.json
Eğer terminalde gözükmesini istiyorsan printlerin başındaki commentleri kaldır
"""

import socket
import struct
import textwrap
import json
from datetime import datetime
import os
import time

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

# DATA_TAB_1 = '\t '
# DATA_TAB_2 = '\t\t '
# DATA_TAB_3 = '\t\t\t '
# DATA_TAB_4 = '\t\t\t\t '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Port scanner'ın IP adresini ve yaygın port tarama portlarını beyaz listeye alalım
    whitelist_ips = {
        socket.gethostbyname(socket.gethostname()),  # Yerel makine IP'si
        '127.0.0.1'  # Localhost
    }
    
    # Port tarama işleminde kullanılan yaygın portlar
    scanner_ports = set(range(1, 1025))  # Well-known portlar

    def is_port_scan_traffic(src_ip, dest_ip, src_port, dest_port, proto, flags=None):
        # Port scanner trafiğini kontrol et
        if src_ip in whitelist_ips:
            # Kaynak IP whitelist'te ve hedef port tarama portlarından biriyse
            if dest_port in scanner_ports:
                return True
            # TCP SYN taraması kontrolü
            if proto == 6 and flags and flags.get('SYN', False) and not flags.get('ACK', False):
                return True
        
        if dest_ip in whitelist_ips:
            # Hedef IP whitelist'te ve kaynak port tarama portlarından biriyse
            if src_port in scanner_ports:
                return True
            # TCP RST/ACK yanıtlarını kontrol et
            if proto == 6 and flags and (flags.get('RST', False) or flags.get('ACK', False)):
                return True
        
        return False

    def write_to_json(packet_data):
        file_path = 'logs/packet_sniffer_logs/sniffer_logs.json'
        
        # Dosya yoksa boş bir liste ile oluştur
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                json.dump([], f)
        
        # Mevcut verileri oku
        with open(file_path, 'r') as f:
            try:
                existing_data = json.load(f)
            except json.JSONDecodeError:
                existing_data = []
        
        # Yeni veriyi ekle
        existing_data.append(packet_data)
        
        # Güncellenmiş veriyi yaz
        with open(file_path, 'w') as f:
            json.dump(existing_data, f, indent=2)

    while True:
        try:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            
            # Varsayılan değerleri başlangıçta tanımlayalım
            src_port = None
            dest_port = None
            packet_data = None
            
            # IPv4 paketlerini kontrol et
            if eth_proto == 8:
                (version, header_length, ttl, proto, src_ip, dest_ip, data) = ipv4_packet(data)
                
                # Paket verisini oluştur
                packet_data = {
                    'timestamp': datetime.now().isoformat(),
                    'ethernet_frame': {
                        'destination': dest_mac,
                        'source': src_mac,
                        'protocol': eth_proto
                    }
                }
                
                # TCP veya UDP trafiği için port ve bayrak bilgilerini kontrol et
                tcp_flags = None
                if proto == 6:  # TCP
                    src_port, dest_port, *_, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, _ = tcp_segment(data)
                    tcp_flags = {
                        'URG': flag_urg,
                        'ACK': flag_ack,
                        'PSH': flag_psh,
                        'RST': flag_rst,
                        'SYN': flag_syn,
                        'FIN': flag_fin
                    }
                elif proto == 17:  # UDP
                    src_port, dest_port, *_ = udp_segment(data)
                
                # Port scanner trafiği ise kaydetme
                if src_port and dest_port and is_port_scan_traffic(src_ip, dest_ip, src_port, dest_port, proto, tcp_flags):
                    continue

                # Paket verisi varsa kaydet
                if packet_data:
                    write_to_json(packet_data)
                
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)
        except KeyboardInterrupt:
            print("Exiting program...")
            break

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
        
if __name__ == "__main__":
    main()