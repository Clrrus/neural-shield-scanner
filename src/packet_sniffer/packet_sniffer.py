"""
Bu Kod MacOs Cihazlarda çalışmaz çünkü AF_PACKET Macos Cihazlarda çalışmaz. Kod öalıştırılacaksa Linux
Cihazlarda çalıştırılmalıdır.
"""

import socket
import struct
import textwrap
import json
from datetime import datetime
import os
from mac_finder import main as mac_finder

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
    scanner_mac_address = mac_finder()

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
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        
        packet_data = {
            'timestamp': datetime.now().isoformat(),
            'ethernet_frame': {
                'destination': dest_mac,
                'source': src_mac,
                'protocol': eth_proto
            }
        }
        if src_mac != scanner_mac_address:
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                packet_data['ipv4_packet'] = {
                    'version': version,
                    'header_length': header_length,
                    'ttl': ttl,
                    'protocol': proto,
                    'source': src,
                    'target': target
                }

                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    packet_data['icmp_packet'] = {
                        'type': icmp_type,
                        'code': code,
                        'checksum': checksum
                    }
                elif proto == 6:
                    src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                    packet_data['tcp_segment'] = {
                        'source_port': src_port,
                        'destination_port': dest_port,
                        'sequence': sequence,
                        'acknowledgement': acknowledgement,
                        'flags': {
                            'URG': flag_urg,
                            'ACK': flag_ack,
                            'PSH': flag_psh,
                            'RST': flag_rst,
                            'SYN': flag_syn,
                            'FIN': flag_fin
                        }
                    }
                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    packet_data['udp_segment'] = {
                        'source_port': src_port,
                        'destination_port': dest_port,
                        'size': length
                    }
        
        write_to_json(packet_data)

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
        
main()