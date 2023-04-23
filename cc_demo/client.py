import socket
import struct
import time
import random
import sys
import base64

def setup_connection():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as msg:
        print('error ' + str(msg[0]) + ': ' + msg[1])
        sys.exit()

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock

def prepare_icmp_packet(src_ip, dst_ip, command):
    src_addr = socket.inet_aton(src_ip)  # You can change this to the desired source IP
    dst_addr = socket.inet_aton(dst_ip)

    # IP header fields
    ip_ver_and_ihl = 0x45
    ip_tos = 0
    ip_tot_len = 20 + 8  # IP header length (20) + ICMP header length (8)
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_ICMP
    ip_check = 0 # System will fill this in

    # IP header struct
    ip_header = struct.pack("!BBHHHBBH4s4s", ip_ver_and_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, src_addr, dst_addr)

    # ICMP header fields
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = random.randint(0, 65535)
    icmp_seq = random.randint(0, 65535)

    # ICMP header struct
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq) + command.encode("utf-8")
    icmp_header += b'\x00' * (len(icmp_header) % 2)  # Padding if needed
    icmp_checksum = checksum(icmp_header)
    # checksum little endian
    icmp_checksum = (icmp_checksum >> 8) | (icmp_checksum << 8 & 0xff00)
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq) + command.encode("utf-8")

    # Create the final packet
    pkt = ip_header + icmp_header

    return pkt


def prepare_dns_packet(src_ip, dst_ip, command):
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)

    command = command.replace(" ", "^").replace(".", "?") + ".google.com"

    # IP header fields
    ip_ver_and_ihl = 0x45
    ip_tos = 0
    ip_tot_len = 20 + 8 + len(command) + 2  # IP header (20) + UDP header (8) + domain length + null byte and QTYPE/QCLASS (2)
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0

    # IP header struct
    ip_header = struct.pack("!BBHHHBBH4s4s", ip_ver_and_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, src_addr, dst_addr)
    
    # DNS header fields
    dns_id = random.randint(0, 65535)
    dns_flags = 0x0100  # Standard query
    dns_qdcount = 1  # Number of questions
    dns_ancount = 0
    dns_nscount = 0
    dns_arcount = 0

    # DNS header struct
    dns_header = struct.pack("!HHHHHH", dns_id, dns_flags, dns_qdcount, dns_ancount, dns_nscount, dns_arcount)

    # Encode the domain name in DNS format
    encoded_command = b""
    for part in command.split("."):
        encoded_command += struct.pack("!B", len(part)) + part.encode("utf-8")
    encoded_command += b"\x00"  # Terminate with a null byte

    # DNS query fields
    dns_qtype = 1  # Query type: A (IPv4)
    dns_qclass = 1  # Query class: IN (Internet)

    # DNS query struct
    dns_query = struct.pack("!HH", dns_qtype, dns_qclass)

    # DNS data
    dns_data = dns_header + encoded_command + dns_query

    # UDP header fields
    udp_src_port = random.randint(1024, 65535)
    udp_dst_port = 53  # DNS uses port 53
    udp_len = 8 + len(dns_data)# UDP header (8) + DNS data length
    udp_check = 0
    placeholder = 0

    # UDP header struct
    udp_header = struct.pack("!HHHH", udp_src_port, udp_dst_port, udp_len, udp_check)
    psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, ip_proto, udp_len)
    psh = psh + udp_header + dns_data
    psh += b'\x00' * (len(psh) % 2)  # Padding if needed
    udp_check = checksum(psh)
    # checksum little endian
    udp_check = (udp_check >> 8) | (udp_check << 8 & 0xff00)
    udp_header = struct.pack("!HHHH", udp_src_port, udp_dst_port, udp_len, udp_check)

    # Create the final packet
    pkt = ip_header + udp_header + dns_data

    return pkt


def prepare_http_packet(src_ip, dst_ip, dst_port, request):
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)

    # IP header fields
    ip_ver_and_ihl = 0x45
    ip_tos = 0
    ip_tot_len = 20 + 20 + len(request)  # IP header (20) + TCP header (20) + request length
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0

    # IP header struct
    ip_header = struct.pack("!BBHHHBBH4s4s", ip_ver_and_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, src_addr, dst_addr)

    # HTTP data
    http_data = request.encode()

    # TCP header fields
    src_port = random.randint(4000, 9000)
    dst_port = dst_port
    seq_num = 0
    ack_num = 0
    data_offset_padding = 0x50  # Data offset = 5 (5 x 32-bit words)
    flags = 0x02 # TCP_F_SYN
    rx_window = 64240
    tcp_checksum = 0  # Filled later
    urgent = 0

    tcp_hdr_no_checksum = struct.pack("!HHLLBBHHH", src_port, dst_port, seq_num, ack_num, data_offset_padding, flags,
                                      rx_window, tcp_checksum, urgent)

    # TCP checksum
    psh = struct.pack("!LLBBH", int.from_bytes(src_addr, byteorder='big'),
                             int.from_bytes(dst_addr, byteorder='big'), 0, ip_proto, len(tcp_hdr_no_checksum + http_data))
    tcp_checksum_data = psh + tcp_hdr_no_checksum + http_data
    tcp_checksum_data += b'\x00' * (len(tcp_checksum_data) % 2)  # Padding if needed
    tcp_checksum = checksum(tcp_checksum_data)
    # checksum little endian
    tcp_checksum = (tcp_checksum >> 8) | (tcp_checksum << 8 & 0xff00)

    # Construct TCP header with checksum
    tcp_header = struct.pack("!HHLLBBHHH", src_port, dst_port, seq_num, ack_num, data_offset_padding, flags, rx_window,
                          tcp_checksum, urgent)
    
    # Create the final packet
    pkt = ip_header + tcp_header + http_data

    return pkt


def send_packet(sock, pkt, target_ip, target_port):
    sock.sendto(pkt, (target_ip, target_port))


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        s = s + (msg[i]) + (msg[i + 1] << 8)
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s


if __name__ == "__main__":

    s = setup_connection()
    while True:
        message_type = input("Enter message type (icmp, dns, http): ")
        command = input("Enter command: ")
        if message_type == 'icmp':
            icmp_pkt = prepare_icmp_packet('10.0.0.20', '10.0.0.21', command)
            send_packet(s, icmp_pkt, '10.0.0.21', 0)
        elif message_type == 'dns':
            dns_pkt = prepare_dns_packet('10.0.0.20', '10.0.0.21', command)
            send_packet(s, dns_pkt, '10.0.0.21', 53)
        elif message_type == 'http':
            http_pkt = prepare_http_packet('10.0.0.20', '10.0.0.21', 80, f'GET / HTTP/1.1\r\nHost:www.googlea.com\r\nData:{command}\r\n\r\n')
            send_packet(s, http_pkt, '10.0.0.21', 80)