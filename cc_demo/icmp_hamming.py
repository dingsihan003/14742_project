import socket
import struct
from collections import defaultdict

HAMMING_THRESHOLD = 20
ALERT_THRESHOLD = 5

icmp_pairs = defaultdict(lambda: {"prev_payload": None, "hamming_threshold_crossed": 0})

def hamming_distance(str1, str2):
    if len(str1) != len(str2):
        return 100

    return sum(b1 != b2 for b1, b2 in zip(str1, str2)) * 100 / len(str1)

def process_icmp_packet(packet):
    ip_header = packet[:20]
    icmp_header = packet[20:28]
    icmp_payload = packet[28:]
    
    src_ip, dest_ip = struct.unpack('!12x4s4s', ip_header)
    icmp_type = icmp_header[0]

    if icmp_type == 8:  # ICMP Echo Request
        flow_key = (socket.inet_ntoa(src_ip), socket.inet_ntoa(dest_ip))

        icmp_data = icmp_pairs[flow_key]
        prev_payload = icmp_data["prev_payload"]
        icmp_payload = icmp_payload.decode("utf-8")
        print(icmp_data)

        if prev_payload is not None:
            distance = hamming_distance(prev_payload, icmp_payload)
            print(f"Hamming distance: {distance}")

            if distance > HAMMING_THRESHOLD:
                icmp_data["hamming_threshold_crossed"] += 1
            else:
                icmp_data["hamming_threshold_crossed"] = 0

            if icmp_data["hamming_threshold_crossed"] >= ALERT_THRESHOLD:
                print(f"Alert: Possible ICMP tunnel between {flow_key[0]} and {flow_key[1]}")
                icmp_data["hamming_threshold_crossed"] = 0

        icmp_data["prev_payload"] = icmp_payload

# Create a raw socket to listen for ICMP packets
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
bind_ip = "0.0.0.0"
bind_port = 53
sock.bind((bind_ip, bind_port))


while True:
    packet, _ = sock.recvfrom(65535)
    process_icmp_packet(packet)
