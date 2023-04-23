import socket
import struct

# Get the server IP address or hostname from the user
# server_address = input("Enter server address: ")
server_address = "10.0.0.21"


# Create a raw socket to send ICMP packets
icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

# Continuously listen for user input and send ICMP Echo Requests with the command
# to execute as the payload
while True:
    # Get input from the user
    command = input("Enter command ('!' if end): ")

    command = command.encode("utf-8")
    
    for i in range(0, len(command), 4):
        data_1 = command[i : min(len(command), i + 2)]
        data_2 = command[min(len(command), i + 2) : min(len(command), i + 4)]

        data_1 += b"\x00" * (2 - len(data_1))
        data_2 += b"\x00" * (2 - len(data_2))
        
        # Create an ICMP Echo Request packet with the command as the payload
        packet = struct.pack('!BBH2s2s', 8, 0, 0, data_1, data_2,)

        # Send the ICMP Echo Request packet to the server
        icmp_socket.sendto(packet, (server_address, 0))