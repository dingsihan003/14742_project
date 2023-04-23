import re
from scapy.all import *

common_shell_commands = [
    "sh", "bash", "zsh", "ksh", "tcsh", "dash",
    "cat", "cp", "mv", "rm", "mkdir", "rmdir", "chmod", "chown",
    "grep", "awk", "sed", "cut", "sort", "uniq",
    "find", "locate", "tar", "gzip", "gunzip", "bzip2", "xz",
    "ps", "top", "htop", "kill", "killall", "pkill",
    "ifconfig", "ip", "route", "netstat", "ss", "ping", "traceroute", "nslookup", "dig",
    "wget", "curl", "ssh", "scp", "ftp", "sftp", "tftp",
    "vi", "vim", "nano", "pico", "emacs", "ed", "ex",
    "sudo", "su", "chroot", "passwd", "useradd", "usermod", "userdel",
    "mount", "umount", "fsck", "mkfs", "dd", "fdisk", "gdisk", "parted", "df", "du", "ls", "pwd"
]

def has_shell_command(payload):
    decoded_payload = payload.decode("utf-8", errors="ignore")
    for command in common_shell_commands:
        if re.search(r'\b' + re.escape(command) + r'\b', decoded_payload):
            return True
    return False

def tcp_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        tcp_packet = packet.getlayer(TCP)
        payload = tcp_packet.payload.load
        if has_shell_command(payload):
            print(f"Potential shell command detected in TCP packet from {packet[IP].src}:{tcp_packet.sport} to {packet[IP].dst}:{tcp_packet.dport}:")
            print(payload.hex())

def main():
    print("Listening for TCP packets...")
    sniff(prn=tcp_callback, filter="tcp", store=0)

if __name__ == "__main__":
    main()
