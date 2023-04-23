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
    "mount", "umount", "fsck", "mkfs", "dd", "fdisk", "gdisk", "parted", "df", "du", "ls"
]

def has_shell_command(payload):
    decoded_payload = payload.decode("utf-8", errors="ignore")
    for command in common_shell_commands:
        if re.search(r'\b' + re.escape(command) + r'\b', decoded_payload):
            return True
    return False

def icmp_callback(packet):
    if packet.haslayer(ICMP):
        icmp_packet = packet.getlayer(ICMP)
        payload = icmp_packet.payload.load

        if has_shell_command(payload):
            print(f"Potential shell command detected in ICMP packet from {packet[IP].src} to {packet[IP].dst}:")
            print(payload.hex())

def main():
    print("Listening for ICMP packets...")
    sniff(prn=icmp_callback, filter="icmp", store=0)

if __name__ == "__main__":
    main()
