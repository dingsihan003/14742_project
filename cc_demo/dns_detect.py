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
    "mount", "umount", "fsck", "mkfs", "dd", "fdisk", "gdisk", "parted", "df", "du"
]

def has_shell_command(text):
    for command in common_shell_commands:
        if re.search(r'\b' + re.escape(command) + r'\b', text):
            return True
    return False

def dns_callback(packet):
    if packet.haslayer(DNS):
        dns_packet = packet.getlayer(DNS)

        for i in range(dns_packet.qdcount):
            query_name = dns_packet.qd[i].qname.decode("utf-8", errors="ignore")
            if has_shell_command(query_name):
                print(f"Potential shell command detected in DNS Query from {packet[IP].src} to {packet[IP].dst}:")
                print(query_name)

        for i in range(dns_packet.ancount):
            answer_name = dns_packet.an[i].rrname.decode("utf-8", errors="ignore")
            if has_shell_command(answer_name):
                print(f"Potential shell command detected in DNS Answer from {packet[IP].src} to {packet[IP].dst}:")
                print(answer_name)

def main():
    print("Listening for DNS packets...")
    sniff(prn=dns_callback, filter="udp and port 53", store=0)

if __name__ == "__main__":
    main()
