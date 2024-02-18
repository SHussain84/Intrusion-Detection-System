from scapy.all import *

conf.iface = "eth0"
rules = []

def read_detection_rules(filename):
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip().lower()
            if line in ['ping', 'icmp']:
                rules.append("icmp")
            elif line == 'ssh':
                rules.append("(tcp and port 22)")
            elif line == 'dns':
                rules.append("udp and port 53")
            elif line == 'http':
                rules.append("tcp and port 80")
            elif line == 'ftp':
                rules.append("tcp and port 21")

    return rules
def packet_callback(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    if "icmp" in rules and ICMP in packet and packet[ICMP].type == 8:
        print(f"Ping detected from {src_ip} to {dst_ip}")
    elif "(tcp and port 22)" in rules and TCP in packet and packet[TCP].dport == 22:
        print(f"SSH connection attempt detected from {src_ip} to {dst_ip}")

rules = read_detection_rules('detection_rules.txt')
filter_str = " or ".join(rules)
print(filter_str)

sniff(prn=packet_callback, filter=filter_str, store=0)
