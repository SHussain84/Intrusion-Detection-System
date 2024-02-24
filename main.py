from scapy.all import *
import datetime

conf.iface = "eth0"
rules = []

def readDetectionRules(filename):
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

def packetCallback(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    currentDateTime = datetime.datetime.now()
    formattedDateTime = currentDateTime.strftime("%d/%m/%Y %H:%M:%S")
    filePath = 'logs.txt'

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    if "icmp" in rules and ICMP in packet and packet[ICMP].type == 8:
        print(f"Ping detected from {src_ip} to {dst_ip} at {formattedDateTime}")
        with open(filePath, 'a') as file:
            file.write(f"Ping detected from {src_ip} to {dst_ip} at {formattedDateTime}\n")
    elif "(tcp and port 22)" in rules and TCP in packet and packet[TCP].dport == 22:
        print(f"SSH connection attempt detected from {src_ip} to {dst_ip} at {formattedDateTime}")
        with open(filePath, 'a') as file:
            file.write(f"SSH connection attempt detected from {src_ip} to {dst_ip} at {formattedDateTime}\n")
    elif "(dos)"

rules = readDetectionRules('detection_rules.txt')
filterStr = " or ".join(rules)
print(filterStr)

sniff(prn=packetCallback, filter=filterStr, store=1)
