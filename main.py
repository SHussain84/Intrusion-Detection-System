from scapy.all import sniff, ICMP, IP, TCP

conf.iface = "eth0"
def packet_callback(packet):
    print("Sniffing interface:", packet.sniffed_on)
    if ICMP in packet and packet[ICMP].type == 8:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Ping detected: {src_ip} -> {dst_ip}")
    elif TCP in packet and packet[TCP].dport == 22:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"SSH connection attempt detected from {src_ip} to {dst_ip}")

# Sniff traffic on the network interface
sniff(prn=packet_callback, filter="icmp or (tcp and port 22)", store=0)