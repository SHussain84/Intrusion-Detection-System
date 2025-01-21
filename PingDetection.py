from scapy.all import *
from Logger import Logger

class PingDetection:
    def detectPing(self, packet):
        if packet.haslayer(ICMP):
            if packet[ICMP].type == 8:  # Ping
                srcIp = packet[IP].src
                dstIp = packet[IP].dst
                Logger.logAttack("Ping", srcIp, dstIp)
                currentDateTime = Logger.getCurrentDateTime()
                print(f"[*] Ping detected from {srcIp} to {dstIp} at {currentDateTime}")

    def start_detection(self):
        print("Starting Ping detection...")
        sniff(filter="icmp", prn=self.detectPing)
