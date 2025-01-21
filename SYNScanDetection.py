from scapy.all import *
from Logger import Logger
from collections import defaultdict
from time import time

syn_packets = defaultdict(list)
SYN_FLAG = 0x02
THRESHOLD_COUNT = 5  # Threshold of SYN packets to consider it a scan
TIME_SPAN = 10  # Time span in seconds to check for SYN packets

class SYNScanDetection:
    def detectSYNScan(self, packet):

        if packet.haslayer(TCP) and packet[TCP].flags & SYN_FLAG:
            srcIp = packet[IP].src
            dstIp = packet[IP].dst
            dstPort = packet[TCP].dport
            current_time = time()
            syn_packets[srcIp].append(current_time)

            # Remove timestamps older than the TIME_SPAN
            syn_packets[srcIp] = [t for t in syn_packets[srcIp] if current_time - t < TIME_SPAN]

            if len(syn_packets[srcIp]) > THRESHOLD_COUNT:
                Logger.logAttack("SYN Scan", srcIp, dstIp, dstPort)
                #Logger.sendEmail("SYN Scan", srcIp, dstIp, dstPort)
                #Logger.sendTextMessage("SYN Scan", srcIp, dstIp, dstPort)
                currentDateTime = Logger.getCurrentDateTime()
                print(f"[*] SYN Scan detected from {srcIp} to {dstIp}:{dstPort} at {currentDateTime}")
                syn_packets[srcIp] = []  # Reset after detection to avoid repeated alerts

    def start_detection(self):
        print("Starting SYN Scan detection...")
        sniff(filter="tcp", prn=self.detectSYNScan)
