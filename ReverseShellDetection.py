from scapy.all import *
from Logger import Logger

class ReverseShellDetection:
    def detectReverseShell(self, packet):
        if (TCP in packet and packet[TCP].dport == 4444):
            srcIp = packet[IP].src
            dstIp = packet[IP].dst
            dstPort = packet[TCP].dport
            if packet[TCP].flags == 'A':
                Logger.logAttack("Reverse Shell", srcIp, dstIp, dstPort)
                #Logger.sendEmail("Reverse Shell", srcIp, dstIp, dstPort)
                #Logger.sendTextMessage("Reverse Shell", srcIp, dstIp, dstPort)
                currentDateTime = Logger.getCurrentDateTime()
                print(f"[*] Reverse Shell detected from {srcIp} to {dstIp}:{dstPort} at {currentDateTime}")

    def start_detection(self):
        print("Starting Reverse Shell detection...")
        sniff(filter="tcp", prn=self.detectReverseShell)