from scapy.all import *
from Logger import Logger

class XMASScanDetection:
    def detectXmasScan(self, packet):
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags == 0x29:  # FIN, URG, PSH flags set (Xmas tree scan)
                srcIp = packet[IP].src
                dstIp = packet[IP].dst
                dstPort = packet[TCP].dport
                Logger.logAttack("Xmas Scan", srcIp, dstIp, dstPort)
                #Logger.sendEmail("Xmas Scan", srcIp, dstIp, dstPort)
                #Logger.sendTextMessage("Xmas Scan", srcIp, dstIp, dstPort)
                currentDateTime = Logger.getCurrentDateTime()
                print(f"[*] Xmas Scan detected from {srcIp} to {dstIp}:{dstPort} at {currentDateTime}")

    def start_detection(self):
        print("Starting Xmas Scan detection...")
        sniff(filter="tcp", prn=self.detectXmasScan)
