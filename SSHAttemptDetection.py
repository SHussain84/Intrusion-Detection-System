from scapy.all import sniff, TCP, IP
from Logger import Logger

class SSHAttemptDetection:
    def detectSshAttempt(self, packet):
        if packet.haslayer(TCP):
            srcPort = packet[TCP].sport
            dstPort = packet[TCP].dport
            if dstPort == 22 and packet[TCP].flags == 'S':  # SSH port
                srcIp = packet[IP].src
                dstIp = packet[IP].dst
                Logger.logAttack("SSH Attempt", srcIp, dstIp, dstPort)
                #Logger.sendEmail("SSH Attempt", srcIp, dstIp, dstPort)
                #Logger.sendTextMessage("SSH Attempt", srcIp, dstIp, dstPort)
                currentDateTime = Logger.getCurrentDateTime()
                print(f"[*] SSH connection attempt detected from {srcIp}:{srcPort} to {dstIp}:{dstPort} at {currentDateTime}")

    def start_detection(self):
        print("Starting SSH Detection...")
        sniff(filter="tcp port 22", prn=self.detectSshAttempt)