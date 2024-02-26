import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from scapy.all import *
import datetime

conf.iface = "eth0"

def getCurrentDateTime():
    currentDateTime = datetime.datetime.now()
    formattedDateTime = currentDateTime.strftime("%d/%m/%Y %H:%M:%S")
    return formattedDateTime

def logAttack(attackType, srcIp, dstIp=None, dstPort=None):
    with open("logs.txt", "a") as f:
        if dstIp and dstPort:
            logMessage = f"[{attackType}] from {srcIp} to {dstIp}:{dstPort} at {getCurrentDateTime()}\n"
        else:
            logMessage = f"[{attackType}] from {srcIp} at {getCurrentDateTime()}\n"
        f.write(logMessage)

def sendEmail(attackType, srcIp, dstIp=None, dstPort=None):
    # Configure email settings
    sender_email = "pythonids@gmail.com"
    receiver_email = "s.hussain84@edu.salford.ac.uk"
    password = "Password456"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = f"[IDS ALERT] {attackType} Detected"
    body = f"{attackType} detected from {srcIp}"
    if dstIp and dstPort:
        body += f" to {dstIp}:{dstPort}"
    msg.attach(MIMEText(body, 'plain'))

    # Send email
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)

def detectSshAttempt(packet):
    if packet.haslayer(TCP):
        srcPort = packet[TCP].sport
        dstPort = packet[TCP].dport
        if dstPort == 22:  # SSH port
            srcIp = packet[IP].src
            dstIp = packet[IP].dst
            print(f"[*] SSH connection attempt detected from {srcIp}:{srcPort} to {dstIp}:{dstPort} at {getCurrentDateTime()}")
            logAttack("SSH Attempt", srcIp, dstIp, dstPort)

def detectPing(packet):
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8:  # Ping
            srcIp = packet[IP].src
            dstIp = packet[IP].dst
            print(f"[*] Ping detected from {srcIp} to {dstIp} at {getCurrentDateTime()}")
            logAttack("Ping", srcIp, dstIp)
def detectPingOfDeath(packet):
    if packet.haslayer(ICMP):
        if len(packet[ICMP]) > 10000:
            srcIp = packet[IP].src
            dstIp = packet[IP].dst
            print(f"[*] Ping of Death attack detected from {srcIp} to {dstIp} at {getCurrentDateTime()}")
            logAttack("Ping of Death", srcIp, dstIp)

def detectSynScan(packet):
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags == 0x02: # 00000010 in binary, the second bit from the right represents a SYN flag
            srcIp = packet[IP].src
            dstIp = packet[IP].dst
            dstPort = packet[TCP].dport
            print(f"[*] SYN Scan detected from {srcIp} to {dstIp}:{dstPort}")
            logAttack("SYN Scan", srcIp, dstIp, dstPort)

def detectXmasAttack(packet):
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags == 0x29:  # FIN, URG, PSH flags set (Xmas tree scan)
            srcIp = packet[IP].src
            dstIp = packet[IP].dst
            dstPort = packet[TCP].dport
            print(f"[*] Xmas Attack detected from {srcIp} to {dstIp}:{dstPort}")
            logAttack("Xmas Attack", srcIp, dstIp, dstPort)

def detectAttacks(packet):
    detectPing(packet)
    detectSshAttempt(packet)
    detectPingOfDeath(packet)
    detectXmasAttack(packet)
    detectSynScan(packet)

print("------------- IDS RUNNING -------------")
sniff(filter="tcp or icmp", prn=detectAttacks)
