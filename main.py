import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from scapy.all import *
import datetime
import threading

print("Please enter the name of the network interface you want to monitor:")
conf.iface = "enp0s3"

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
        if dstPort == 22 and packet[TCP].flags == 'S':  # SSH port
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

def checkLogFile():
    logFilePath = '/var/log/auth.log'

    try:
        with open(logFilePath, 'r') as file:
            for line in file:
                if "Failed password" in line or "Accepted password" in line:
                    flag = True
    except FileNotFoundError:
        print(f"The log file {logFilePath} was not found.")
    except PermissionError:
        print(f"Permission denied when trying to read {logFilePath}")

    if flag == True:
        return True
    else:
        return False

def parseLogFile():
    logFilePath = '/var/log/auth.log'
    parsedLogs = []

    try:
        with open(logFilePath, 'r') as file:
            for line in file:
                if "Failed password" in line or "Accepted password" in line:
                    parsedLog = parseLogLine(line)
                    parsedLogs.append(parsedLog)
        return parsedLogs
    except FileNotFoundError:
        print(f"The log file {logFilePath} was not found.")
    except PermissionError:
        print(f"Permission denied when trying to read {logFilePath}")

def parseLogLine(line):
    parts = line.split()
    date = ' '.join(parts[:2])
    time = parts[2]
    outcome = "Failed" if "Failed" in line else "Accepted"
    forIndex = parts.index("for") + 1
    invalidUserIndex = parts.index("invalid") if "invalid" in parts else forIndex
    userIndex = invalidUserIndex if "invalid" in parts else forIndex
    fromIndex = parts.index("from")
    ipIndex = fromIndex + 1
    portIndex = parts.index("port") + 1
    protocolIndex = parts.index("port") + 2
    user = ' '.join(parts[userIndex:fromIndex]).replace("invalid user", "").strip()
    ipAddress = parts[ipIndex]
    port = parts[portIndex]
    protocol = parts[protocolIndex]
    return {
        "date": date,
        "time": time,
        "outcome": outcome,
        "user": user,
        "ipAddress": ipAddress,
        "port": port,
        "protocol": protocol
    }

def detectBruteForceAttempts():
    parsedLogs = parseLogFile()
    threshold = 3
    failedAttempts = {}

    for log in parsedLogs:
        if log['outcome'] == "Failed":
            ipAddress = log['ipAddress']
            if ipAddress in failedAttempts:
                failedAttempts[ipAddress] += 1
            else:
                failedAttempts[ipAddress] = 1
        if log['outcome'] == "Accepted":
            print(f"Accepted SSH connection from {ipAddress} on user {log['user']} on {log['date']} at {log['time']}.")
            print("If this was not you, please change your password as soon as possible!")

    for ip, count in failedAttempts.items():
        if count >= threshold:
            print(f"[*] Possible brute force attack detected from {ip} with {count} failed login attempts on {log['date']} at {log['time']}!")
            print(f"The following attempts were made from {ip}:")
            for log in parsedLogs:
                if log['ipAddress'] == ip and log['outcome'] == "Failed":
                    print(f"Failed login attempt on {log['date']} at {log['time']} for the user {log['user']}")


def monitorLogFile(detectionThreshold=5, checkInterval=1):
    logFilePath = '/var/log/auth.log'
    print("Starting real-time monitoring for brute force attacks...")
    lastPosition = os.path.getsize(logFilePath)  # Start at the end of the file
    failedAttempts = {}

    while True:
        with open(logFilePath, 'r') as file:
            file.seek(lastPosition)
            newLines = file.readlines()
            lastPosition = file.tell()  # Update last position

        for line in newLines:
            if "Failed password" in line:
                logEntry = parseLogLine(line)
                ipAddress = logEntry['ipAddress']
                failedAttempts[ipAddress] = failedAttempts.get(ipAddress, 0) + 1

                if failedAttempts[ipAddress] >= detectionThreshold:
                    print(f"Possible brute force attack detected from {ipAddress}: {failedAttempts[ipAddress]} failed attempts")

        time.sleep(checkInterval)  # Wait a bit before checking the file again

def startPingDetection():
    print("Starting ICMP packet detection...")
    sniff(filter="icmp", prn=detectPing)

def startSshDetection():
    print("Starting SSH detection...")
    sniff(filter="tcp port 22", prn=detectSshAttempt)

#def detectAttacks(packet):
    # detectPing(packet)
    # detectSshAttempt(packet)
    # detectPingOfDeath(packet)
    # detectXmasAttack(packet)
    # detectSynScan(packet)

def main():
    print("------------- IDS RUNNING -------------")

    logMonitorThread = threading.Thread(target=monitorLogFile, args=(2,2), daemon=True)
    detectPingThread = threading.Thread(target=startPingDetection, daemon=True)
    detectSshThread = threading.Thread(target=startSshDetection, daemon=True)

    if checkLogFile() == True:
        print("Failed or accepted SSH login attempts found!")
        userResponse = None

        while userResponse not in ('Y', 'N'):
            userResponse = input("Would you like to view them? (Y/N): ").upper()
            if userResponse not in ('Y', 'N'):
                print("Invalid response. Please enter 'Y' for Yes or 'N' for No.")

        if userResponse == "Y":
            detectBruteForceAttempts()
    else:
        print("No failed or accepted SSH login attempts found.")

    logMonitorThread.start()
    detectPingThread.start()
    detectSshThread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping threads and exiting program...")

if __name__ == "__main__":
    main()