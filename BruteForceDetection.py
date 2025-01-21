from scapy.all import *
from Logger import Logger

class BruteForceDetection:

    def detectBruteForceAttempts(self):
        parsedLogs = self.parseLogFile()
        threshold = 3
        failedAttempts = {}

        for log in parsedLogs:
            if log['outcome'] == "Failed":
                ipAddress = log['ipAddress']
                print(f"Failed login attempt on {log['date']} at {log['time']} for the user {log['user']} from IP {log['ipAddress']}")
                if ipAddress in failedAttempts:
                    failedAttempts[ipAddress] += 1
                else:
                    failedAttempts[ipAddress] = 1
            if log['outcome'] == "Accepted":
                print(
                    f"Accepted SSH connection from {ipAddress} on user {log['user']} on {log['date']} at {log['time']}.")
                print("If this was not you, please change your password as soon as possible!")

        for ip, count in failedAttempts.items():
            if count >= threshold:
                print(
                    f"[*] Possible brute force attack detected whilst the IDS was offline from {ip} with {count} failed login attempts on {log['date']} at {log['time']}!")

    def monitorLogFile(self, detectionThreshold, checkInterval):
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
                    logEntry = self.parseLogLine(line)
                    ipAddress = logEntry['ipAddress']
                    date = logEntry['date']
                    attackTime = logEntry['time']
                    failedAttempts[ipAddress] = failedAttempts.get(ipAddress, 0) + 1

                    if failedAttempts[ipAddress] >= detectionThreshold:
                        print(
                            f"[*] Possible live brute force attack detected from {ipAddress} with {failedAttempts[ipAddress]} failed login attempts on {date} at {attackTime}!")
                        Logger.logAttack("Brute Force", ipAddress)
                        #Logger.sendEmail("Brute Force", ipAddress)
                        #Logger.sendTextMessage("Brute Force", ipAddress)

            time.sleep(checkInterval)  # Wait a bit before checking the file again

    def checkLogFile(self):
        logFilePath = '/var/log/auth.log'
        flag = False

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

    def parseLogFile(self):
        logFilePath = '/var/log/auth.log'
        parsedLogs = []

        try:
            with open(logFilePath, 'r') as file:
                for line in file:
                    if "Failed password" in line or "Accepted password" in line:
                        parsedLog = self.parseLogLine(line)
                        parsedLogs.append(parsedLog)
            return parsedLogs
        except FileNotFoundError:
            print(f"The log file {logFilePath} was not found.")
        except PermissionError:
            print(f"Permission denied when trying to read {logFilePath}")

    def parseLogLine(self, line):
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