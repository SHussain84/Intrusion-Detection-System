import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class Logger:
    @staticmethod
    def logAttack(attackType, srcIp, dstIp=None, dstPort=None):
        currentDateTime = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        with open("logs.txt", "a") as logFile:
            if dstIp and dstPort:
                logMessage = f"[{attackType}] from {srcIp} to {dstIp}:{dstPort} at {currentDateTime}\n"
            else:
                logMessage = f"[{attackType}] from {srcIp} at {currentDateTime}\n"
            logFile.write(logMessage)

    @staticmethod
    def getCurrentDateTime():
        return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    @staticmethod
    def sendEmail(attackType, srcIp, dstIp=None, dstPort=None):
        senderEmail = "redacted"
        receiverEmail = "redacted"
        password = "redacted"

        msg = MIMEMultipart()
        msg['From'] = senderEmail
        msg['To'] = receiverEmail
        msg['Subject'] = f"[IDS ALERT] {attackType} Detected"
        body = f"{attackType} detected from {srcIp}"
        if dstIp and dstPort:
            body += f" to {dstIp}:{dstPort}"
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(senderEmail, password)
            text = msg.as_string()
            server.sendmail(senderEmail, receiverEmail, text)

    @staticmethod
    def sendTextMessage(attackType, srcIp, dstIp=None, dstPort=None):
        accountSid = ''
        authToken = ''
        twilioPhoneNumber = ''
        destinationPhoneNumber = 'redacted'

        client = Client(accountSid, authToken)
        messageBody = f"{attackType} detected from {srcIp}"
        if dstIp and dstPort:
            messageBody += f" to {dstIp}:{dstPort}"

        message = client.messages.create(
            body=messageBody,
            from_=twilioPhoneNumber,
            to=destinationPhoneNumber
        )

        print(f"Message sent with SID: {message.sid}")