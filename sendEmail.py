import smtplib
import ssl
from email.message import EmailMessage

senderEmail = "redacted"
receiverEmail = "redacted"
password = "redacted"

subject = "[PyIDS ALERT] Test Attack Detected"
body = "Test Attack detected from Test IP"

em = EmailMessage()
em['From'] = senderEmail
em['To'] = receiverEmail
em['Subject'] = subject
em.set_content(body)

context = ssl.create_default_context()

with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
    smtp.login(senderEmail, password)
    smtp.sendmail(senderEmail, receiverEmail, em.as_string())
