from twilio.rest import Client

accountSid = 'redacted'
authToken = 'redacted'
twilioPhoneNumber = 'redacted'
destinationPhoneNumber = 'redacted'

client = Client(accountSid, authToken)
messageBody = "Test Attack detected from Test IP"

message = client.messages.create(
    body=messageBody,
    from_=twilioPhoneNumber,
    to=destinationPhoneNumber
)
