#!/usr/bin/env python3

# This script experiments with the process of generating a test message and encrypting it into
# what is appropriate to store on the server.

import json

from pymensago.encryption import EncryptionPair, SecretKey

msg_recipient = json.dumps({
	'To': '22222222-2222-2222-2222-222222222222/example.com',
	'SenderDomain': 'example.com'
})

msg_sender = json.dumps({
	'From': '11111111-1111-1111-1111-111111111111/example.com',
	'RecipientDomain': 'example.com'
})

sample_envelope = {
	'Version' : '1.0',
	'Receiver' : '',
	'Sender' : '',
	'Date' : '20190905 155323',
	'KeyHash' : '',
	'PayloadKey' : ''
}

sample_msg = {
	"Type:": "usermessage",
	"Version": "1.0",
	'From': '11111111-1111-1111-1111-111111111111/example.com',
	'To': '22222222-2222-2222-2222-222222222222/example.com',
	'Date': '20190905 155323',
	'ThreadID': '2280c1f2-d9c0-440c-a182-967b16ba428a',
	'Subject': 'Sample User Message',
	'Body': 'It was a bright cold day in April, and the clocks were striking thirteen.',
}

# These would normally be the Primary Encryption Keys of the sending and receiving servers
sdomain_epair = EncryptionPair()
rdomain_epair = EncryptionPair()

# Ephemeral keys for the delivery info and message body
msg_key = SecretKey()

# Encryption key given to the sending user by the receiving user
recipient_epair = EncryptionPair()

status = rdomain_epair.encrypt(msg_recipient.encode())
sample_envelope['Recipient'] = status['data']

status = sdomain_epair.encrypt(msg_sender.encode())
sample_envelope['Sender'] = status['data']

sample_envelope['KeyHash'] = recipient_epair.get_public_hash()

payload = msg_key.encrypt(json.dumps(sample_msg).encode())
status = recipient_epair.encrypt(msg_key.get_key().encode())
sample_envelope['PayloadKey'] = status['data']

sections = [
	'MENSAGO',
	json.dumps(sample_envelope, indent=4),
	'----------',
	msg_key.enctype,
	payload
]
for section in sections:
	print(section)
