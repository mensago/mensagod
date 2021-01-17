from base64 import b85decode, b85encode
import secrets

from pyanselus.cryptostring import CryptoString
from pyanselus.encryption import EncryptionPair, PublicKey
from integration_setup import setup_test, config_server, ServerNetworkConnection

server_response = {
	'title' : 'Anselus Server Response',
	'type' : 'object',
	'required' : [ 'Code', 'Status', 'Data' ],
	'properties' : {
		'Code' : {
			'type' : 'integer'
		},
		'Status' : {
			'type' : 'string'
		},
		'Data' : {
			'type' : 'object'
		}
	}
}

class Base85Encoder:
	'''Base85 encoder for PyNaCl library'''
	@staticmethod
	def encode(data):
		'''Returns Base85 encoded data'''
		return b85encode(data)
	
	@staticmethod
	def decode(data):
		'''Returns Base85 decoded data'''
		return b85decode(data)

def test_login():
	'''Performs a basic login intended to be successful'''
	
	dbconn = setup_test()
	server_config = config_server(dbconn)
	sock = ServerNetworkConnection()
	assert sock.connect(), "Connection to server at localhost:2001 failed"

	wid = '11111111-1111-1111-1111-111111111111'
	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	devid = '22222222-2222-2222-2222-222222222222'
	devpair = EncryptionPair(CryptoString(r'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'),
		CryptoString(r'CURVE25519:W30{oJ?w~NBbj{F8Ag4~<bcWy6_uQ{i{X?NDq4^l'))
	
	# Register a workspace
	sock.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : wid,
			'Password-Hash' : pwhash,
			'Device-ID' : wid,
			'Device-Key' : devpair.public.as_string()
		}
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 201 and response['Status'] == 'REGISTERED', \
		'test_login: failed to register test workspace'

	# Phase 1: LOGIN
	
	# To ensure that we really are connecting to the server we *think* we are, we'll create a
	# challenge that the server must decrypt. We'll encrypt the challenge, which is just a string 
	# of random bytes, using the server's public encryption key obtained from the organization's
	# keycard. Each workspace ID is unique to the server, so we don't have to submit the domain
	# associated with it. The best part is that because workspace IDs are arbitrary, submitting
	# a workspace ID to a malicious server only gives them a UUID associated with an IP address.
	# This is not anything special and if an APT were to have set up a malicious server, they would 
	# very likely already have this information anyway.

	# We Base85 encode the challenge because it doesn't change the randomness and it makes the
	# comparison easier -- comparing strings. :)
	challenge = b85encode(secrets.token_bytes(32))
	ekey = PublicKey(CryptoString(server_config['oekey']))
	status = ekey.encrypt(challenge)
	assert not status.error(), 'test_login: failed to encrypt server challenge'

	sock.send_message({
		'Action' : "LOGIN",
		'Data' : {
			'Workspace-ID' : wid,
			'Login-Type' : 'PLAIN',
			'Challenge' : status['data']
		}
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 100 and response['Status'] == 'CONTINUE', \
		'test_login: failed to log in'
	assert response['Data']['Response'] == challenge.decode(), \
		'test_login: server failed identity response'

	# Phase 2: PASSWORD
	sock.send_message({
		'Action' : "PASSWORD",
		'Data' : { 'Password-Hash' : pwhash }
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 100 and response['Status'] == 'CONTINUE', \
		'test_login: failed to auth password'

	# Phase 3: DEVICE
	sock.send_message({
		'Action' : "DEVICE",
		'Data' : { 
			'Device-ID' : devid,
			'Device-Key' : devpair.public.as_string()
		}
	})

	# Receive, decrypt, and return the server challenge
	response = sock.read_response(server_response)
	assert response['Code'] == 100 and response['Status'] == 'CONTINUE', \
		'test_login: failed to auth device'
	assert 'Challenge' in response['Data'], 'test_login: server did not return a device challenge'
	
	status = devpair.decrypt(response['Data']['Challenge'])
	assert not status.error(), 'test_login: failed to decrypt device challenge'

	sock.send_message({
		'Action' : "DEVICE",
		'Data' : { 
			'Device-ID' : devid,
			'Device-Key' : devpair.public.as_string(),
			'Response' : status['data']
		}
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 200 and response['Status'] == 'OK', \
		'Server challenge-response phase failed'

	sock.send_message({'Action' : "QUIT"})


if __name__ == '__main__':
	test_login()
