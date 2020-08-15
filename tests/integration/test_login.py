from base64 import b85decode, b85encode
from nacl.public import PrivateKey, SealedBox
from integration_setup import setup_test, connect, validate_uuid

# Workspace ID : 11111111-1111-1111-1111-111111111111
# Friendly Address : jrobinson
# Status : active
# Password : SandstoneAgendaTricycle
# Local Password Hash : $argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCqdcCYkJLok65qussSyhN5TTZP+OTgzEI
# Server Password Hash : $argon2id$v=19$m=65536,t=2,p=1$stqWnAj7604YLtPk/oEd+w$KET7Q1OjDz8jymJhYLVvkxgcwB7uWCuxpZuUqwooLrM
# Identity Verify.b85 : 23k&JP-4sNQ{HKYn)7#j`(Fw}pv@WhJ2`^!Cs57)
# Identity Signing.b85 : nuV^-YSY~shq9cFjn8HRs4+AI&^{Fvkat1>4$G$Z
# Contact Public.b85 : q~NVs$%Z82g7ZfniK3@!N+FrzcYJnawDdyYa!}@W
# Contact Private.b85 : oLdi)O~WWC={1pe8W{e&E_OiW&J?j&E9@}mO(Iha
# Broadcast.b85 : VHMt@bDw|w-+KC8|IEn!;o|Li3gVG#rof@)gi&C1
# System.b85 : iNdT1WT&G5gx=;<G=2*N$EP$+TCf4gz@2rY$<UCr
# Folder Map.b85 : I|u|QIIZ_=+i#k#aA-_uP=E`>-1+g9X%jL}Z8tbR
# Message Folder : b32e9eb1-33bd-4a35-a8ce-eed23f5c9c4a
# Contacts Folder : 7c22e94b-65fa-43d2-9b27-9e202ef813cd
# Calendar Folder : 0603506a-395d-43e5-af11-b946e358e9a1
# Tasks Folder : 0a4171bd-8a5e-4e61-a6b1-1657418f311f
# Files Folder : c4f853de-4735-4889-85f0-044c84f6142f
# Attachments Folder : d24679e3-da6e-4730-b9f8-be376c6dcf19
# Social Folder : 98327262-cfba-454b-bd51-b24c9dfdb3ad
# Device #1 ID : c64eed46-1a2a-4baf-81b7-ac28c6284de9
# Device #1 Key Type : curve25519
# Device #1 Public.b85 : @X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z
# Device #1 Private.b85 : W30{oJ?w~NBbj{F8Ag4~<bcWy6_uQ{i{X?NDq4^l
# Device #2 ID : 7e780f98-529a-4b2d-92eb-1f874976ba62
# Device #2 Key Type : curve25519
# Device #2 Public.b85 : @B8FD;u#}Sd4jD*+LtpzRhxeVKW7h$Q4uA$`%AxM
# Device #2 Private.b85 : u3x80VFNg9V+`Jok5%$H(9os=$>W;W%qG8Y+>_Cz
# Device #3 ID : 92dc8c59-18e4-4472-b41f-95e2c3ebe31d
# Device #3 Key Type : curve25519
# Device #3 Public.b85 : K_3$mL8X@P(x!u7PkWnncDvp(XSYFJ0&qU*6!Hc`
# Device #3 Private.b85 : 3>Y=(Mg*|xcxl#}p+L0IcxqB%cncjQEA`R|1&r0_
# Device #4 ID : 1eb935eb-623f-4319-8a65-dc9ffa102bf5
# Device #4 Key Type : curve25519
# Device #4 Public.b85 : ij>F4A$$uckNj|M@7kSf=SKx#?K?l9!veJ`VTuYM
# Device #4 Private.b85 : RX!@Zj1N@`6CMffaqYIWE2JXit{$tg5U*TUHt$y)
# Device #5 ID : 36340705-3b30-4507-8e3b-4433287933ba
# Device #5 Key Type : curve25519
# Device #5 Public.b85 : YlT2>26y#gaIQOM8x*wO7Hc~+jflG#Din3VCs52v
# Device #5 Private.b85 : !lw2!SA7Qp%u!+(RCbgfdm1xicVHEELHdD!V24je

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

	print("Test: LOGIN")
	setup_test()

	wid = '11111111-1111-1111-1111-111111111111'
	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	algorithm = 'curve25519'
	devkey = '@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'
	devkeypriv = 'W30{oJ?w~NBbj{F8Ag4~<bcWy6_uQ{i{X?NDq4^l'
	keyobj = PrivateKey(b85decode(devkeypriv))
	box = SealedBox(keyobj)

	sock = connect()
	assert sock, "Connection to server at localhost:2001 failed"

	# Register a workspace

	cmd = ' '.join([ "REGISTER", wid, pwhash, algorithm, devkey, "\r\n" ])
	sock.send(cmd.encode())
	response = sock.recv(8192).decode()
	parts = response.strip().split(' ')
	assert len(parts) == 3, 'Server returned wrong number of parameters'
	assert parts[0] == '201' and parts[1] == 'REGISTERED', 'Failed to register'
	assert validate_uuid(parts[2]), 'Device ID from server failed to validate'
	devid = parts[2]

	# Test #1: Login

	## Phase 1: LOGIN
	cmd = ' '.join([ "LOGIN PLAIN", wid, "\r\n" ])
	print('Login\n--------------------------')
	print('CLIENT: %s' % cmd)
	sock.send(cmd.encode())

	response = sock.recv(8192).decode()
	print('SERVER: %s\n' % response)
	
	parts = response.strip().split(' ')
	assert parts[0] == '100' and parts[1] == 'CONTINUE', 'Failed to log in'

	## Phase 2: PASSWORD
	cmd = ' '.join([ "PASSWORD", pwhash, "\r\n" ])
	print('CLIENT: %s' % cmd)
	sock.send(cmd.encode())

	response = sock.recv(8192).decode()
	print('SERVER: %s\n' % response)
	
	parts = response.strip().split(' ')
	assert parts[0] == '100' and parts[1] == 'CONTINUE', 'Failed to auth password'

	## Phase 3: DEVICE
	cmd = ' '.join([ "DEVICE", devid, devkey, "\r\n" ])
	print('CLIENT: %s' % cmd)
	sock.send(cmd.encode())

	### Receive the server challenge
	response = sock.recv(8192).decode()
	print('SERVER: %s\n' % response)
	parts = response.strip().split(' ')
	assert len(parts) == 3, 'Server device challenge had wrong number of arguments'
	assert parts[0] == '100' and parts[1] == 'CONTINUE', 'Failed to auth password'

	### Decrypt the challenge
	encrypted_challenge = b85decode(parts[2])
	decrypted_challenge = box.decrypt(encrypted_challenge)

	### Send the response
	cmd = ' '.join([ "DEVICE", devid, devkey, b85encode(decrypted_challenge).decode(), "\r\n" ])
	print('CLIENT: %s' % cmd)
	sock.send(cmd.encode())

	### Receive the server's final response
	response = sock.recv(8192).decode()
	print('SERVER: %s\n' % response)
	parts = response.strip().split(' ')
	assert parts[0] == '200' and parts[1] == 'OK', 'Server challenge-response phase failed'

	sock.send(b'QUIT\r\n')


if __name__ == '__main__':
	test_login()
