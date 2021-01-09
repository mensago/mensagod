
from integration_setup import setup_test, config_server, validate_uuid, \
	ServerNetworkConnection

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

def test_register():
	'''Tests the server's REGISTER command - success and duplicate WID condition'''

	dbconn = setup_test()
	config_server(dbconn)

	wid = '11111111-1111-1111-1111-111111111111'
	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	devkey = 'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'

	sock = ServerNetworkConnection()
	assert sock.connect(), "Connection to server at localhost:2001 failed"

	
	# Subtest #1: Regular registration that is supposed to succeed
	sock.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : wid,
			'Password-Hash' : pwhash,
			'Device-ID' : '11111111-1111-1111-1111-111111111111',
			'Device-Key' : devkey
		}
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 201 and response['Status'] == 'REGISTERED', \
		'test_register: subtest #1 returned an error'
	assert validate_uuid(response['Data']['Device-ID']), \
		'test_register: bad device ID in subtest #1'

	
# 	# Test #2: Attempt registration of existing WID

# 	cmd = ' '.join([ "REGISTER", wid, pwhash, algorithm, devkey, "\r\n" ])
# 	print('Duplicate registration\n--------------------------')
# 	print('CLIENT: %s' % cmd)
# 	sock.send(cmd.encode())

# 	response = sock.recv(8192).decode()
# 	print('SERVER: %s\n' % response)
	
# 	parts = response.split(' ')
# 	assert parts[0] == '408' and parts[1] == 'RESOURCE', 'Failed to catch duplicate registration'

# 	sock.send(b'QUIT\r\n')


# def test_register_failures():
# 	'''Tests the server's REGISTER command with failure conditions'''

# 	setup_test()

# 	wid = '11111111-1111-1111-1111-111111111111'
# 	# password is 'SandstoneAgendaTricycle'
# 	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
# 				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
# 	algorithm = 'curve25519'
# 	devkey = '@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'

# 	sock = connect()
# 	assert sock, "Connection to server at localhost:2001 failed"

	
# 	# Test #1: Attempt registration with unsupported encryption type

# 	wid = '11111111-1111-1111-1111-222222222222'
# 	cmd = ' '.join([ "REGISTER", wid, pwhash, '3DES', devkey, "\r\n" ])
# 	print('Bad encryption algorithm\n--------------------------')
# 	print('CLIENT: %s' % cmd)
# 	sock.send(cmd.encode())

# 	response = sock.recv(8192).decode()
# 	print('SERVER: %s' % response)
	
# 	parts = response.split(' ')
# 	assert parts[0] == '309' and parts[1] == 'ENCRYPTION', 'Failed to catch unsupported algorithm'


# 	# Test #2: Send bad WID

# 	wid = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
# 	cmd = ' '.join([ "REGISTER", wid, pwhash, algorithm, devkey, "\r\n" ])
# 	print('Bad WID\n--------------------------')
# 	print('CLIENT: %s' % cmd)
# 	sock.send(cmd.encode())

# 	response = sock.recv(8192).decode()
# 	print('SERVER: %s' % response)
	
# 	parts = response.split(' ')
# 	assert parts[0] == '400' and parts[1] == 'BAD', 'Failed to catch bad WID'

# 	sock.send(b'QUIT\r\n')


# def test_overflow():
# 	'''Tests the server's command handling for commands greater than 8K'''

# 	print("Test: Command Overflow")
# 	setup_test()

# 	wid = '11111111-1111-1111-1111-111111111111'
# 	# password is 'SandstoneAgendaTricycle'
# 	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
# 				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
# 	algorithm = 'curve25519'
# 	devkey = '@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'

# 	sock = connect()
# 	assert sock, "Connection to server at localhost:2001 failed"

# 	wid = 'A' * 10240
# 	cmd = ' '.join([ "REGISTER", wid, pwhash, algorithm, devkey, "\r\n" ])
# 	print('Overflow\n--------------------------')
# 	print('CLIENT: %s' % cmd)
# 	sock.send(cmd.encode())

# 	response = sock.recv(8192).decode()
# 	print('SERVER: %s' % response)
	
# 	parts = response.split(' ')
# 	assert parts[0] == '400' and parts[1] == 'BAD', 'Failed to catch overflow'


	sock.send_message({'Action' : "QUIT"})


if __name__ == '__main__':
	test_register()
	# test_register_failures()
	# test_overflow()
