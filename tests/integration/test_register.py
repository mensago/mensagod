
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

	
	# Subtest #2: Attempt registration of existing WID
	
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
	assert response['Code'] == 408 and response['Status'] == 'RESOURCE EXISTS', \
		'test_register: subtest #2 failed to catch duplicate registration'

	sock.send_message({'Action' : "QUIT"})


def test_register_failures():
	'''Tests the server's REGISTER command with failure conditions'''

	dbconn = setup_test()
	config_server(dbconn)

	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'

	sock = ServerNetworkConnection()
	assert sock.connect(), "Connection to server at localhost:2001 failed"
	
	# Test #1: Attempt registration with unsupported encryption type

	sock.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : '11111111-1111-1111-1111-222222222222',
			'Password-Hash' : pwhash,
			'Device-ID' : '11111111-1111-1111-1111-111111111111',
			'Device-Key' : '3DES:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'
		}
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 309 and response['Status'] == 'ENCRYPTION TYPE NOT SUPPORTED', \
		'test_register_failures: subtest #1 failed to catch unsupported encryption'

	# Test #2: Send bad WID

	sock.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
			'Password-Hash' : pwhash,
			'Device-ID' : '11111111-1111-1111-1111-111111111111',
			'Device-Key' : 'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'
		}
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 400 and response['Status'] == 'BAD REQUEST', \
		'test_register_failures: subtest #2 failed to catch a bad WID'

	sock.send_message({'Action' : "QUIT"})


def test_overflow():
	'''Tests the server's command handling for commands greater than 8K'''

	dbconn = setup_test()
	config_server(dbconn)
	sock = ServerNetworkConnection()
	assert sock.connect(), "Connection to server at localhost:2001 failed"

	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'

	sock.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : 'A' * 10240,
			'Password-Hash' : pwhash,
			'Device-ID' : '11111111-1111-1111-1111-111111111111',
			'Device-Key' : 'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'
		}
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 400 and response['Status'] == 'BAD REQUEST', \
		'test_overflow: failed to catch overflow'

	sock.send_message({'Action' : "QUIT"})


if __name__ == '__main__':
	test_register()
	# test_register_failures()
	# test_overflow()
