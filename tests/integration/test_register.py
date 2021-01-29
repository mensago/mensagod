from pyanselus.encryption import EncryptionPair
from pyanselus.cryptostring import CryptoString
from pyanselus.serverconn import ServerConnection
from integration_setup import setup_test, config_server, regcode_admin, login_admin

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
	server_config = config_server(dbconn)
	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"
	
	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	devid = '22222222-2222-2222-2222-222222222222'
	devpair = EncryptionPair(CryptoString(r'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'),
		CryptoString(r'CURVE25519:W30{oJ?w~NBbj{F8Ag4~<bcWy6_uQ{i{X?NDq4^l'))
	
	server_config['pwhash'] = pwhash
	server_config['devid'] = devid
	server_config['devpair'] = devpair
	
	regcode_admin(server_config, conn)
	login_admin(server_config, conn)



	wid = '11111111-1111-1111-1111-111111111111'
	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	devkey = 'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'
	
	# Subtest #1: Regular registration that is supposed to succeed
	conn.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : wid,
			'Password-Hash' : pwhash,
			'Device-ID' : '11111111-1111-1111-1111-111111111111',
			'Device-Key' : devkey
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 201 and response['Status'] == 'REGISTERED', \
		'test_register: subtest #1 returned an error'
	
	# Subtest #2: Attempt registration of existing WID
	
	conn.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : wid,
			'Password-Hash' : pwhash,
			'Device-ID' : '11111111-1111-1111-1111-111111111111',
			'Device-Key' : devkey
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 408 and response['Status'] == 'RESOURCE EXISTS', \
		'test_register: subtest #2 failed to catch duplicate registration'

	conn.send_message({'Action' : "QUIT"})


def test_register_failures():
	'''Tests the server's REGISTER command with failure conditions'''

	dbconn = setup_test()
	server_config = config_server(dbconn)
	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	devid = '22222222-2222-2222-2222-222222222222'
	devpair = EncryptionPair(CryptoString(r'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'),
		CryptoString(r'CURVE25519:W30{oJ?w~NBbj{F8Ag4~<bcWy6_uQ{i{X?NDq4^l'))
	
	server_config['pwhash'] = pwhash
	server_config['devid'] = devid
	server_config['devpair'] = devpair
	
	regcode_admin(server_config, conn)
	login_admin(server_config, conn)

	# Test #1: Attempt registration with unsupported encryption type

	conn.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : '11111111-1111-1111-1111-222222222222',
			'Password-Hash' : pwhash,
			'Device-ID' : '11111111-1111-1111-1111-111111111111',
			'Device-Key' : '3DES:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 309 and response['Status'] == 'ENCRYPTION TYPE NOT SUPPORTED', \
		'test_register_failures: subtest #1 failed to catch unsupported encryption'

	# Test #2: Send bad WID

	conn.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
			'Password-Hash' : pwhash,
			'Device-ID' : '11111111-1111-1111-1111-111111111111',
			'Device-Key' : 'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400 and response['Status'] == 'BAD REQUEST', \
		'test_register_failures: subtest #2 failed to catch a bad WID'

	conn.send_message({'Action' : "QUIT"})


def test_overflow():
	'''Tests the server's command handling for commands greater than 8K'''

	dbconn = setup_test()
	server_config = config_server(dbconn)
	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	devid = '22222222-2222-2222-2222-222222222222'
	devpair = EncryptionPair(CryptoString(r'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'),
		CryptoString(r'CURVE25519:W30{oJ?w~NBbj{F8Ag4~<bcWy6_uQ{i{X?NDq4^l'))
	
	server_config['pwhash'] = pwhash
	server_config['devid'] = devid
	server_config['devpair'] = devpair
	
	regcode_admin(server_config, conn)
	login_admin(server_config, conn)

	conn.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : 'A' * 10240,
			'Password-Hash' : pwhash,
			'Device-ID' : '11111111-1111-1111-1111-111111111111',
			'Device-Key' : 'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400 and response['Status'] == 'BAD REQUEST', \
		'test_overflow: failed to catch overflow'

	conn.send_message({'Action' : "QUIT"})


if __name__ == '__main__':
	test_register()
	test_register_failures()
	test_overflow()
