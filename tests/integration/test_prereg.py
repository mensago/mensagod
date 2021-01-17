from pyanselus.encryption import EncryptionPair, Password
from pyanselus.cryptostring import CryptoString
from integration_setup import setup_test, config_server, validate_uuid, \
	ServerNetworkConnection, regcode_admin, login_admin

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

def test_prereg():
	'''Tests the server's PREREG command with failure conditions'''

	dbconn = setup_test()
	server_config = config_server(dbconn)

	uid = 'TestUserID'
	wid = '11111111-1111-1111-1111-111111111111'
	domain = 'acme.com'

	sock = ServerNetworkConnection()
	assert sock.connect(), "Connection to server at localhost:2001 failed"

	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	devid = '22222222-2222-2222-2222-222222222222'
	devpair = EncryptionPair(CryptoString(r'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'),
		CryptoString(r'CURVE25519:W30{oJ?w~NBbj{F8Ag4~<bcWy6_uQ{i{X?NDq4^l'))
	
	server_config['pwhash'] = pwhash
	server_config['devid'] = devid
	server_config['devpair'] = devpair
	
	regcode_admin(server_config, sock)
	login_admin(server_config, sock)
	
	# Subtest #1: Prereg with user ID and domain
	sock.send_message({
		'Action' : "PREREG",
		'Data' : {
			'User-ID' : uid,
			'Domain' : domain
		}
	})
	
	response = sock.read_response(server_response)
	assert response['Code'] == 200 and response['Status'] == 'OK', \
		'test_prereg: subtest #1 returned an error'
	assert response['Data']['User-ID'] == uid, \
		'test_prereg: wrong user ID in subtest #1'
	assert response['Data']['Domain'] == domain, \
		'test_prereg: wrong domain in subtest #1'
	assert validate_uuid(response['Data']['Workspace-ID']), 'Server returned a bad WID'
	assert len(response['Data']['Workspace-ID']) <= 128, \
		'Server returned a regcode longer than allowed'

	# REGCODE subtest setup
	regdata = response
	pwd = Password()
	status = pwd.Set('ShrivelCommuteGottenAgonizingElbowQuiver')
	assert not status.error(), 'test_prereg: Failed to set password'
	devid = '0e6406e3-1831-4352-9fbe-0de8faebf0f0'
	devkey = EncryptionPair()


	# Subtest #2: Regcode with User ID and domain
	sock.send_message({
		'Action' : "REGCODE",
		'Data' : {
			'User-ID' : regdata['Data']['User-ID'],
			'Domain' : regdata['Data']['Domain'],
			'Reg-Code' : regdata['Data']['Reg-Code'],
			'Password-Hash' : pwd.hashstring,
			'Device-ID' : devid,
			'Device-Key' : devkey.get_public_key()
		}
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 201 and response['Status'] == 'REGISTERED', \
		'test_prereg: subtest #2 returned an error'


	# Subtest #3: Plain prereg
	sock.send_message({
		'Action' : "PREREG",
		'Data' : { }
	})
	
	response = sock.read_response(server_response)
	assert response['Code'] == 200 and response['Status'] == 'OK', \
		'test_prereg: subtest #2 returned an error'
	assert validate_uuid(response['Data']['Workspace-ID']), 'Server returned a bad WID'
	assert len(response['Data']['Workspace-ID']) <= 128, \
		'Server returned a regcode longer than allowed'

	# Subtest #4: Plain regcode
	regdata = response
	sock.send_message({
		'Action' : "REGCODE",
		'Data' : {
			'Workspace-ID' : regdata['Data']['Workspace-ID'],
			'Reg-Code' : regdata['Data']['Reg-Code'],
			'Password-Hash' : pwd.hashstring,
			'Device-ID' : devid,
			'Device-Key' : devkey.get_public_key()
		}
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 201 and response['Status'] == 'REGISTERED', \
		'test_prereg: subtest #4 returned an error'


	# Subtest #5: duplicate user ID
	sock.send_message({
		'Action' : "PREREG",
		'Data' : {
			'User-ID' : uid,
			'Domain' : domain
		}
	})
	
	response = sock.read_response(server_response)
	assert response['Code'] == 408 and response['Status'] == 'RESOURCE EXISTS', \
		'test_prereg: subtest #3 failed to catch duplicate user'


	# Subtest #6: WID as user ID
	sock.send_message({
		'Action' : "PREREG",
		'Data' : { 'User-ID' : wid }
	})
	
	response = sock.read_response(server_response)
	assert response['Code'] == 200 and response['Status'] == 'OK', \
		'test_prereg: subtest #4 returned an error'
	assert response['Data']['Workspace-ID'] == wid, 'Server returned a bad WID'
	assert len(response['Data']['Workspace-ID']) <= 128, \
		'Server returned a regcode longer than allowed'


	# Subtest #7: Specify WID
	wid = '22222222-2222-2222-2222-222222222222'
	sock.send_message({
		'Action' : "PREREG",
		'Data' : { 'Workspace-ID' : wid }
	})
	
	response = sock.read_response(server_response)
	assert response['Code'] == 200 and response['Status'] == 'OK', \
		'test_prereg: subtest #4 returned an error'
	assert response['Data']['Workspace-ID'] == wid, 'Server returned a bad WID'
	assert len(response['Data']['Workspace-ID']) <= 128, \
		'Server returned a regcode longer than allowed'


	# Subtest #8: Specify User ID only.
	uid = 'TestUserID2'
	sock.send_message({
		'Action' : "PREREG",
		'Data' : { 'User-ID' : uid }
	})
	
	response = sock.read_response(server_response)
	assert response['Code'] == 200 and response['Status'] == 'OK', \
		'test_prereg: subtest #6 returned an error'
	assert response['Data']['User-ID'] == uid , 'Server returned the wrong user ID'
	assert validate_uuid(response['Data']['Workspace-ID']), 'Server returned a bad WID'
	assert len(response['Data']['Workspace-ID']) <= 128, \
		'Server returned a regcode longer than allowed'

	sock.send_message({'Action' : "QUIT"})

if __name__ == '__main__':
	test_prereg()
