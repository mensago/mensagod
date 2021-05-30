from pymensago.encryption import EncryptionPair, Password
from pycryptostring import CryptoString
from pymensago.serverconn import ServerConnection
from integration_setup import setup_test, init_server, regcode_admin, login_admin

server_response = {
	'title' : 'Mensago Server Response',
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

def test_set_status():
	'''Tests the SETSTATUS command'''

	dbconn = setup_test()
	dbdata = init_server(dbconn)

	uid = 'csimons'
	domain = 'example.net'

	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	devid = '22222222-2222-2222-2222-222222222222'
	devpair = EncryptionPair(CryptoString(r'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'),
		CryptoString(r'CURVE25519:W30{oJ?w~NBbj{F8Ag4~<bcWy6_uQ{i{X?NDq4^l'))
	
	dbdata['pwhash'] = pwhash
	dbdata['devid'] = devid
	dbdata['devpair'] = devpair
	
	regcode_admin(dbdata, conn)
	login_admin(dbdata, conn)
	
	# Prereg with a test user
	conn.send_message({
		'Action' : "PREREG",
		'Data' : {
			'User-ID' : uid,
			'Domain' : domain
		}
	})
	
	response = conn.read_response(server_response)
	assert response['Code'] == 200 and response['Status'] == 'OK', \
		'test_set_status: failed to prereg test user'

	# Call REGCODE to actually register the user
	regdata = response
	pwd = Password()
	status = pwd.Set('ShrivelCommuteGottenAgonizingElbowQuiver')
	assert not status.error(), 'test_set_status: Failed to set password'
	devid = '0e6406e3-1831-4352-9fbe-0de8faebf0f0'
	devkey = EncryptionPair()


	# Subtest #2: Regcode with User ID and domain
	conn.send_message({
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

	response = conn.read_response(server_response)
	assert response['Code'] == 201 and response['Status'] == 'REGISTERED', \
		'test_set_status: failed to register test user'

	conn.send_message({
		'Action': 'SETSTATUS',
		'Data': {
			'Workspace-ID': regdata['Data']['Workspace-ID'],
			'Status': 'disabled'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200 and response['Status'] == 'OK', \
		'test_set_status: failed to disable test user'


if __name__ == '__main__':
	test_set_status()
