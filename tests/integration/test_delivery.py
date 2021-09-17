from pycryptostring import CryptoString
from pymensago.encryption import EncryptionPair
from pymensago.serverconn import ServerConnection

from integration_setup import login_admin, regcode_admin, setup_test, init_server, init_user, \
	init_user2, reset_top_dir


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

def test_send():
	'''Tests the SEND command'''

	dbconn = setup_test()
	dbdata = init_server(dbconn)

	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	reset_top_dir(dbdata)

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

	init_user(dbdata, conn)
	init_user2(dbdata, conn)
	
	# Subtest #1: Missing parameters
	
	conn.send_message({
		'Action': 'SEND',
		'Data': {
			'Size': '1000',
			# Hash parameter is missing
			'Path': '/ ' + dbdata['admin_wid']
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_send: #1 failed to handle missing parameter'

	# Subtest #2: Non-existent domain

	# TODO: POSTDEMO: Implement SEND subtest for non-existent domain

	# Subtest #3: Size too big

	conn.send_message({
		'Action': 'SEND',
		'Data': {
			'Size': str(0x4000_0000 * 200), # 200GiB isn't all that big :P
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid'],
			'Domain': 'example.net'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 414, 'test_send: #3 failed to handle file too big'

	# Subtest #4: Insufficient quota remaining

	# The administrator normally can't have a quota. We'll just fix that just for this one test
	# *heh*

	# Normally in Python direct string substitution is a recipe for SQL injection. We're not 
	# bringing in any insecure code here, so it's only a little bit bad.
	cur = dbconn.cursor()
	cur.execute(f"INSERT INTO quotas(wid, usage, quota)	VALUES('{dbdata['admin_wid']}', 5100 , 5120)")
	dbconn.commit()

	conn.send_message({
		'Action': 'SEND',
		'Data': {
			'Size': str(0x10_0000 * 30), # 30MiB
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid'],
			'Domain': 'example.net'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 409, 'test_send: #4 quota check failed'

	# We need this to be unlimited for later tests
	cur = dbconn.cursor()
	cur.execute(f"UPDATE quotas SET quota=0 WHERE wid = '{dbdata['admin_wid']}'")
	dbconn.commit()

	# TODO: Finish tests once PyMensago messaging code is implemented


def test_sendfast():
	'''Tests the SEND command'''
	
	dbconn = setup_test()
	dbdata = init_server(dbconn)

	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	reset_top_dir(dbdata)

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

	init_user(dbdata, conn)
	init_user2(dbdata, conn)
	
	# Subtest #1: Missing parameters
	
	conn.send_message({
		'Action': 'SENDFAST',
		'Data': {
			# Domain parameter is missing
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_send: #1 failed to handle missing parameter'

	# Subtest #2: Non-existent domain

	# TODO: POSTDEMO: Implement SEND subtest for non-existent domain

	# Subtest #3: real successful message delivery

	# Construct the contact request
	
	# TODO: Finish implementing sendfast() test
	conreq = {
		'Version': '1.0',
		'ID': 'FIXME',
		'Type': 'sysmessage',
		'Subtype': 'contactreq.1',
		'ContactInfo': {
			'Header': { 'Version':'1.0', 'EntityType':'Individual' },
			'GivenName': 'Example.com',
			'FamilyName': 'Admin',
			'FormattedName': 'Example.com Admin',
			'Mensago': [
				{	'Label': 'Primary',
					'UserID': admin_profile_data['uid'].as_string(),
					'Domain': admin_profile_data['domain'].as_string(),
					'WorkspaceID': admin_profile_data['wid'].as_string()
				}
			]
		}		
	}


if __name__ == '__main__':
	test_send()
	test_sendfast()
