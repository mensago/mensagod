from pymensago.encryption import EncryptionPair, SigningPair
from pycryptostring import CryptoString
import pymensago.keycard as keycard
import pymensago.iscmds as iscmds
import pymensago.serverconn as serverconn
from integration_setup import load_server_config_file, setup_test, init_server, regcode_admin, \
	login_admin

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


def test_register():
	'''Tests the server's REGISTER command - success and duplicate WID condition'''

	# Testing the REGISTER command only works when the server uses either network or public mode
	serverconfig = load_server_config_file()
	if serverconfig['global']['registration'] not in ['network', 'public']:
		return
	
	dbconn = setup_test()
	dbdata = init_server(dbconn)
	conn = serverconn.ServerConnection()
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

	# Testing the REGISTER command only works when the server uses either network or public mode
	serverconfig = load_server_config_file()
	if serverconfig['global']['registration'] not in ['network', 'public']:
		return
	
	dbconn = setup_test()
	dbdata = init_server(dbconn)
	conn = serverconn.ServerConnection()
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
	assert response['Code'] == 309, \
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


def test_unregister():
	'''Test the UNREGISTER command'''

	# Testing the UNREGISTER command only works when the server uses either network or public mode
	serverconfig = load_server_config_file()
	if serverconfig['global']['registration'] not in ['network', 'public']:
		return
	
	dbconn = setup_test()
	dbdata = init_server(dbconn)
	conn = serverconn.ServerConnection()
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

	userwid = '11111111-1111-1111-1111-111111111111'
	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	devkey = 'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'
	
	conn.send_message({
		'Action' : "REGISTER",
		'Data' : {
			'Workspace-ID' : userwid,
			'Password-Hash' : pwhash,
			'Device-ID' : devid,
			'Device-Key' : devkey
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 201 and response['Status'] == 'REGISTERED', \
		f"test_unregister: test user registration failed: {response['Status']}"
	
	# Subtest #1: Try to unregister the admin account
	conn.send_message({
		'Action' : "UNREGISTER",
		'Data' : {
			'Password-Hash' : pwhash
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 403 and response['Status'] == 'FORBIDDEN', \
		"test_unregister(): failed to properly handle trying to unregister admin account"

	conn.send_message({'Action' : "LOGOUT", 'Data' : {}})
	response = conn.read_response(server_response)
	assert response['Code'] == 200 and response['Status'] == 'OK'

	# Set up for subtest #2: log in as the user
	status = iscmds.login(conn, userwid, CryptoString(dbdata['oekey']))
	assert not status.error(), f"test_unregister(): user login phase failed: {status.info()}"

	status = iscmds.password(conn, userwid, pwhash)
	assert not status.error(), f"test_unregister(): password phase failed: {status.info()}"

	status = iscmds.device(conn, devid, devpair)
	assert not status.error(), f"test_unregister(): device phase failed: {status.info()}"

	# As a general rule, these mensagod integration tests don't call the regular pymensago client 
	# library calls because we do extra validation. However, we're going to make an exception in 
	# this test because LOGIN and ADDENTRY are both really big.
	usercard = keycard.UserEntry()
	usercard.set_fields({
		'Name':'Corbin Simons',
		'Workspace-ID':userwid,
		'User-ID':'csimons',
		'Domain':'example.com',
		'Contact-Request-Verification-Key':'ED25519:E?_z~5@+tkQz!iXK?oV<Zx(ec;=27C8Pjm((kRc|',
		'Contact-Request-Encryption-Key':'CURVE25519:yBZ0{1fE9{2<b~#i^R+JT-yh-y5M(Wyw_)}_SZOn',
		'Encryption-Key':'CURVE25519:_`UC|vltn_%P5}~vwV^)oY){#uvQSSy(dOD_l(yE',
		'Verification-Key':'ED25519:k^GNIJbl3p@N=j8diO-wkNLuLcNF6#JF=@|a}wFE'
	})

	crspair = SigningPair(
		CryptoString(r'ED25519:E?_z~5@+tkQz!iXK?oV<Zx(ec;=27C8Pjm((kRc|'),
		CryptoString(r'ED25519:u4#h6LEwM6Aa+f<++?lma4Iy63^}V$JOP~ejYkB;')
	)

	status = usercard.is_data_compliant()
	assert not status.error(), f"test_unregister: user card not compliant: {status.info()}"
	status = iscmds.addentry(conn, usercard, CryptoString(dbdata['ovkey']), crspair)
	assert not status.error(), f"test_unregister: addentry() failed: {status.info()}\n" \
		f"Server Info: {status['Info']}"


	# Subtest #2: Unregister regular user from admin account
	conn.send_message({
		'Action' : "UNREGISTER",
		'Data' : {
			'Workspace-ID' : userwid,
			'Password-Hash' : pwhash
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 202 and response['Status'] == 'UNREGISTERED', \
		f"test_unregister(): user unregistration failed: {response['Status']}"
	
	# Check to make sure the database end was handled correctly
	cur = dbconn.cursor()
	cur.execute('SELECT password,status FROM workspaces WHERE wid = %s ', (userwid,))
	row = cur.fetchone()
	assert row, "test_unregister(): cleanup check query found no rows"
	assert row[0] == '-' and row[1] == 'deleted', \
		"test_unregister(): server failed to clean up database properly"
	
	conn.send_message({'Action' : "QUIT"})



def test_overflow():
	'''Tests the server's command handling for commands greater than 8K'''

	dbconn = setup_test()
	dbdata = init_server(dbconn)
	conn = serverconn.ServerConnection()
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
	# mensagod doesn't even respond to this message because the JSON data isn't formatted correctly.
	# In short, you can send as big of a message as you want, but if it's not properly formatted
	# JSON because it's too big to fit into 8K, we're going to ignore you now. *heh*
	assert response['Code'] == 400, 'test_overflow: failed to catch overflow'

	conn.send_message({'Action' : "QUIT"})


if __name__ == '__main__':
	# test_register()
	# test_register_failures()
	test_overflow()
	# test_unregister()
