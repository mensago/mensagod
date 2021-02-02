from pyanselus.cryptostring import CryptoString
from pyanselus.encryption import EncryptionPair
from pyanselus.serverconn import ServerConnection
from integration_setup import setup_test, init_server, regcode_admin, login_admin

def test_login():
	'''Performs a basic login intended to be successful'''
	
	dbconn = setup_test()
	dbdata = init_server(dbconn)
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

	# Most of the code which was originally written for this test is needed for other tests
	# because commands like PREREG require being logged in as the administrator. Both of these
	# functions still perform all the necessary tests that were originally done here.
	regcode_admin(dbdata, conn)
	login_admin(dbdata, conn)

	conn.send_message({'Action' : "QUIT"})


def test_setpassword():
	'''Tests the SETPASSWORD command'''
	dbconn = setup_test()
	dbdata = init_server(dbconn)
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

	badpwhash = '$argon2id$v=19$m=65536,t=2,' \
		'p=1$l0nvPkQDxJDKIMZsA96x4A$c5+XHmZjzSJIg3/vXXr33YNB1Jl52mdXtbMASLP1abs'
	newpwhash = '$argon2id$v=19$m=65536,t=2,' \
		'p=1$4WOWeLn7oOmrkp41zMzMcQ$8G51UCiIC/eETPJf0RZ5cNkX7jr3NkT92etTwNEO+f0'
	
	# Subtest #1: Failure because of wrong password sent
	conn.send_message({
		'Action' : "SETPASSWORD",
		'Data' : {
			'Password-Hash' : badpwhash,
			'NewPassword-Hash' : newpwhash
		}
	})
	
	response = conn.read_response(None)
	assert response['Code'] == 402 and response['Status'] == 'AUTHENTICATION FAILURE', \
		'test_setpassword(): Failed to catch bad password'

	# Subtest #2: Successful password change
	conn.send_message({
		'Action' : "SETPASSWORD",
		'Data' : {
			'Password-Hash' : pwhash,
			'NewPassword-Hash' : newpwhash
		}
	})
	
	response = conn.read_response(None)
	assert response['Code'] == 200 and response['Status'] == 'OK', \
		'test_setpassword(): Failed to update admin password'

	conn.send_message({'Action' : "QUIT"})


if __name__ == '__main__':
	# test_login()
	test_setpassword()

