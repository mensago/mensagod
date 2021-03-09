import os
import shutil
import time

from pymensago.cryptostring import CryptoString
from pymensago.encryption import EncryptionPair
from pymensago.serverconn import ServerConnection
from integration_setup import login_admin, regcode_admin, setup_test, init_server, init_user

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

def setup_testdir(name) -> str:
	'''Creates a test folder for holding files'''
	topdir = os.path.join(os.path.dirname(os.path.realpath(__file__)),'testfiles')
	if not os.path.exists(topdir):
		os.mkdir(topdir)

	testdir = os.path.join(topdir, name)
	while os.path.exists(testdir):
		try:
			shutil.rmtree(testdir)
		except:
			print("Waiting a second for test folder to unlock")
			time.sleep(1.0)
	os.mkdir(testdir)
	return testdir


def test_setquota():
	'''Tests the SETQUOTA command'''

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

	# Subtest #1: Non-administrator
	
	login_admin(dbdata, conn)

	init_user(dbdata, conn)

	# Subtest #2: Bad size

	# Subtest #3: Bad workspace list

	# Subtest #4: Actual success



def test_upload():
	'''Tests the UPLOAD command'''

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

	init_user(dbdata, conn)
	
	testpath = setup_testdir('test_upload')

	# Make a test file
	try:
		fhandle = open(os.path.join(testpath, 'uploadme.txt'), 'w')
	except Exception as e:
		assert False, f"test_upload: exception thrown creating temp file: {e}"
	
	fhandle.write('0' * 1000)
	fhandle.close()

	# Subtest #1: Missing parameters
	
	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': '1000',
			# Hash parameter is missing
			'Path': '/ ' + dbdata['user_wid']
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_upload: failed to handle missing parameter'

	# Subtest #2: Non-existent path

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': '1000',
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['user_wid'] + ' 22222222-2222-2222-2222-222222222222'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 404, 'test_upload: failed to handle non-existent path'

	# Subtest #3: Size too big

	conn.send_message({
		'Action': 'MKDIR',
		'Data': {
			'Path': '/ ' + dbdata['user_wid']
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_upload: failed to create user workspace directory'


	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': str(0x10_0000 * 200_000),
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['user_wid']
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 414, 'test_upload: failed to handle file too big'

	# Subtest #4: Insufficient quota remaining

	# Subtest #5: Hash mismatch

	# Subtest #6: Actual success

	# Subtest #7: Interrupted transfer

	# Subtest #8: Resume offset larger than size of data stored server-side

	# Subtest #9: Resume interrupted transfer - exact match

	# Subtest #10: Overlapping resume


if __name__ == '__main__':
	test_upload()
