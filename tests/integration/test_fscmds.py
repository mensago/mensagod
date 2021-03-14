import os
import random
import shutil
import time
import uuid

from pymensago.cryptostring import CryptoString
from pymensago.encryption import EncryptionPair
from pymensago.retval import RetVal, ExceptionThrown
from pymensago.serverconn import ServerConnection

from integration_setup import login_admin, regcode_admin, setup_test, init_server, init_user, \
	init_user2


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

def make_test_file(path: str, file_size=-1, file_name='') -> RetVal:
	'''Generate a test file containing nothing but zeroes. If the file size is negative, a random 
	size between 1 and 10 Kb will be chosen. If the file name is empty, a random one will be 
	generated.'''
	
	if file_size < 0:
		file_size = random.randint(1,10) * 1024
	
	if file_name == '' or not file_name:
		file_name = f"{int(time.time())}.{file_size}.{str(uuid.uuid4())}"
	
	try:
		fhandle = open(os.path.join(path, file_name), 'w')
	except Exception as e:
		return RetVal(ExceptionThrown, e)
	
	fhandle.write('0' * file_size)
	fhandle.close()
	
	return RetVal()


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


def test_getquotainfo():
	'''This tests the command GETQUOTAINFO, which gets both the quota for the workspace and the 
	disk usage'''

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
	
	status = make_test_file(os.path.join(dbdata['configfile']['global']['workspace_dir'], 
		dbdata['admin_wid']), file_size=1000)
	assert not status.error(), f"Failed to create test workspace file: {status.info}"

	conn.send_message({ 'Action': 'GETQUOTAINFO', 'Data': {} })
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_getquotainfo: failed to get quota information'
	
	assert response['Data']['DiskUsage'] == '1000', 'test_getquotainfo: disk usage was incorrect'
	assert response['Data']['QuotaSize'] == dbdata['configfile']['global']['default_quota'], \
		"test_getquotainfo: admin quota didn't match the default"


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
	login_admin(dbdata, conn)

	init_user(dbdata, conn)
	init_user2(dbdata, conn)

	# Subtest #1: Bad sizes

	conn.send_message({
		'Action': 'SETQUOTA',
		'Data': {
			'Size': '0',
			'Workspaces': '33333333-3333-3333-3333-333333333333'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_setquota: failed to handle bad size value'

	conn.send_message({
		'Action': 'SETQUOTA',
		'Data': {
			'Size': "Real programmers don't eat quiche ;)",
			'Workspaces': '33333333-3333-3333-3333-333333333333'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_setquota: failed to handle bad size data type'

	# Subtest #2: Bad workspace list

	conn.send_message({
		'Action': 'SETQUOTA',
		'Data': {
			'Size': "4096",
			'Workspaces': '33333333-3333-3333-3333-333333333333,'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_setquota: failed to handle bad workspace list'

	# Subtest #3: Actual success

	conn.send_message({
		'Action': 'SETQUOTA',
		'Data': {
			'Size': "4096",
			'Workspaces': '33333333-3333-3333-3333-333333333333, ' \
				'44444444-4444-4444-4444-444444444444'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_setquota: failed to handle actual success'



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

	# Subtest #1: Missing parameters
	
	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': '1000',
			# Hash parameter is missing
			'Path': '/ ' + dbdata['admin_wid']
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_upload: #1 failed to handle missing parameter'

	# Subtest #2: Non-existent path

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': '1000',
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid'] + ' 22222222-2222-2222-2222-222222222222'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 404, 'test_upload: #2 failed to handle non-existent path'

	# Subtest #3: Size too big

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': str(0x4000_0000 * 200), # 200GiB isn't all that big :P
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid']
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 414, 'test_upload: #3 failed to handle file too big'

	# Subtest #4: Insufficient quota remaining

	# The administrator normally can't have a quota. We'll just fix that just for this one test
	# *heh*

	# Normally in Python direct string substitution is a recipe for SQL injection. We're not 
	# bringing in any insecure code here, so it's only a little bit bad.
	cur = dbconn.cursor()
	cur.execute(f"INSERT INTO quotas(wid, usage, quota)	VALUES('{dbdata['admin_wid']}', 5100 , 5120)")
	dbconn.commit()

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': str(0x10_0000 * 30), # 30MiB
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid']
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 409, 'test_upload: #4 quota check failed'

	# We need this to be unlimited for later tests
	cur = dbconn.cursor()
	cur.execute(f"UPDATE quotas SET quota=0 WHERE wid = '{dbdata['admin_wid']}'")
	dbconn.commit()

	# Subtest #5: Hash mismatch

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': str(1000),
			'Hash': r'BLAKE2B-256:5(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid']
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 100, 'test_upload: #5 failed to proceed to file upload'

	conn.write('0' * 1000)

	response = conn.read_response(server_response)
	assert response['Code'] == 410, 'test_upload: #5 failed to handle file hash mismatch'

	# Subtest #6: Actual success

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': str(1000),
			'Hash': r'BLAKE2B-256:|CAi^d1>P`4Tg*@9eZ2Kg|P^D!klB|G|=?q!;NVw',
			'Path': '/ ' + dbdata['admin_wid']
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 100, 'test_upload: #6 failed to proceed to file upload'

	conn.write('0' * 1000)

	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_upload: #6 failed to handle file hash mismatch'

	# Subtest #7: Interrupted transfer

	# Subtest #8: Resume offset larger than size of data stored server-side

	# Subtest #9: Resume interrupted transfer - exact match

	# Subtest #10: Overlapping resume


if __name__ == '__main__':
	# test_getquotainfo()
	# test_setquota()
	test_upload()
