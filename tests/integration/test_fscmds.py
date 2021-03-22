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
	init_user2, reset_workspace_dir


server_response = {
	'title' : 'Mensago Server Response',
	'type' : 'object',
	'required' : [ 'Code', 'Status', 'Info', 'Data' ],
	'properties' : {
		'Code' : {
			'type' : 'integer'
		},
		'Status' : {
			'type' : 'string'
		},
		'Info' : {
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
	
	return RetVal().set_values({ 'name':file_name, 'size':file_size })


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

def test_copy():
	'''Tests the COPY command'''

	# Subtest #1: Nonexistent source file

	# Subtest #2: Nonexistent destination directory

	# Subtest #3: Source path is a directory

	# Subtest #4: Destination is file path

	# Subtest #5: Insufficient quota remaining

	# Subtest #6: Actual success


def test_getquotainfo():
	'''This tests the command GETQUOTAINFO, which gets both the quota for the workspace and the 
	disk usage'''

	dbconn = setup_test()
	dbdata = init_server(dbconn)

	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	reset_workspace_dir(dbdata)

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
	assert response['Data']['QuotaSize'] == '0', \
		"test_getquotainfo: admin quota wasn't unlimited"


def test_list():
	'''Tests the LIST command'''

	dbconn = setup_test()
	dbdata = init_server(dbconn)

	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	reset_workspace_dir(dbdata)

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

	# Subtest #1: Nonexistent path

	conn.send_message({
		'Action': 'LIST',
		'Data': {
			'Path': '/ 11111111-1111-1111-1111-111111111111'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 404, 'test_list: #1 failed to handle missing path'
	
	# Subtest #2: Path is a file

	admin_dir = os.path.join(dbdata['configfile']['global']['workspace_dir'],
		dbdata['admin_wid'])
	status = make_test_file(admin_dir)
	assert not status.error(), "test_list: #2 failed to create test file"

	conn.send_message({
		'Action': 'LIST',
		'Data': {
			'Path': ' '.join(['/', dbdata['admin_wid'], status['name']])
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_list: #2 failed to handle path as file'

	# Subtest #3: Empty directory

	os.mkdir(os.path.join(admin_dir, '11111111-1111-1111-1111-111111111111'))

	conn.send_message({
		'Action': 'LIST',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' 11111111-1111-1111-1111-111111111111'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_list: #3 failed to handle empty directory'
	assert 'Files' in response['Data'] and len(response['Data']['Files']) == 0, \
		'test_list: #3 failed to have empty response for empty directory'

	# Subtest #4: A list of files

	for i in range(1,6):
		tempname = '.'.join([str(1000 * i), '500', str(uuid.uuid4())])
		try:
			fhandle = open(os.path.join(admin_dir, '11111111-1111-1111-1111-111111111111', 
				tempname), 'w')
		except Exception as e:
			assert False, 'test_list: #4 failed to create test files: ' + e
		
		fhandle.write('0' * 500)
		fhandle.close()
		
	conn.send_message({
		'Action': 'LIST',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' 11111111-1111-1111-1111-111111111111'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_list: #4 failed to handle non-empty directory'
	assert 'Files' in response['Data'] and len(response['Data']['Files']) == 5, \
		'test_list: #4 failed to list all files in directory'

	# Subtest #5: A list of files with time specifier

	conn.send_message({
		'Action': 'LIST',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' 11111111-1111-1111-1111-111111111111',
			'Time': '3000'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_list: #5 failed to handle non-empty directory'
	assert 'Files' in response['Data'] and len(response['Data']['Files']) == 3, \
		'test_list: #5 failed to filter files'


def test_listdirs():
	'''Tests the LISTDIRS command'''

	dbconn = setup_test()
	dbdata = init_server(dbconn)

	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	reset_workspace_dir(dbdata)

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

	# Subtest #1: Nonexistent path

	conn.send_message({
		'Action': 'LISTDIRS',
		'Data': {
			'Path': '/ 11111111-1111-1111-1111-111111111111'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 404, 'test_listdirs: #1 failed to handle missing path'
	
	# Subtest #2: Path is a file

	admin_dir = os.path.join(dbdata['configfile']['global']['workspace_dir'],
		dbdata['admin_wid'])
	status = make_test_file(admin_dir)
	assert not status.error(), "test_listdirs: #2 failed to create test file"

	conn.send_message({
		'Action': 'LIST',
		'Data': {
			'Path': ' '.join(['/', dbdata['admin_wid'], status['name']])
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_listdirs: #2 failed to handle path as file'

	# Subtest #3: Empty directory

	os.mkdir(os.path.join(admin_dir, '11111111-1111-1111-1111-111111111111'))

	conn.send_message({
		'Action': 'LISTDIRS',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' 11111111-1111-1111-1111-111111111111'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_listdirs: #3 failed to handle empty directory'
	assert 'Directories' in response['Data'] and len(response['Data']['Directories']) == 0, \
		'test_listdirs: #3 failed to have empty response for empty directory'

	# Subtest #4: A list of directories

	for i in range(2,7):
		tempname = '-'.join([(str(i) * 8), (str(i) * 4), (str(i) * 4), (str(i) * 4), (str(i) * 12)])
		try:
			os.mkdir(os.path.join(admin_dir, '11111111-1111-1111-1111-111111111111', tempname))
		except Exception as e:
			assert False, 'test_listdirs: #4 failed to create test directories: ' + e
		
		make_test_file(os.path.join(admin_dir, '11111111-1111-1111-1111-111111111111'))

	conn.send_message({
		'Action': 'LISTDIRS',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' 11111111-1111-1111-1111-111111111111'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_listdirs: #4 failed to handle non-empty directory'
	assert 'Directories' in response['Data'] and len(response['Data']['Directories']) == 5, \
		'test_list: #4 failed to list all subdirectories'


def test_mkdir():
	'''Tests the MKDIR command'''

	dbconn = setup_test()
	dbdata = init_server(dbconn)

	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	reset_workspace_dir(dbdata)

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

	# Subtest #1: Bad directory name

	conn.send_message({
		'Action': 'MKDIR',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' some_dir_name'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_mkdir: #1 failed to handle bad path'
	

	# Subtest #2: Actual success - 1 directory

	conn.send_message({
		'Action': 'MKDIR',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' 11111111-1111-1111-1111-111111111111'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_mkdir: #2 failed to create legitimate directory'

	# Subtest #3: Directory already exists

	conn.send_message({
		'Action': 'MKDIR',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' 11111111-1111-1111-1111-111111111111'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 408, 'test_mkdir: #3 failed to handle existing directory'

	# Subtest #4: Actual success - nested directories

	multipath = ' '.join(['/', dbdata['admin_wid'],
		'22222222-2222-2222-2222-222222222222',
		'33333333-3333-3333-3333-333333333333',
		'44444444-4444-4444-4444-444444444444',
		'55555555-5555-5555-5555-555555555555'
	])
	conn.send_message({
		'Action': 'MKDIR',
		'Data': {
			'Path': multipath
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_mkdir: #2 failed to create legitimate directory'


def test_move():
	'''Tests the MOVE command'''

	# Subtest #1: Nonexistent source file

	# Subtest #2: Nonexistent destination directory

	# Subtest #3: Source path is a directory

	# Subtest #4: Destination is file path

	# Subtest #5: Actual success


def test_rmdir():
	'''Tests the RMDIR command'''

	dbconn = setup_test()
	dbdata = init_server(dbconn)

	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	reset_workspace_dir(dbdata)

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


	# Subtest #1: Bad directory name

	conn.send_message({
		'Action': 'MKDIR',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' some_dir_name',
			'Recursive': 'False'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_rmdir: #1 failed to handle bad path'

	# Subtest #2: Directory doesn't exist

	conn.send_message({
		'Action': 'RMDIR',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' 11111111-1111-1111-1111-111111111111',
			'Recursive': 'False'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 404, 'test_rmdir: #2 failed to handle nonexistent directory'

	# Subtest #3: Non-recursive call fails because of non-empty directory

	multipath = ' '.join(['/', dbdata['admin_wid'],
		'22222222-2222-2222-2222-222222222222',
		'33333333-3333-3333-3333-333333333333',
		'44444444-4444-4444-4444-444444444444',
		'55555555-5555-5555-5555-555555555555'
	])
	conn.send_message({
		'Action': 'MKDIR',
		'Data': {
			'Path': multipath,
			'Recursive': 'False'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_rmdir: #3 failed to create test hierarchy'

	conn.send_message({
		'Action': 'RMDIR',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' 22222222-2222-2222-2222-222222222222',
			'Recursive': 'False'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 408, 'test_rmdir: #3 failed to handle non-empty directory'

	# Subtest #4: Actual success - non-recursively remove an empty directory


	conn.send_message({
		'Action': 'RMDIR',
		'Data': {
			'Path': multipath,
			'Recursive': 'False'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_rmdir: #4 failed to remove an empty directory'

	# Subtest #5: Actual success - recursively remove files and subdirectories

	conn.send_message({
		'Action': 'RMDIR',
		'Data': {
			'Path': '/ ' + dbdata['admin_wid'] + ' 22222222-2222-2222-2222-222222222222',
			'Recursive': 'True'
		}
	})
	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_rmdir: #5 failed to remove an empty directory'


def test_select():
	'''Tests the SELECT command'''

	# Subtest #1: Nonexistent path

	# Subtest #2: Path is a file

	# Subtest #3: Actual success


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
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid']
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 100, 'test_upload: #6 failed to proceed to file upload'

	conn.write('0' * 1000)

	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_upload: #6 failed to handle file hash mismatch'

	# Set up an interrupted transfer

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': str(1000),
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid']
		}
	})

	response = conn.read_response(server_response)
	tempFileName = response['Data']['TempName']
	assert response['Code'] == 100, 'test_upload: #6 failed to proceed to file upload'
	assert tempFileName != '', 'test_upload: #6 server failed to return temp file name'

	conn.write('0' * 500)
	del conn
	
	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"
	login_admin(dbdata, conn)

	# Subtest #7: Resume offset larger than size of data stored server-side

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': str(1000),
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid'],
			'TempName': tempFileName,
			'Offset': '2000'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_upload: #7 failed to handle offset > file size'


	# Subtest #8: Resume interrupted transfer - exact match

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': str(1000),
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid'],
			'TempName': tempFileName,
			'Offset': '500'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 100, 'test_upload: #8 failed to proceed to file upload'

	conn.write('0' * 500)

	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_upload: #8 failed to resume with exact offset match'

	# Set up one last interrupted transfer

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': str(1000),
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid']
		}
	})

	response = conn.read_response(server_response)
	tempFileName = response['Data']['TempName']
	assert response['Code'] == 100, 'test_upload: #6 failed to proceed to file upload'
	assert tempFileName != '', 'test_upload: #6 server failed to return temp file name'

	conn.write('0' * 500)
	del conn
	
	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"
	login_admin(dbdata, conn)

	# Subtest #9: Overlapping resume

	conn.send_message({
		'Action': 'UPLOAD',
		'Data': {
			'Size': str(1000),
			'Hash': r'BLAKE2B-256:4(8V*JuSdLH#SL%edxldiA<&TayrTtdIV9yiK~Tp',
			'Path': '/ ' + dbdata['admin_wid'],
			'TempName': tempFileName,
			'Offset': '400'
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 100, 'test_upload: #9 failed to proceed to file upload'

	conn.write('0' * 600)

	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_upload: #9 failed to resume with overlapping offset'



if __name__ == '__main__':
	# test_getquotainfo()
	# test_list()
	# test_listdirs()
	# test_mkdir()
	test_rmdir()
	# test_setquota()
	# test_upload()
