# pylint: disable=too-many-lines
import os
import random
import shutil
import time
import uuid

from retval import RetVal

from pycryptostring import CryptoString
from pymensago.encryption import EncryptionPair
from pymensago.serverconn import ServerConnection

from integration_setup import login_admin, regcode_admin, setup_test, init_server, \
	reset_top_dir

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
		return RetVal().wrap_exception(e)
	
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


def setup_updates(dbconn, dbdata: dict) -> dict:
	'''Sets up the administrator workspace with some test files and adds records to the database 
	to enable testing the update/sync code'''
	
	admin_dir = os.path.join(dbdata['configfile']['global']['workspace_dir'], dbdata['admin_wid'])

	dirinfo = [
		('new',os.path.join(admin_dir, 'new')),
		('messages',os.path.join(admin_dir, '11111111-1111-1111-1111-111111111111')),
		('contacts',os.path.join(admin_dir, '22222222-2222-2222-2222-222222222222')),
		('files', os.path.join(admin_dir, '33333333-3333-3333-3333-333333333333')),
		('attachments', os.path.join(admin_dir, '33333333-3333-3333-3333-333333333333',
									'11111111-1111-1111-1111-111111111111'))
	]
	dirs = {}
	for item in dirinfo:
		os.mkdir(item[1])
		dirs[item[0]] = item[1]

	now = int(time.time())
	cur = dbconn.cursor()
	
	files = {}
	files['new'] = []
	for i in range(200):
		status = make_test_file(dirs['new'])
		assert not status.error(), f"setup_updates: failed to create test file: {status.info}"
		files['new'].append(status['name'])
		
		path = f"/ {dbdata['admin_wid']} new {status['name']}"

		# we make the timestamp for each of the new files about a day apart
		filetime = now - ((200-i) * 86400)

		cur.execute("INSERT INTO updates(rid,wid,update_type,update_data,unixtime) VALUES("
			f"'{str(uuid.uuid4())}','{dbdata['admin_wid']}',1,'{path}','{filetime}')")
	
	dbconn.commit()

	return { 'dirs': dirs, 'files': files }


def test_get_updates():
	'''Tests GETUPDATES'''
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

	setup_updates(dbconn, dbdata)
	now = int(time.time())

	# Subtest #1: missing parameter
	conn.send_message({'Action': 'GETUPDATES','Data': {}})
	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_get_updates: #1 failed to handle missing parameter'

	# Subtest #2: get updates from the last 5 days
	conn.send_message({
		'Action': 'GETUPDATES',
		'Data': { 'Time': str(now - (86400 * 5)) }
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_get_updates: #2 failed to get updates'
	assert len(response['Data']['Updates']) == 4, "failed to get updates from the last 5 days"
	assert response['Data']['UpdateCount'] == "4", \
		"test_get_updates: #2 got wrong number of updates in count"
	
	# Subtest #3: test out handling more updates than will fit into 1 response
	conn.send_message({
		'Action': 'GETUPDATES',
		'Data': { 'Time': '0' }
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_get_updates: #3 failed to get updates'
	assert len(response['Data']['Updates']) < 150, "test_get_updates: #3 returned all possible updates"
	assert response['Data']['UpdateCount'] == "200", \
		"test_get_updates: #3 got wrong number of updates in count"

	# Subtest #4: test out handling more updates than will fit into 1 response
	conn.send_message({
		'Action': 'IDLE',
		'Data': { 'CountUpdates': str(now - (86400 * 5)) }
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_get_updates: #4 IDLE command failed'
	assert response['Data']['UpdateCount'] == "4", \
		"test_get_updates: #4 got wrong number of updates in count"

	conn.disconnect()



if __name__ == '__main__':
	test_get_updates()
