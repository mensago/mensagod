import os
import shutil
import time

from pymensago.serverconn import ServerConnection
from integration_setup import setup_test, init_server

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


def test_upload():
	'''Tests the UPLOAD command'''

	dbconn = setup_test()
	init_server(dbconn)

	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

	testpath = setup_testdir('test_upload')

	# Make a test file
	try:
		fhandle = open(os.path.join(testpath, 'uploadme.txt'), 'w')
	except Exception as e:
		assert False, f"test_upload: exception thrown creating temp file: {e}"
	
	fhandle.write('0' * 1000)
	fhandle.close()

	# Subtest #1:

if __name__ == '__main__':
	test_upload()
