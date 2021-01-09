from integration_setup import setup_test, config_server, validate_uuid, \
	ServerNetworkConnection

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
	config_server(dbconn)

	uid = 'TestUserID'
	wid = '11111111-1111-1111-1111-111111111111'
	domain = 'acme.com'

	sock = ServerNetworkConnection()
	assert sock.connect(), "Connection to server at localhost:2001 failed"

	
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


	# Subtest #2: Plain prereg
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


	# Subtest #3: duplicate user ID
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


	# Subtest #4: WID as user ID
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


	# Subtest #5: Specify WID
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


	# Subtest #6: Specify User ID only.
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
