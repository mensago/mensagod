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

def test_upload():
	'''Tests the UPLOAD command'''

	dbconn = setup_test()
	init_server(dbconn)

	conn = ServerConnection()
	assert conn.connect('localhost', 2001), "Connection to server at localhost:2001 failed"

if __name__ == '__main__':
	test_upload()
