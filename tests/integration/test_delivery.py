import json

import psycopg2
from pycryptostring import CryptoString
from pymensago.encryption import EncryptionPair, SecretKey
from pymensago.hash import blake2hash
from pymensago.serverconn import ServerConnection

# There were so many individual imports from integration_setup that it actually makes sense to
# wildcard this import. *shrug*
from integration_setup import *

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
			# Domain and Message parameters are missing
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 400, 'test_send: #1 failed to handle missing parameter'


	# Subtest #2: real successful message delivery

	
	# Construct the contact request
	
	conreq = {
		'Version': '1.0',
		'ID': '539ed177-d0f3-446e-8d23-dcdcf55dd839',
		'Date': "20190905T155323Z",
		# Sender added below
		# Receiver added below
		# KeyHash added below
		# PayloadKey added below
	}
	payload = {
		'Version': '1.0',
		'Type': 'sysmessage',
		'Subtype': 'contactreq.1',
		'From': admin_profile_data['waddress'].as_string(),
		'To': user1_profile_data['waddress'].as_string(),
		'Date': "20190905T155323Z",
		'Message': "Here's my info in case you need help with anything",
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

	# Encrypt and attach sender and recipient headers

	rawdata = '{"To":"%s","SenderDomain":"%s"}' % (user1_profile_data['waddress'].as_string(),
													admin_profile_data['domain'].as_string())
	status = dbdata['oepair'].encrypt(rawdata.encode())
	assert not status.error(), f"{funcname()}: Failed to encrypt recipient header"

	# encrypt() returns the prefix and data separately because the data has the potential to be
	# huge and could be stored separate from the prefix. The sender and receiver headers, though,
	# can't be very large and will be just fine as standard CryptoStrings.
	conreq['Receiver'] = status['prefix'] + ':' + status['data']

	
	rawdata = '{"From":"%s","RecipientDomain":"%s"}' % (admin_profile_data['waddress'].as_string(),
													user1_profile_data['domain'].as_string())
	status = dbdata['oepair'].encrypt(rawdata.encode())
	assert not status.error(), f"{funcname()}: Failed to encrypt sender header"
	conreq['Sender'] = status['prefix'] + ':' + status['data']

	# Encrypt the payload and construct the full message text
	
	msgkey = SecretKey()
	conreq['KeyHash'] = blake2hash(msgkey.as_string().encode())
	status = user1_profile_data['crencryption'].encrypt(msgkey.as_string().encode())
	assert not status.error(), f"{funcname()}: Failed to encrypt message key: {status.info()}"
	conreq['PayloadKey'] = status['prefix'] + ':' + status['data']
	
	msgdata = [
		'-----',
		'MENSAGO',
		json.dumps(conreq),
		'----------',
		'XSALSA20',
		msgkey.encrypt(json.dumps(payload).encode()),
		'-----'
	]

	conn.send_message({
		'Action': 'SENDFAST',
		'Data': {
			'Domain': user1_profile_data['domain'].as_string(),
			'Message': '\r\n'.join(msgdata)
		}
	})

	response = conn.read_response(server_response)
	assert response['Code'] == 200, 'test_sendfast: failed to send valid message'

	# Confirm update record in recipient account

	cur = dbconn.cursor()

	# There appears to be a race condition somewhere in the backend. Waiting just 100ms seems to
	# be just enough of a wait for this to pass. Without it, the fetchmany() call gets no results.
	time.sleep(.1)

	cur.execute("SELECT update_data FROM updates WHERE wid=%s LIMIT 1",
				(user1_profile_data['wid'].as_string(),))
	row = cur.fetchone()
	assert row is not None and len(row) == 1, f"{funcname()}: update record missing from database"
	cur.close()
	
	# Convert the Mensago path to a regular one
	parts = row[0].split(' ')
	
	# Using [1:] strips out the initial /, which we want
	temppath = os.sep.join(parts[1:])
	filepath = dbdata['configfile']['global']['workspace_dir']

	assert os.path.exists(filepath), f"{funcname()}: client file for message missing"

	# Subtest #3: Non-existent domain

	# TODO: POSTDEMO: Implement SENDFAST subtest for non-existent domain




if __name__ == '__main__':
	# test_send()
	test_sendfast()
