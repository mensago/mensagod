from pyanselus.cryptostring import CryptoString
from pyanselus.encryption import EncryptionPair
import pyanselus.keycard as keycard
from integration_setup import setup_test, config_server, ServerNetworkConnection, regcode_admin, \
	login_admin

# Keys used in the various tests. 
# THESE KEYS ARE STORED ON GITHUB! DO NOT USE THESE FOR ANYTHING EXCEPT UNIT TESTS!!

# User Signing Key: p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+
# User Verification Key: 6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p

# User Contact Request Signing Key: ip52{ps^jH)t$k-9bc_RzkegpIW?}FFe~BX&<V}9
# User Contact Request Verification Key: d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D

# User Contact Request Encryption Key: j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph
# User Contact Request Decryption Key: 55t6A0y%S?{7c47p(R@C*X#at9Y`q5(Rc#YBS;r}

# User Primary Encryption Key: nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN
# User Primary Decryption Key: 4A!nTPZSVD#tm78d=-?1OIQ43{ipSpE;@il{lYkg

# Organization Primary Signing Key: msvXw(nII<Qm6oBHc+92xwRI3>VFF-RcZ=7DEu3|
# Organization Primary Verification Key: )8id(gE02^S<{3H>9B;X4{DuYcb`%wo^mC&1lN88

# Organization Encryption Key: @b?cjpeY;<&y+LSOA&yUQ&ZIrp(JGt{W$*V>ATLG
# Organization Decryption Key: nQxAR1Rh{F4gKR<KZz)*)7}5s_^!`!eb!sod0<aT


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

def test_orgcard():
	'''Tests the server's ORGCARD command'''
	dbconn = setup_test()
	config_data = config_server(dbconn)

	sock = ServerNetworkConnection()
	assert sock.connect(), "Connection to server at localhost:2001 failed"
	
	sock.send_message({
		'Action' : "ORGCARD",
		'Data' : { 'Start-Index' : '1' }
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 104 and response['Status'] == 'TRANSFER' and \
		response['Data']['Item-Count'] == '2', 'test_orgcard: server returned wrong number of items'
	data_size = int(response['Data']['Total-Size'])
	sock.send_message({'Action':'TRANSFER'})

	chunks = list()
	tempstr = sock.read()
	data_read = len(tempstr)
	chunks.append(tempstr)
	while data_read < data_size:
		tempstr = sock.read()
		data_read = data_read + len(tempstr)
		chunks.append(tempstr)
	
	assert data_read == data_size, 'test_orgcard: size mismatch'
	
	# Now that the data has been downloaded, we put it together and split it properly. We should
	# have two entries
	entries = ''.join(chunks).split('----- END ORG ENTRY -----\r\n')
	if entries[-1] == '':
		entries.pop()
	
	# These entries are added to the database in config_server(). The insert operations are not
	# done here because the two org entries are needed for other tests, as well.
	assert len(entries) == 2, "test_orgcard: server did not send 2 entries"
	assert entries[0] == '----- BEGIN ORG ENTRY -----\r\n' + \
		config_data['root_org_entry'].make_bytestring(-1).decode(), \
		"test_orgcard: first entry didn't match"
	assert entries[1] == '----- BEGIN ORG ENTRY -----\r\n' + \
		config_data['second_org_entry'].make_bytestring(-1).decode(), \
		"test_orgcard: second entry didn't match"

	sock.send_message({'Action' : "QUIT"})


def test_addentry_usercard():
	'''Tests the ADDENTRY and USERCARD command processes'''
	dbconn = setup_test()
	config_data = config_server(dbconn)

	sock = ServerNetworkConnection()
	assert sock.connect(), "Connection to server at localhost:2001 failed"
	
	# password is 'SandstoneAgendaTricycle'
	pwhash = '$argon2id$v=19$m=65536,t=2,p=1$ew5lqHA5z38za+257DmnTA$0LWVrI2r7XCq' \
				'dcCYkJLok65qussSyhN5TTZP+OTgzEI'
	devid = '22222222-2222-2222-2222-222222222222'
	devpair = EncryptionPair(CryptoString(r'CURVE25519:@X~msiMmBq0nsNnn0%~x{M|NU_{?<Wj)cYybdh&Z'),
		CryptoString(r'CURVE25519:W30{oJ?w~NBbj{F8Ag4~<bcWy6_uQ{i{X?NDq4^l'))
	
	config_data['pwhash'] = pwhash
	config_data['devid'] = devid
	config_data['devpair'] = devpair
	
	regcode_admin(config_data, sock)
	login_admin(config_data, sock)

	# Test setup is complete. Create a test keycard and do ADDENTRY

	# 1) Client sends the `ADDENTRY` command, attaching the entry data between the
	#    `----- BEGIN USER KEYCARD -----` header and the `----- END USER KEYCARD -----` footer.
	# 2) The server then checks compliance of the entry data. Assuming that it complies, the server
	#    generates a cryptographic signature and responds with `100 CONTINUE`, returning the
	#    signature, the hash of the data, and the hash of the previous entry in the database.
	# 3) The client verifies the signature against the organization’s verification key. This has
	#    the added benefit of ensuring that none of the fields were altered by the server and that
	#    the signature is valid.
	# 4) The client appends the hash from the previous entry as the `Previous-Hash` field
	# 5) The client verifies the hash value for the entry from the server and sets the `Hash` field
	# 6) The client signs the entry as the `User-Signature` field and then uploads the result to
	#    the server.
	# 7) Once uploaded, the server validates the `Hash` and `User-Signature` fields, and,
	#    assuming that all is well, adds it to the keycard database and returns `200 OK`.
	#
	# Once that monster of a process completes, the card should be successfully added, but we're not
	# done yet. From there, create a new user entry, chain it to the first, and upload it. This will
	# test the chaining code in the AddEntry command processing.
	#
	# Finally, once that entire mess is complete, send a USERCARD command and verify what is 
	# returned against the data set up so far. It doesn't seem like piggybacking a test for a
	# different command off another is the right thing to do, but in this case, it's the perfect
	# setup to confirm that a user's entire keycard is handled properly.

	usercard = keycard.UserEntry()
	usercard.set_fields({
		'Name':'Test Administrator',
		'Workspace-ID':config_data['admin_wid'],
		'User-ID':'admin',
		'Domain':'example.com',
		'Contact-Request-Verification-Key':'ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D',
		'Contact-Request-Encryption-Key':'CURVE25519:yBZ0{1fE9{2<b~#i^R+JT-yh-y5M(Wyw_)}_SZOn',
		'Public-Encryption-Key':'CURVE25519:_`UC|vltn_%P5}~vwV^)oY){#uvQSSy(dOD_l(yE'
	})

	sock.send_message({
		'Action' : "ADDENTRY",
		'Data' : { 'Base-Entry' : usercard.make_bytestring(0).decode() }
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 100 and \
		response['Status'] == 'CONTINUE' and \
		'Organization-Signature' in response['Data'] and \
		'Hash' in response['Data'] and \
		'Previous-Hash' in response['Data'], 'test_addentry(): server did return all needed fields'

	usercard.signatures['Organization'] =  response['Data']['Organization-Signature']

	# A regular client will check the entry cache, pull updates to the org card, and get the 
	# verification key. Because this is just an integration test, we skip all that and just use
	# the known verification key from earlier in the test.
	status = usercard.verify_signature(
		CryptoString(config_data['ovkey']), 'Organization')
	assert not status.error(), f"test_addentry(): org signature didn't verify: {status.info()}"
	
	assert response['Data']['Previous-Hash'] == config_data['second_org_entry'].hash, \
		"test_addentry(): server did not attach correct Previous Hash to root user entry"
	
	usercard.prev_hash = response['Data']['Previous-Hash']
	usercard.hash = response['Data']['Hash']
	status = usercard.verify_hash()
	assert not status.error(), f"test_addentry(): hash didn't verify: {status.info()}"

	# User sign and verify
	skey = CryptoString('ED25519:ip52{ps^jH)t$k-9bc_RzkegpIW?}FFe~BX&<V}9')
	assert skey.is_valid(), "test_addentry(): failed to set user's cr signing key"
	status = usercard.sign(skey, 'User')
	assert not status.error(), "test_addentry(): failed to user sign"

	vkey = CryptoString('ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D')
	assert vkey.is_valid(), "test_addentry(): failed to set user's cr verification key"
	status = usercard.verify_signature(vkey, 'User')

	status = usercard.is_compliant()
	assert not status.error(), f"test_addentry(): compliance error: {str(status)}"

	sock.send_message({
		'Action' : "ADDENTRY",
		'Data' : { 'User-Signature' : usercard.signatures['User'] }
	})
	
	response = sock.read_response(server_response)
	assert response['Code'] == 200 and \
		response['Status'] == 'OK', f"test_addentry(): final upload server error {response}"


	# Now to test ADDENTRY with a chained entry. Hold on tight!

	# Submit the chained entry
	newkeys = usercard.chain(skey, True)
	assert not newkeys.error(), f"test_addentry(): new entry failed to chain: {newkeys.info()}"

	second_user_entry = newkeys['entry']
	sock.send_message({
		'Action' : "ADDENTRY",
		'Data' : { 'Base-Entry' : second_user_entry.make_bytestring(1).decode() }
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 100 and \
		response['Status'] == 'CONTINUE' and \
		'Organization-Signature' in response['Data'] and \
		'Hash' in response['Data'] and \
		'Previous-Hash' in response['Data'], 'test_addentry(): server did return all needed fields'

	second_user_entry.signatures['Organization'] =  response['Data']['Organization-Signature']
	
	# Verify the server's signature, add and verify the hashes, sign, and upload
	status = second_user_entry.verify_signature(
		CryptoString(config_data['ovkey']), 'Organization')
	assert not status.error(), f"test_addentry(): org signature didn't verify: {status.info()}"
	
	second_user_entry.prev_hash = response['Data']['Previous-Hash']
	assert response['Data']['Previous-Hash'] == usercard.hash, \
		"Server did not return correct chained user entry hash"
	second_user_entry.hash = response['Data']['Hash']
	status = second_user_entry.verify_hash()
	assert not status.error(), f"test_addentry(): hash didn't verify: {status.info()}"

	skey = CryptoString(newkeys['crsign.private'])
	assert skey.is_valid(), "test_addentry(): failed to set user signing key"
	status = second_user_entry.sign(skey, 'User')
	assert not status.error(), "test_addentry(): failed to user sign"

	vkey = CryptoString(newkeys['crsign.public'])
	assert vkey.is_valid(), "test_addentry(): failed to set user verification key"
	status = second_user_entry.verify_signature(vkey, 'User')

	status = second_user_entry.is_compliant()
	assert not status.error(), f"test_addentry(): compliance error: {str(status)}"

	sock.send_message({
		'Action' : "ADDENTRY",
		'Data' : { 'User-Signature' : second_user_entry.signatures['User'] }
	})
	
	response = sock.read_response(server_response)
	assert response['Code'] == 200 and \
		response['Status'] == 'OK', f"test_addentry(): final upload server error {response}"
	
	sock.send_message({
		'Action' : "USERCARD",
		'Data' : { 
			'Owner' : 'admin/example.com',
			'Start-Index' : '1'
		}
	})

	response = sock.read_response(server_response)
	assert response['Code'] == 104 and response['Status'] == 'TRANSFER', \
		'test_addentry.usercard: server returned %s' % response['Status']
	assert response['Data']['Item-Count'] == '2', \
		'test_addentry.usercard: server returned wrong number of items'
	data_size = int(response['Data']['Total-Size'])
	sock.send_message({'Action':'TRANSFER'})

	chunks = list()
	tempstr = sock.read()
	data_read = len(tempstr)
	chunks.append(tempstr)
	while data_read < data_size:
		tempstr = sock.read()
		data_read = data_read + len(tempstr)
		chunks.append(tempstr)
	
	assert data_read == data_size, 'test_orgcard.usercard: size mismatch'
	
	# Now that the data has been downloaded, we put it together and split it properly. We should
	# have two entries
	entries = ''.join(chunks).split('----- END USER ENTRY -----\r\n')
	if entries[-1] == '':
		entries.pop()
	
	# These entries are added to the database in config_server(). The insert operations are not
	# done here because the two org entries are needed for other tests, as well.
	assert len(entries) == 2, "test_orgcard.usercard: server did not send the expected entry"
	assert entries[1] == '----- BEGIN USER ENTRY -----\r\n' + \
		second_user_entry.make_bytestring(-1).decode(), \
		"test_orgcard.usercard: entry didn't match"

	sock.send_message({'Action' : "QUIT"})


if __name__ == '__main__':
	#test_orgcard()
	test_addentry_usercard()
