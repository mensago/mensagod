import base64
import json
import os.path
import re
import socket
import sys
import time

import jsonschema
import nacl.secret
import psycopg2
import toml

from pyanselus.cryptostring import CryptoString
import pyanselus.keycard as keycard

# Keys used in the various tests. 
# THESE KEYS ARE STORED ON GITHUB! DO NOT USE THESE FOR ANYTHING EXCEPT UNIT TESTS!!

# Test Organization Information

# Name: Example.com
# Contact-Admin: ae406c5e-2673-4d3e-af20-91325d9623ca/acme.com
# Support and Abuse accounts are forwarded to Admin
# Language: en

# Initial Organization Primary Signing Key: {UNQmjYhz<(-ikOBYoEQpXPt<irxUF*nq25PoW=_
# Initial Organization Primary Verification Key: r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*
# Initial Organization Primary Verification Key Hash: 
# 	BLAKE2B-256:ag29av@TUvh-V5KaB2l}H=m?|w`}dvkS1S1&{cMo

# Initial Organization Encryption Key: SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az
# Initial Organization Encryption Key Hash: BLAKE2B-256:-Zz4O7J;m#-rB)2llQ*xTHjtblwm&kruUVa_v(&W
# Initial Organization Decryption Key: WSHgOhi+bg=<bO^4UoJGF-z9`+TBN{ds?7RZ;w3o

# Test User Information

# Name: Corbin Simons
# Workspace-ID: 4418bf6c-000b-4bb3-8111-316e72030468
# Domain: example.com

# Initial User Signing Key: p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+
# Initial User Verification Key: 6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p

# Initial User Contact Request Signing Key: ip52{ps^jH)t$k-9bc_RzkegpIW?}FFe~BX&<V}9
# Initial User Contact Request Verification Key: d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D

# Initial User Contact Request Encryption Key: j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph
# Initial User Contact Request Decryption Key: 55t6A0y%S?{7c47p(R@C*X#at9Y`q5(Rc#YBS;r}

# Initial User Primary Encryption Key: nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN
# Initial User Primary Decryption Key: 4A!nTPZSVD#tm78d=-?1OIQ43{ipSpE;@il{lYkg

def load_db_config(config_file_path: str) -> dict:
	'''Loads the Anselus server configuration from the config file'''
	
	if os.path.exists(config_file_path):
		try:
			serverconfig = toml.load(config_file_path)
		except Exception as e:
			print("Unable to load server config %s: %s" % (config_file_path, e))
			sys.exit(1)
	else:
		serverconfig = {}

	serverconfig.setdefault('database', dict())
	serverconfig['database'].setdefault('engine','postgresql')
	serverconfig['database'].setdefault('ip','127.0.0.1')
	serverconfig['database'].setdefault('port','5432')
	serverconfig['database'].setdefault('name','anselus')
	serverconfig['database'].setdefault('user','anselus')
	serverconfig['database'].setdefault('password','CHANGEME')

	serverconfig.setdefault('network', dict())
	serverconfig['network'].setdefault('listen_ip','127.0.0.1')
	serverconfig['network'].setdefault('port','2001')

	serverconfig.setdefault('global', dict())
	serverconfig['global'].setdefault('workspace_dir','/var/anselus')
	serverconfig['global'].setdefault('registration','private')
	serverconfig['global'].setdefault('default_quota',0)

	serverconfig.setdefault('security', dict())
	serverconfig['security'].setdefault('failure_delay_sec',3)
	serverconfig['security'].setdefault('max_failures',5)
	serverconfig['security'].setdefault('lockout_delay_min',15)
	serverconfig['security'].setdefault('registration_delay_min',15)

	if serverconfig['database']['engine'].lower() != 'postgresql':
		print("This script exepects a server config using PostgreSQL. Exiting")
		sys.exit()
	
	return serverconfig


def db_setup(serverconfig: dict, schema_path: str):
	'''Reset the test database to defaults'''
	try:
		conn = psycopg2.connect(host=serverconfig['database']['ip'],
								port=serverconfig['database']['port'],
								database="anselus",
								user=serverconfig['database']['user'],
								password=serverconfig['database']['password'])
	except Exception as e:
		print("Couldn't connect to database: %s" % e)
		sys.exit(1)

	sqlcmds = ''
	with open(schema_path, 'r') as f:
		sqlcmds = f.read()
	
	cur = conn.cursor()
	cur.execute(sqlcmds)
	cur.close()
	conn.commit()

	return conn


def setup_test():
	'''Resets the Postgres test database to be ready for an integration test'''
	config = load_db_config('/etc/anselusd/serverconfig.toml')

	schema_path = os.path.abspath(__file__ + '/../')
	schema_path = os.path.join(schema_path, 'psql_schema.sql')

	return db_setup(config, schema_path)


def config_server(dbconn) -> dict:
	'''Adds basic data to the database as if setupconfig had been run. Returns data needed for 
	tests, such as the keys'''
	
	# Start off by generating the org's root keycard entry and add to the database

	cur = dbconn.cursor()
	card = keycard.Keycard()
	
	root_entry = keycard.OrgEntry()
	root_entry.set_fields({
		'Name':'Acme Widgets, Inc.',
		'Contact-Admin':'c590b44c-798d-4055-8d72-725a7942f3f6/acme.com',
		'Language':'en',
		'Domain':'acme.com',
		'Primary-Verification-Key':'ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*',
		'Encryption-Key':'CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az'
	})

	initial_ovkey = CryptoString(r'ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*')
	initial_oskey = CryptoString(r'ED25519:{UNQmjYhz<(-ikOBYoEQpXPt<irxUF*nq25PoW=_')
	initial_ovhash = CryptoString(r'BLAKE2B-256:ag29av@TUvh-V5KaB2l}H=m?|w`}dvkS1S1&{cMo')

	initial_epubkey = CryptoString(r'CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az')
	initial_eprivkey = CryptoString(r'CURVE25519:WSHgOhi+bg=<bO^4UoJGF-z9`+TBN{ds?7RZ;w3o')
	initial_epubhash = CryptoString(r'BLAKE2B-256:-Zz4O7J;m#-rB)2llQ*xTHjtblwm&kruUVa_v(&W')
	
	# Organization sign, hash, and verify

	rv = root_entry.sign(initial_oskey, 'Organization')
	assert not rv.error(), 'Unexpected RetVal error %s' % rv.error()
	assert root_entry.signatures['Organization'], 'entry failed to user sign'

	rv = root_entry.generate_hash('BLAKE2B-256')
	assert not rv.error(), 'entry failed to hash'

	rv = root_entry.verify_signature(initial_ovkey, 'Organization')
	assert not rv.error(), 'org entry failed to verify'

	status = root_entry.is_compliant()
	assert not status.error(), f"OrgEntry wasn't compliant: {str(status)}"

	card.entries.append(root_entry)
	cur.execute("INSERT INTO keycards(owner,creationtime,index,entry,fingerprint) " \
		"VALUES('organization',%s,%s,%s,%s);",
		(root_entry.fields['Timestamp'],root_entry.fields['Index'],
			root_entry.make_bytestring(-1).decode(), root_entry.hash))

	cur.execute("INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose, fingerprint) "
				"VALUES(%s,%s,%s,'encrypt',%s);",
				(root_entry.fields['Timestamp'], initial_epubkey.as_string(),
				initial_eprivkey.as_string(), initial_epubhash.as_string()))

	cur.execute("INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose, fingerprint) "
				"VALUES(%s,%s,%s,'sign',%s);",
				(root_entry.fields['Timestamp'], initial_ovkey.as_string(),
				initial_oskey.as_string(), initial_ovhash.as_string()))

	# Sleep for 1 second in order for the new entry's timestamp to be useful
	time.sleep(1)

	# Chain a new entry to the root

	status = card.chain(initial_oskey, True)
	assert not status.error(), f'keycard chain failed: {status}'

	# Save the keys to a separate RetVal so we can keep using status for return codes
	keys = status
	
	new_entry = status['entry']
	new_entry.prev_hash = root_entry.hash
	new_entry.generate_hash('BLAKE2B-256')
	assert not status.error(), f'chained entry failed to hash: {status}'
	
	status = card.verify()
	assert not status.error(), f'keycard failed to verify: {status}'

	cur.execute("INSERT INTO keycards(owner,creationtime,index,entry,fingerprint) " \
		"VALUES('organization',%s,%s,%s,%s);",
		(new_entry.fields['Timestamp'],new_entry.fields['Index'],
			new_entry.make_bytestring(-1).decode(), new_entry.hash))

	cur.execute("INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose, fingerprint) "
				"VALUES(%s,%s,%s,'encrypt',%s);",
				(new_entry.fields['Timestamp'], keys['sign.public'],
				keys['sign.private'], keys['sign.pubhash']))

	cur.execute("INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose, fingerprint) "
				"VALUES(%s,%s,%s,'encrypt',%s);",
				(new_entry.fields['Timestamp'], keys['encrypt.public'],
				keys['encrypt.private'], keys['encrypt.pubhash']))
	
	if keys.has_value('altsign.public'):
		cur.execute("INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose, fingerprint) "
					"VALUES(%s,%s,%s,'encrypt',%s);",
					(new_entry.fields['Timestamp'], keys['altsign.public'],
					keys['altsign.private'], keys['altsign.pubhash']))


	# Prereg the admin account
	admin_wid = 'ae406c5e-2673-4d3e-af20-91325d9623ca'
	regcode = 'Undamaged Shining Amaretto Improve Scuttle Uptake'
	cur.execute(f"INSERT INTO prereg(wid, uid, regcode) VALUES('{admin_wid}', 'admin', '{regcode}');")

	cur.close()
	dbconn.commit()	

	return {
		'ovkey' : keys['sign.public'],
		'oskey' : keys['sign.private'],
		'oekey' : keys['encrypt.public'],
		'odkey' : keys['encrypt.private'],
		'admin_wid' : admin_wid,
		'admin_regcode' : regcode
	}


def add_workspace(account: dict, dbconn):
	'''Creates a workspace using the supplied information in the parameter `account`'''
	
	cursor = dbconn.cursor()
	cmdparts = ["INSERT INTO iwkspc_main(wid,friendly_address,password,status) VALUES('",
				account['wid'],
				"',"]
	if account['uid']:
		cmdparts.extend(["'",account['uid'],"',"])
	else:
		cmdparts.append("'',")
	
	cmdparts.extend(["'", account['serverpwhash'],"','", account['status'], "');"])
	cmd = ''.join(cmdparts)
	cursor.execute(cmd)
	
	box = nacl.secret.SecretBox(account['keys'][4]['key'])
	for folder_name,fid in account['folder_map'].items():
		cmd = ("INSERT INTO iwkspc_folders(wid, fid, enc_name, enc_key) "
					"VALUES('%s','%s','%s',$$%s$$);" % 
					( account['wid'], fid,
					base64.b85encode(box.encrypt(bytes(folder_name, 'utf8'))).decode('utf8'),
					account['keys'][4]['id']))
		cursor.execute(cmd)

	i = 0
	while i < len(account['devices']):
		cmd =	(	"INSERT INTO iwkspc_devices(wid, devid, keytype, devkey, status) "
					"VALUES('%s','%s','%s','%s','active');" % (
						account['wid'], account['devices'][i]['id'], 
						account['devices'][i]['keytype'],
						account['devices'][i]['public_b85']
					)
				)
		cursor.execute(cmd)
		i = i + 1
	
	cursor.close()
	dbconn.commit()


def validate_uuid(indata):
	'''Validates a UUID's basic format. Does not check version information.'''

	# With dashes, should be 36 characters or 32 without
	if (len(indata) != 36 and len(indata) != 32) or len(indata) == 0:
		return False
	
	uuid_pattern = re.compile(
			r"[\da-fA-F]{8}-?[\da-fA-F]{4}-?[\da-fA-F]{4}-?[\da-fA-F]{4}-?[\da-fA-F]{12}")
	
	if not uuid_pattern.match(indata):
		return False
	
	return True

class ServerNetworkConnection:
	'''Mini class to simplify network communications for integration tests'''
	def __init__(self):
		self.socket = None
	
	def connect(self) -> bool:
		'''Creates a connection to the server.'''
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			# Set a short timeout in case the server doesn't respond immediately,
			# which is the expectation as soon as a client connects.
			sock.settimeout(10.0)
		except:
			return None
		
		try:
			sock.connect(('127.0.0.1', 2001))
			
			# absorb the hello string
			_ = sock.recv(8192)

		except Exception as e:
			print("Connection failed: %s" % e)
			sock.close()
			return False

		# Set a timeout of 30 minutes
		sock.settimeout(1800.0)
		
		self.socket = sock
		return True

	def send_message(self, command : dict) -> bool:
		'''Sends a message to the server with command sent as JSON data'''
		cmdstr = json.dumps(command) + '\r\n'
		
		if not self.socket:
			return False
		
		try:
			self.socket.send(cmdstr.encode())
		except:
			self.socket.close()
			return False
		
		return True

	def read_response(self, schema: dict) -> dict:
		'''Reads a server response and returns a separated code and string'''
		
		if not self.socket:
			return None
		
		# We don't actually handle the possible exceptions because we *want* to have them crash --
		# the test will fail and give us the cause of the exception. If we have a successful test, 
		# exceptions weren't thrown
		rawdata = self.socket.recv(8192)
		rawstring = rawdata.decode()
		response = json.loads(rawstring)
		jsonschema.validate(response, schema)

		return response
	
	def read(self) -> str:
		'''Reads a string from the network connection'''
		
		if not self.socket:
			return None
		
		rawdata = self.socket.recv(8192)
		return rawdata.decode()
