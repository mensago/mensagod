
import array
import nacl.public
import nacl.secret
import nacl.utils
import os.path
import psycopg2
import secrets
import string
import sys
import toml
import uuid


# Function definitions


def jenc_encode(indata):
	escapes = [
		0,	# NULL
		8,	# Backspace
		9,	# Tab
		10, # Line feed
		12, # Form feed
		13, # Carriage return
		34, # Double quotes
		61, # =, the escape character
		92, # \, the JSON escape character
	]
	outdata = array.array('B')
	for i in range(0, len(indata)):
		c = (indata[i] + 42) & 255
		
		if c in escapes:
			outdata.extend([61, c + 64])
		else:
			outdata.append(c)
	return outdata.tobytes()


def generate_account():
	# The real server code pulls from multiple Unicode code points. This is here for simplicity's sake
	alphabet = string.ascii_letters + string.digits + string.punctuation

	first_names = [ "Leanne", "Lauryn", "Cheryl", "Addie", "Lynnette", "Meredith", "Jay", "Bernie",
					"Kenneth", "Harding", "Elissa", "Beth", "Vance", "Holden", "Careen", "Jackie",
					"Laurence", "Grover", "Megan", "Daniel", "Shelby", "Desmond", "Jason", "Patton",
					"Harvey", "Dylan", "Eleanor", "Grace", "Randall", "Carmen", "Lewis"
	]

	last_names = [ "Rennoll", "Layton", "Page", "Steffen", "Wilbur", "Clifford", "Ridge", "Norton",
					"Haden", "Smith", "Harris", "Bush", "Addison", "Warren", "Armstrong", "Radcliff",
					"Stern", "Jernigan", "Tucker", "Blackwood", "Gray", "Eaton", "Bissette", "Albert",
					"Rogers", "Tyrrell", "Randall", "Ramsey", "Parish", "Towner", "Granville"
	]

	rgen = secrets.SystemRandom()

	account = {}

	# Generate basic account data

	wid = str(uuid.uuid4())
	account['wid'] = wid
	if rgen.randint(1, 100) < 51:
		account['friendly_address'] = ''.join([rgen.choice(first_names), ' ', 
											rgen.choice(last_names), '/example.com'])
	else:
		account['friendly_address'] = ''
	
	account['password'] = ''.join(secrets.choice(alphabet) for i in range(20))

	# Generate user's encryption keys
	keypair = nacl.public.PrivateKey.generate()
	account['keys'] = [
		{	'type' : 'pki',
			'purpose' : 'identity',
			'public_key' : str(keypair.public_key),
			'private_key' : str(keypair)
		},
		{
			'type' : 'aes256',
			'purpose' : 'broadcast',
			'key' : nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
		},
		{
			'type' : 'aes256',
			'purpose' : 'system',
			'key' : nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
		},
		{
			'type' : 'aes256',
			'purpose' : 'folder',
			'key' : nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
		}
	]
	
	account['folder_map'] = {
		'Messages' : str(uuid.uuid4()),
		'Contacts' : str(uuid.uuid4()),
		'Calendar' : str(uuid.uuid4()),
		'Tasks' : str(uuid.uuid4()),
		'Files' : str(uuid.uuid4()),
		'Files Attachments' : str(uuid.uuid4()),
		'Social' : str(uuid.uuid4())
	}

	account['sessions'] = [ ''.join(secrets.choice(alphabet) for i in range(50)) ]

	return account

## Begin script execution

# Step 1: load the config

config_file_path = '/etc/anselus-server/serverconfig.toml'

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

# Step 2: Connect to the database

try:
	conn = psycopg2.connect(host=serverconfig['database']['ip'],
							port=serverconfig['database']['port'],
							database=serverconfig['database']['name'],
							user=serverconfig['database']['user'],
							password=serverconfig['database']['password'])
except Exception as e:
	print("Couldn't connect to database: %s" % e)
	sys.exit(1)

# Step 3: Generate accounts and add to database

print(generate_account())