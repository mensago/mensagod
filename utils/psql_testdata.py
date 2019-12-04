
import os.path
import psycopg2
import secrets
import string
import sys
import toml
import uuid

# Step 2: Set data for account generation
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
	
	char_list = []
	for i in range(0,20):
		char_list.append(rgen.choice(alphabet))
	account['password'] = ''.join(char_list)

	# TODO: Generate the account main key pair
	

	# Generate an AES256 key
	char_list.clear()
	for i in range(0,32):
		char_list.append(rgen.choice(alphabet))
	account['folderkey'] = ''.join(char_list)

	
	# TODO: Generate and add folder mappings

	# TODO: Generate and add session IDs


	return account



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