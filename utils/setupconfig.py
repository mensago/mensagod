#!/usr/bin/env python3

# setupconfig - a script perform post-installation server configuration

# Released under the terms of the MIT license
# ©2019-2020 Jon Yoder <jsyoder@mailfence.com>

import argparse
import base64
import hashlib
import os
import platform
import subprocess
import sys
import time
import uuid

import diceware
import nacl.public
import nacl.signing
import psycopg2


def make_diceware():
	'''Generates a diceware password'''
	options = argparse.Namespace()
	options.num = 3
	options.caps = True
	options.specials = 0
	options.delimiter = ''
	options.randomsource = 'system'
	options.wordlist = 'en_eff'
	options.infile = None
	return diceware.get_passphrase(options)

# Steps to perform:
#
# Check prerequisites
# 	- root privileges

# Get necessary information from the user
#	- location of workspace data
#	- registration type
#	- is separate abuse account desired?
#	- is separate support account desired?
#	- quota size
#	- IP address of postgres server
#	- port of postgres server
#	- database name
#	- database username
#	- database user password

# Set up the database tables
# 	- Create and save the org's keys
# 	- Preregister the admin account
# 	- Create the org's root keycard

# Save the config file


# Step 1: Check prerequisites

print("This script generates the necessary baseline configuration for a new anselusd server. "
	"It will generate a new vanilla server config file. Depending on your environment, you may "
	"need to perform additional editing of the file once it is generated.\n\n"
	"Any existing server config file will be renamed to a backup.\n")

server_platform = "posix"
if platform.system() == "Windows":
	server_platform = "windows"

# Prerequisite: check for admin privileges
if server_platform == "windows":
	result = subprocess.run(["powershell","-Command",
		"(New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::"
		"GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)"],
		check=False, capture_output=True)
	is_admin = result.stdout.decode().strip().lower()
	if is_admin == 'false':
		print("This script requires administrator privileges.")
		sys.exit(0)
else:
	# TODO: handle os.geteuid()
	pass


# Step 2: Get necessary information from the user
#	- location of workspace data
#	- registration type
#	- is separate abuse account desired?
#	- is separate support account desired?
#	- quota size
#	- IP address of postgres server
#	- port of postgres server
#	- database name
#	- database username
#	- database user password

config = dict()
default_workspace_path = '/var/anselus'
if server_platform == 'windows':
	default_workspace_path = os.environ['PROGRAMDATA'] + '\\anselus'


# location of workspace data
tempstr = input(f'Enter the location for the workspace data [{default_workspace_path}]: ')
if tempstr == '':
	tempstr = default_workspace_path

if not os.path.exists(tempstr):
	choice = input(f"{tempstr} doesn't exist. Create it? [Y/n]: ")
	choice = choice.lower()
	if choice == 'yes' or choice == 'y' or choice == '':
		try:
			os.mkdir(tempstr, 0o755)
			print(f"Created folder f{tempstr}")
		except Exception as e:
			print(f"Error creating folder {tempstr}: {e}")
			choice = input("Do you want to continue? [Y/n]: ")
			choice = choice.lower()
			if choice == 'yes' or choice == 'y':
				sys.exit(0)

config['workspace_path'] = tempstr

# registration type

print('''Registration types:
  - private (default): administrator must create all accounts manually
  - public: anyone with access can create a new account. Not recommended.
  - network: anyone on a subnet may create a new account. By default this is
        set to the local network (192.168/16, 172.16/12, 10/8)
  - moderated: anyone ask for an account, but admin must approve

''')

config['regtype'] = ''
while config['regtype'] == '':
	choice = input(f"Registration mode [private]: ")
	if choice == '':
		choice = 'private'
	else:
		choice = choice.lower()

	if choice in ['private','public','network','moderated']:
		config['regtype'] = choice
		break

config['separate_abuse'] = ''
print('The built-in abuse account can be a separate workspace or just autoforwarded to admin. '
	'Small environments will probably want to say "no" here.')
while config['separate_abuse'] == '':
	choice = input(f"Do you want to use a separate abuse account? [y/N]: ")
	choice = choice.lower()
	if choice in ['yes', 'y']:
		config['separate_abuse'] = 'y'
	elif choice in ['n', 'no', '']:
		config['separate_abuse'] = 'n'

config['separate_support'] = ''
print('The built-in support account can be a separate workspace or just autoforwarded to admin. '
	'Small environments will probably want to say "no" here.')
while config['separate_support'] == '':
	choice = input(f"Do you want to use a separate support account? [y/N]: ")
	choice = choice.lower()
	if choice in ['yes', 'y']:
		config['separate_support'] = 'y'
	elif choice in ['n', 'no', '']:
		config['separate_support'] = 'n'

config['quota_size'] = ''
print('Disk quotas, if set, set each user at a default value that can be changed later.')
while config['quota_size'] == '':
	choice = input(f"Size, in MiB, of default user disk quota (0 = No quota): ")
	try:
		tempint = int(choice)
		config['quota_size'] = choice
	except:
		continue

# location of server config

config['config_path'] = '/etc/anselusd'
if server_platform == 'windows':
	config['config_path'] = os.environ['PROGRAMDATA'] + '\\anselusd'


# IP address of postgres server
tempstr = input('Enter the IP address of the database server. [localhost]: ')
if tempstr == '':
	tempstr = 'localhost'
config['server_ip'] = tempstr

# port of postgres server
tempstr = input('Enter the database server port. [5432]: ')
if tempstr == '':
	tempstr = '5432'
config['server_port'] = tempstr

# database username
tempstr = input('Enter the name of the database to store data. [anselus]: ')
if tempstr == '':
	tempstr = 'anselus'
config['db_name'] = tempstr

tempstr = input('Enter a username which has admin privileges on this database. [anselus]: ')
if tempstr == '':
	tempstr = 'anselus'
config['db_user'] = tempstr

# database user password
config['db_password'] = input('Enter the password of this user: ')

print(config)

# connectivity check
try:
	conn = psycopg2.connect(host=config['server_ip'],
							port=config['server_port'],
							database='anselus',
							user=config['db_user'],
							password=config['db_password'])
except Exception as e:
	print("Couldn't connect to database: %s" % e)
	print("Unable to continue until connectivity problems are resolved. Sorry!")
	sys.exit(1)

# Step 3: set up the database tables

# TODO: detect if tables already exist.
# If they do, ask the user if they want to reset the database and continue

cur = conn.cursor()
cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'iwkspc_main' AND "
			"c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE iwkspc_main(rowid SERIAL PRIMARY KEY, wid char(36) NOT NULL, "
				"uid VARCHAR(32), domain VARCHAR(253) NOT NULL, password VARCHAR(128) NOT NULL, "
				"status VARCHAR(16) NOT NULL, type VARCHAR(16) NOT NULL);")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'iwkspc_folders' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE iwkspc_folders(rowid SERIAL PRIMARY KEY, wid char(36) NOT NULL, "
				"enc_name VARCHAR(128) NOT NULL, enc_key VARCHAR(64) NOT NULL);")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'iwkspc_devices' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE iwkspc_devices(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL, "
				"devid CHAR(36) NOT NULL, keytype VARCHAR(16) NOT NULL, "
				"devkey VARCHAR(1000) NOT NULL, status VARCHAR(16) NOT NULL);")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'failure_log' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE failure_log(rowid SERIAL PRIMARY KEY, type VARCHAR(16) NOT NULL, "
				"id VARCHAR(36), source VARCHAR(36) NOT NULL, count INTEGER, "
				"last_failure TIMESTAMP NOT NULL, lockout_until TIMESTAMP);")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'prereg' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE prereg(rowid SERIAL PRIMARY KEY, wid VARCHAR(36) NOT NULL UNIQUE, "
				"uid VARCHAR(128) NOT NULL, regcode VARCHAR(128));")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'keycards' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE keycards(rowid SERIAL PRIMARY KEY, owner VARCHAR(64) NOT NULL, "
				"creationtime TIMESTAMP NOT NULL, index INTEGER NOT NULL, "
				"entry VARCHAR(8192) NOT NULL, fingerprint VARCHAR(800) NOT NULL);")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'orgkeys' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE orgkeys(rowid SERIAL PRIMARY KEY, creationtime TIMESTAMP NOT NULL, "
				"pubkey VARCHAR(7000), privkey VARCHAR(7000) NOT NULL, "
				"purpose VARCHAR(8) NOT NULL, fingerprint VARCHAR(800) NOT NULL);")


# create the org's keys and put them in the table

ekey = dict()
hasher = hashlib.blake2b(digest_size=32)
key = nacl.public.PrivateKey.generate()
ekey['public'] = "CURVE25519:" + base64.b85encode(key.public_key.encode())
ekey['private'] = "CURVE25519:" + base64.b85encode(key.encode())
hasher.update(base64.b85encode(key.public_key.encode()))
ekey['fingerprint'] = "BLAKE2B-256:" + base64.b85encode(hasher.digest())
ekey['timestamp'] = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())


pskey = dict()
hasher = hashlib.blake2b(digest_size=32)
key = nacl.signing.SigningKey.generate()
pskey['verify'] = "CURVE25519:" + base64.b85encode(key.verify_key.encode())
pskey['sign'] = "CURVE25519:" + base64.b85encode(key.encode())
hasher.update(base64.b85encode(key.verify_key.encode()))
pskey['fingerprint'] = "BLAKE2B-256:" + base64.b85encode(hasher.digest())
pskey['timestamp'] = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())

# Using Python's string substitution to compose SQL commands is normally really, really 
# dangerous because it enables SQL injection attacks. We're using only our own data generated in 
# this script, so it's not so terrible

cur.execute(f"INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose) "
			f"VALUES('{ekey['timestamp']}', '{ekey['public']}', '{ekey['private']}', 'encrypt', "
			f"'{ekey['fingerprint']}');")

cur.execute(f"INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose) "
			f"VALUES('{pskey['timestamp']}', '{pskey['public']}', '{pskey['private']}', 'sign', "
			f"'{pskey['fingerprint']}');")


# preregister the admin account and put into the serverconfig

admin_wid = str(uuid.uuid4())
regcode = make_diceware()
cur.execute(f"INSERT INTO prereg(wid, uid, regcode) VALUES('{admin_wid}', 'admin', '{regcode}');")

config['admin_wid'] = admin_wid
config['admin_regcode'] = regcode

# preregister the abuse account if not aliased and put into the serverconfig

if config['separate_abuse'] = 'y':
	abuse_wid = str(uuid.uuid4())
	abuse_regcode = make_diceware()
	cur.execute(f"INSERT INTO prereg(wid, uid, regcode) "
		f"VALUES('{abuse_wid}', 'abuse', '{abuse_regcode}');")

	config['abuse_wid'] = abuse_wid
	config['abuse_regcode'] = abuse_regcode

# preregister the support account if not aliased and put into the serverconfig

if config['separate_support'] = 'y':
	support_wid = str(uuid.uuid4())
	support_regcode = make_diceware()
	cur.execute(f"INSERT INTO prereg(wid, uid, regcode) "
		f"VALUES('{support_wid}', 'support', '{support_regcode}');")

	config['support_wid'] = support_wid
	config['support_regcode'] = support_regcode

# TODO: create and add the org's root keycard

cur.close()
conn.commit()

# create the server config folder

try:
	os.mkdir(config['config_path'], 0o755)
	print(f"Created server config folder f{config['config_path']}")
except Exception as e:
	print(f"Error creating folder {config['config_path']}: {e}")
	print("You will need to create this folder manually, reset the database, "
		"and restart this script.")
	sys.exit(-1)

# Step 4: save the config file

config_file_path = os.path.join(config['config_path'], 'serverconfig.toml')
if os.path.exists(config_file_path):
	backup_name = 'serverconfig.toml.' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
	print(f"Config file f{config_file_path} exists. Renaming to f{backup_name}.")
	try:
		os.rename(config_file_path, os.path.join(config['config_path'], backup_name))
	except Exception as e:
		print(f"Error backing up server config file: {e}")
		print("You will need to find out why and restart this script.")
		sys.exit(-1)

try:
	fhandle = open(config_file_path, 'w')
except Exception as e:
	print(f"Error creating server config file: {e}")
	print("You will need to find out why and restart this script.")
	sys.exit(-1)

fhandle.write('''
# This is an Anselus server config file. Each value listed below is the 
# default value. Every effort has been made to set this file to sensible 
# defaults so that configuration is kept to a minimum. This file is expected
# to be found in /etc/anselusd/serverconfig.toml or C:\\ProgramData\\anselusd
# on Windows.

[database]
# The database section should generally be the only real editing for this 
# file.
#
# ip = "localhost"
# port = "5432"
# name = "anselus"
# user = "anselus"
''')
if config['server_ip'] != 'localhost':
	fhandle.write('ip = "' + config['server_ip'] + '"' + os.linesep)

if config['server_port'] != '5432':
	fhandle.write('port = "' + config['server_port'] + '"' + os.linesep)

if config['db_name'] != 'anselus':
	fhandle.write('name = "' + config['db_name'] + '"' + os.linesep)

if config['db_password'] != 'anselus':
	fhandle.write('user = "' + config['db_user'] + '"' + os.linesep)

fhandle.write('''
[network]
# The interface and port to listen on
# listen_ip = "127.0.0.1"
# port = "2001"

[global]
# The location where workspace data is stored. On Windows, the default is 
# C:\\ProgramData\\anselus, but for other platforms is "/var/anselus".
# workspace_dir = "/var/anselus"
''')

if config['workspace_path'] != default_workspace_path:
	fhandle.write('workspace_dir = "' + config['workspace_path'] + '"' + os.linesep)

fhandle.write('''
# The type of registration. 'public' is open to outside registration requests,
# and would be appropriate only for hosting a public free server. 'moderated'
# is open to public registration, but an administrator must approve the request
# before an account can be created. 'network' limits registration to a 
# specified subnet or IP address. 'private' permits account registration only
# by an administrator. For most workflows 'private' is the appropriate setting.
# registration = "private"
''')

if config['regtype'] != 'private':
	fhandle.write('registration = "' + config['regtype'] + '"' + os.linesep)

fhandle.write('''
# For servers configured to network registration, this variable sets the 
# subnet(s) to which account registration is limited. Subnets are expected in
# CIDR notation and comma-separated. The default setting restricts registration
# to the private (non-routable) networks.
# registration_subnet = 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8
# registration_subnet6 = fe80::/10
# 
# The default storage quota for a workspace, measured in MiB. 0 means no limit.
# default_quota = 0

[security]
# The number of seconds to wait after a login failure before accepting another
# attempt
# failure_delay_sec = 3
# 
# The number of login failures made before a connection is closed. 
# max_failures = 5
# 
# The number of minutes the client must wait after reaching max_failures before
# another attempt may be made. Note that additional attempts to login prior to
# the completion of this delay resets the timeout.
# lockout_delay_min = 15
# 
# The delay, in minutes, between account registration requests from the same IP
# address. This is to prevent registration spam
# registration_delay_min = 15
# 
# Device checking enables an extra layer of security, checking the identity of
# a device for a workspace by exchanging a random key which is updated every
# time that device logs in.
# device_checking = on
# 
# Adjust the password security strength. Argon2id is used for the hash
# generation algorithm. This setting may be `normal` or `enhanced`. Normal is
# best for most situations, but for environments which require extra security,
# `enhanced` provides additional protection at the cost of higher server
# demands.
# password_security = normal
''')

fhandle.close()

print('''Basic setup is complete.

From here, please make sure you

1) Make sure port 2001 is open on the firewall
2) Start the anselusd service
3) Finish registration of the admin account on a device that is NOT this 
   server
4) If you are using separate abuse or support accounts, also complete 
   registration for those accounts
''')
