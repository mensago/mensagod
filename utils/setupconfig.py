#!/usr/bin/env python3

# setupconfig - a script perform post-installation server configuration

# Released under the terms of the MIT license
# ©2019-2020 Jon Yoder <jsyoder@mailfence.com>

import argparse
import base64
import hashlib
import os
import platform
import re
import subprocess
import sys
import time
import uuid

import diceware
import nacl.public
import nacl.signing
import psycopg2
from termcolor import colored

import pyanselus.keycard as keycard
from pyanselus.cryptostring import CryptoString	

def make_diceware():
	'''Generates a diceware password'''
	options = argparse.Namespace()
	options.num = 4
	options.caps = True
	options.specials = 0
	options.delimiter = '-'
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

# print("This script generates the necessary baseline configuration for a new anselusd server. "
# 	"It will generate a new vanilla server config file. Depending on the requirements of your "
# 	"environment, you may need to perform additional editing of the file once it is generated.\n\n"
# 	"Any existing server config file will be renamed to a backup.\n")

print("""This script generates the first-time setup for a new anselusd 
server. Depending on the requirements of your environment, you may need to edit
the config file afterward.

The database will be emptied and reset, but any existing config file will be
backed up.
""")

server_platform = "posix"
if platform.system() == "Windows":
	server_platform = "windows"

if server_platform != 'windows':
	import pwd # pylint: disable=import-error
	import grp # pylint: disable=import-error


# Prerequisite: check for admin privileges
if server_platform == "windows":
	result = subprocess.run(["powershell","-Command",
		"(New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::"
		"GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)"],
		check=False, capture_output=True)
	is_admin = result.stdout.decode().strip().lower()
	if is_admin == 'false':
		print(colored("This script requires administrator privileges.",'yellow'))
		sys.exit(0)
else:
	if os.geteuid() != 0:	# pylint: disable=no-member
		print(colored("This script requires root privileges.", 'yellow'))
		sys.exit(0)

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
#	- required keycard fields

config = dict()
default_workspace_path = '/var/anselus'
if server_platform == 'windows':
	default_workspace_path = os.environ['PROGRAMDATA'] + '\\anselus'


# location of workspace data
tempstr = input(f'Where should workspace data be stored? [{default_workspace_path}]: ')
if tempstr == '':
	tempstr = default_workspace_path

if not os.path.exists(tempstr):
	choice = input(f"{tempstr} doesn't exist. Create it? [Y/n]: ")
	choice = choice.lower()
	if choice == 'yes' or choice == 'y' or choice == '':
		try:
			os.mkdir(tempstr, 0o755)
			print(f"Created folder {tempstr}")
		except Exception as e:
			print(f"Error creating folder {tempstr}: {e}")
			choice = input("Do you want to continue? [Y/n]: ")
			choice = choice.lower()
			if choice == 'yes' or choice == 'y':
				sys.exit(0)

config['workspace_path'] = tempstr

# registration type

print('''
Registration types:
  - private (default): the admin creates all accounts manually.
  - moderated: anyone can ask for an account, but the admin must approve.
  - network: anyone on a subnet can create a new account. By default this is
        set to the local network (192.168/16, 172.16/12, 10/8).
  - public: anyone with access can create a new account. Not recommended.
''')

config['regtype'] = ''
while config['regtype'] == '':
	choice = input("Registration mode [private]: ")
	if choice == '':
		choice = 'private'
	else:
		choice = choice.lower()

	if choice in ['private','public','network','moderated']:
		config['regtype'] = choice
		break

print('''
Each instance has abuse and support addresses. These can autoforward
to the admin workspace or be their own separate, distinct workspaces. Smaller
environments probably will want to say "yes" here.
''')

config['forward_abuse'] = ''
while config['forward_abuse'] == '':
	choice = input("Do you want to autoforward abuse to admin? [Y/n]: ")
	choice = choice.lower()
	if choice in ['yes', 'y', '']:
		config['forward_abuse'] = 'y'
	elif choice in ['n', 'no']:
		config['forward_abuse'] = 'n'

config['forward_support'] = ''
while config['forward_support'] == '':
	choice = input("Do you want to autoforward support to admin? [Y/n]: ")
	choice = choice.lower()
	if choice in ['yes', 'y', '']:
		config['forward_support'] = 'y'
	elif choice in ['n', 'no']:
		config['forward_support'] = 'n'

config['quota_size'] = ''
print('\nDisk quotas set each user to a default value that can be customized.')
while config['quota_size'] == '':
	choice = input("Size, in MiB, of default user disk quota (0 = No quota, default): ")
	if choice == '':
		choice = '0'
	
	try:
		tempint = int(choice)
		config['quota_size'] = choice
	except:
		continue

# location of server config and log files

config['config_path'] = '/etc/anselusd'
if server_platform == 'windows':
	config['config_path'] = os.environ['PROGRAMDATA'] + '\\anselusd'
	config['log_path'] = config['config_path']
else:
	config['log_path'] = '/var/log/anselusd'
	tempstr = input('\nEnter the name of the user to run the server as. [anselus]: ')
	if tempstr == '':
		tempstr = 'anselus'
	config['server_user'] = tempstr

	tempstr = input('\nEnter the name of the group for the server user. [anselus]: ')
	if tempstr == '':
		tempstr = 'anselus'
	config['server_group'] = tempstr

# IP address of postgres server
tempstr = input('\nEnter the IP address of the database server. [localhost]: ')
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

tempstr = input('Enter a username which has admin privileges on this database. [anselus]: ').strip()
if tempstr == '':
	tempstr = 'anselus'
config['db_user'] = tempstr

# database user password
config['db_password'] = ''
while config['db_password'] == '':
	choice = input('Enter the password of this user (min 8 characters): ').strip()

	if len(choice) <= 64 and len(choice) >= 8:
		config['db_password'] = choice

# required keycard fields

print(f"""
{colored('NOTE: ','yellow')}Now it is time to enter the organization's information used in the root keycard.
This information can be changed, but the original information will still be a
permanent part of the organization's keycard.

{colored("Please use care when answering",'yellow')}.
""")

config['org_name'] = ''
while config['org_name'] == '':
	choice = input("Name of organization (max 64 characters): ").strip()

	m = re.match(r'\w+', choice)
	if m and len(choice) <= 64:
		config['org_name'] = choice

config['org_domain'] = ''
while config['org_domain'] == '':
	choice = input("Organization's domain (max 253 characters): ").strip()

	m = re.match(r'([a-zA-Z0-9]+\.)+[a-zA-Z0-9]+', choice)
	if m and len(choice) <= 253:
		config['org_domain'] = choice

# set initially to space on-purpose
config['org_language'] = ''
print("""Specifying the languages used by your organization is optional.

Please use two- or three-letter language codes in order of preference from 
greatest to least and separated by a comma. You may choose up to 10 languages.

Examples: 'en' or 'fr,es'

A complete list may be found at 
https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes.
""")

while config['org_language'] == '':
	choice = input("Language(s) [en]: ").strip()
	if choice == '':
		choice = 'en'
	
	m = re.match(r'^[a-zA-Z]{2,3}(,[a-zA-Z]{2,3})*?$', choice)
	count = len(choice.split(','))
	if count > 10:
		print('Too many languages given. Please specify no more than 10.')
		continue
	
	if m and len(choice) <= 253:
		config['org_language'] = choice

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

cur = conn.cursor()
cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER "
			"BY table_name;")
rows = cur.fetchall()
if len(rows) > 0:
	print(f"""
{colored("================================================================================", 'red')}
                      WARNING: the database is not empty!
{colored("================================================================================", 'red')}
	
If you continue, {colored("ALL DATA WILL BE DELETED FROM THE DATABASE",'yellow')}, which means all
keycards and workspace information will be erased.
""")
	choice = input("Do you want to DELETE ALL DATA and continue? [y/N]: ").casefold()
	if choice not in ['y', 'yes']:
		sys.exit(0)
	
	dropcmd = '''DO $$ DECLARE
		r RECORD;
	BEGIN
		FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = current_schema()) LOOP
			EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
		END LOOP;
	END $$;'''
	cur.execute(dropcmd)

print('Performing database first-time setup.\n')

cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'workspaces' AND "
			"c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE workspaces(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL, "
		"uid VARCHAR(64), domain VARCHAR(255) NOT NULL, wtype VARCHAR(32) NOT NULL, "
		"status VARCHAR(16) NOT NULL, password VARCHAR(128));")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'aliases' AND "
			"c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE aliases(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL, "
		"alias CHAR(292) NOT NULL);")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'iwkspc_folders' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE iwkspc_folders(rowid SERIAL PRIMARY KEY, wid char(36) NOT NULL, "
				"enc_key VARCHAR(64) NOT NULL);")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'iwkspc_devices' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE iwkspc_devices(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL, "
				"devid CHAR(36) NOT NULL, devkey VARCHAR(1000) NOT NULL, "
				"status VARCHAR(16) NOT NULL);")


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
				"uid VARCHAR(128) NOT NULL, domain VARCHAR(255) NOT NULL, regcode VARCHAR(128));")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'keycards' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE keycards(rowid SERIAL PRIMARY KEY, owner VARCHAR(292) NOT NULL, "
				"creationtime TIMESTAMP NOT NULL, index INTEGER NOT NULL, "
				"entry VARCHAR(8192) NOT NULL, fingerprint VARCHAR(96) NOT NULL);")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'orgkeys' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE orgkeys(rowid SERIAL PRIMARY KEY, creationtime TIMESTAMP NOT NULL, "
				"pubkey VARCHAR(7000), privkey VARCHAR(7000) NOT NULL, "
				"purpose VARCHAR(8) NOT NULL, fingerprint VARCHAR(96) NOT NULL);")


# create the org's keys and put them in the table

ekey = dict()
hasher = hashlib.blake2b(digest_size=32)
key = nacl.public.PrivateKey.generate()
ekey['public'] = "CURVE25519:" + base64.b85encode(key.public_key.encode()).decode()
ekey['private'] = "CURVE25519:" + base64.b85encode(key.encode()).decode()
hasher.update(base64.b85encode(key.public_key.encode()))
ekey['fingerprint'] = "BLAKE2B-256:" + base64.b85encode(hasher.digest()).decode()
ekey['timestamp'] = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
config['org_encrypt'] = ekey['public']
config['org_decrypt'] = ekey['private']


pskey = dict()
hasher = hashlib.blake2b(digest_size=32)
key = nacl.signing.SigningKey.generate()
pskey['verify'] = "ED25519:" + base64.b85encode(key.verify_key.encode()).decode()
pskey['sign'] = "ED25519:" + base64.b85encode(key.encode()).decode()
hasher.update(base64.b85encode(key.verify_key.encode()))
pskey['fingerprint'] = "BLAKE2B-256:" + base64.b85encode(hasher.digest()).decode()
pskey['timestamp'] = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
config['org_verify'] = pskey['verify']
config['org_sign'] = pskey['sign']

# Using Python's string substitution to compose SQL commands is normally really, really 
# dangerous because it enables SQL injection attacks. We're using only our own data generated in 
# this script, so it's not so terrible

cur.execute(f"INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose, fingerprint) "
			f"VALUES('{ekey['timestamp']}', '{ekey['public']}', '{ekey['private']}', 'encrypt', "
			f"'{ekey['fingerprint']}');")

cur.execute(f"INSERT INTO orgkeys(creationtime, pubkey, privkey, purpose, fingerprint) "
			f"VALUES('{pskey['timestamp']}', '{pskey['verify']}', '{pskey['sign']}', 'sign', "
			f"'{pskey['fingerprint']}');")


rootentry = keycard.OrgEntry()
rootentry.set_fields({
	'Name' : config['org_name'],
	'Primary-Verification-Key' : config['org_verify'],
	'Encryption-Key' : config['org_encrypt']
})

if 'org_language' in config and len(config['org_language']) > 0:
	rootentry.set_field('Language', config['org_language'])

# preregister the admin account and put into the serverconfig

admin_wid = str(uuid.uuid4())
regcode = make_diceware()
cur.execute(f"INSERT INTO prereg(wid, uid, domain, regcode) VALUES('{admin_wid}', 'admin', "
	f"'{config['org_domain']}', '{regcode}');")

config['admin_wid'] = admin_wid
config['admin_regcode'] = regcode
rootentry.set_field('Contact-Admin', '/'.join([admin_wid,config['org_domain']]))

cur.execute(f"INSERT INTO workspaces(wid, uid, domain, wtype, status) VALUES('{admin_wid}', "
	f"'admin', '{config['org_domain']}', 'individual', 'active');")

# preregister the abuse account if not aliased and put into the serverconfig

abuse_wid = str(uuid.uuid4())
config['abuse_wid'] = abuse_wid
rootentry.set_field('Contact-Abuse', '/'.join([abuse_wid,config['org_domain']]))

if config['forward_abuse'] == 'y':
	cur.execute(f"INSERT INTO workspaces(wid, uid, domain, wtype, status) VALUES('{abuse_wid}', "
		f"'abuse', '{config['org_domain']}', 'alias', 'active');")
	
	cur.execute(f"INSERT INTO aliases(wid, alias) VALUES('{abuse_wid}', "
		f"'{'/'.join([admin_wid, config['org_domain']])}');")
else:
	abuse_regcode = make_diceware()
	cur.execute(f"INSERT INTO prereg(wid, uid, domain, regcode) "
		f"VALUES('{abuse_wid}', 'abuse', '{config['org_domain']}', '{abuse_regcode}');")
	cur.execute(f"INSERT INTO workspaces(wid, uid, domain, wtype, status) VALUES('{abuse_wid}', "
		f"'abuse', '{config['org_domain']}', 'individual', 'active');")

	config['abuse_regcode'] = abuse_regcode


# preregister the support account if not aliased and put into the serverconfig

support_wid = str(uuid.uuid4())
config['support_wid'] = support_wid
rootentry.set_field('Contact-Support', '/'.join([support_wid,config['org_domain']]))

if config['forward_support'] == 'y':
	cur.execute(f"INSERT INTO workspaces(wid, uid, domain, wtype, status) VALUES('{support_wid}', "
		f"'support', '{config['org_domain']}', 'alias', 'active');")
	
	cur.execute(f"INSERT INTO aliases(wid, alias) VALUES('{support_wid}', "
		f"'{'/'.join([admin_wid, config['org_domain']])}');")
else:
	support_regcode = make_diceware()
	cur.execute(f"INSERT INTO prereg(wid, uid, domain, regcode) "
		f"VALUES('{support_wid}', 'support', '{config['org_domain']}', '{support_regcode}');")
	cur.execute(f"INSERT INTO workspaces(wid, uid, domain, wtype, status) VALUES('{support_wid}', "
		f"'support', '{config['org_domain']}', 'individual', 'active');")

	config['support_regcode'] = support_regcode

status = rootentry.is_data_compliant()
if status.error():
	print(f"There was a problem with the organization data: {status.info()}")
	sys.exit()

status = rootentry.generate_hash('BLAKE2B-256')
if status.error():
	print(f"Unable to generate the hash for the org keycard: {status.info()}")
	sys.exit()

status = rootentry.sign(CryptoString(config['org_sign']), 'Organization')
if status.error():
	print(f"Unable to sign the org keycard: {status.info()}")
	sys.exit()

status = rootentry.generate_hash('BLAKE2B-256')
if status.error():
	print(f"Unable to generate the hash for the org keycard: {status.info()}")
	sys.exit()

status = rootentry.is_compliant()
if status.error():
	print(f"There was a problem with the keycard's compliance: {status.info()}")
	sys.exit()

cur.execute("INSERT INTO keycards(owner, creationtime, index, entry, fingerprint) "
			"VALUES(%s, %s, %s, %s, %s);",
			(config['org_domain'], rootentry.fields['Timestamp'], rootentry.fields['Index'],
				str(rootentry), rootentry.hash)
			)

cur.close()
conn.commit()

# For POSIX platforms, ensure that the user and group for the server daemon exist

if server_platform != 'windows':
	create_group = False
	try:
		grp.getgrnam(config['server_group'])
	except:
		create_group = True
	
	if create_group:
		cmd = ['groupadd', '--system', config['server_group']]

		pipe = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output, error = pipe.communicate()
		output = output.strip().decode("utf-8")
		error = error.decode("utf-8")
		if pipe.returncode != 0:
			print(f"Error creating group {config['server_group']}. Error: {error}")
			print("Please create the group manually as a system group and restart this script.")
			sys.exit(1)

	create_user = False
	try:
		pwd.getpwnam(config['server_user'])
	except:
		create_user = True
	
	if create_user:
		cmd = ['useradd', '-d', config['workspace_path'], '-M', '-g', config['server_group'],
			'--system', '-s', '/bin/false', config['server_user']]
		
		pipe = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output, error = pipe.communicate()
		output = output.strip().decode("utf-8")
		error = error.decode("utf-8")
		if pipe.returncode != 0:
			print(f"Error creating user {config['server_user']}. Error: {error}")
			print("Please create the user manually as a system user without a login shell and "
				"restart this script.")
			sys.exit(1)


# create the server config folder and, for POSIX platforms, the log folder 

if not os.path.exists(config['config_path']):
	try:
		os.mkdir(config['config_path'], 0o755)
		print(f"Created server config folder {config['config_path']}")
	except Exception as e:
		print(f"Error creating folder {config['config_path']}: {e}")
		print("You will need to create this folder manually and restart this script.")
		sys.exit(-1)

if not os.path.exists(config['log_path']):
	try:
		os.mkdir(config['log_path'], 0o775)
		print(f"Created log folder {config['log_path']}")

	except Exception as e:
		print(f"Error creating folder {config['log_path']}: {e}")
		print("You will need to create this folder manually, set full permissions for the owner "
			"and group members and restart this script.")
		sys.exit(-1)
	
	try:
		gid = grp.getgrnam(config['server_group'])
		os.chown(config['log_path'], -1, gid.gr_gid) # pylint: disable=no-member
	except Exception as e:
		print(f"Error changing group for folder {config['log_path']}: {e}")
		print(f"You will need to do this manually. Please set the group for {config['log_path']} "
			f"to {config['server_group']} and restart this script. ")
		sys.exit(-1)

# Step 4: save the config file

config_file_path = os.path.join(config['config_path'], 'serverconfig.toml')
if os.path.exists(config_file_path):
	backup_name = 'serverconfig.toml.' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
	print(f"Config file {config_file_path} exists. Renaming to {backup_name}.")
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

fhandle.write('''# This is an Anselus server config file. Each value listed below is the 
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

if config['db_user'] != 'anselus':
	fhandle.write('user = "' + config['db_user'] + '"' + os.linesep)

if config['db_password'] != 'anselus':
	fhandle.write('password = "' + config['db_password'] + '"' + os.linesep)

fhandle.write('''
[global]
# The domain for the organization.
''' + 'domain = "' + config['org_domain'] + '"' + os.linesep)

fhandle.write('''
# The location where workspace data is stored. The default for Windows is 
# "C:\\ProgramData\\anselus", but for other platforms is "/var/anselus".
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
# by an administrator. For most situations 'private' is the appropriate setting.
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
''')

if config['quota_size'] != '0':
	fhandle.write('default_quota = ' + config['quota_size'] + os.linesep)

fhandle.write('''
# Location for log files. This directory requires full permissions for the user anselusd runs as.
# On Windows, this defaults to the same location as the server config file, i.e. 
# C:\\ProgramData\\anselusd
# log_path = /var/log/anselusd
''')

fhandle.write('''
[network]
# The interface and port to listen on
# listen_ip = "127.0.0.1"
# port = "2001"

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
# Adjust the password security strength. Argon2id is used for the hash
# generation algorithm. This setting may be `normal` or `enhanced`. Normal is
# best for most situations, but for environments which require extra security,
# `enhanced` provides additional protection at the cost of higher server
# demands.
# password_security = normal
''')

fhandle.close()

print(f"""

{colored('==============================================================================','green')}
Basic setup is complete.

From here, please make sure you:

1) Review the config file at {config_file_path}.
2) Make sure port 2001 is open on the firewall.
3) Start the anselusd service.
4) Finish registration of the admin account on a device that is NOT this server.
5) If you are using separate abuse or support accounts, also complete
   registration for those accounts on a device that is NOT this server.

""")

print(f"Administrator workspace: {config['admin_wid']}/{config['org_domain']}")
print(f"Administrator registration code: {config['admin_regcode']}\n")

if config['forward_abuse'] != 'y':
	print(f"Abuse workspace: {config['abuse_wid']}/{config['org_domain']}")
	print(f"Abuse registration code: {config['abuse_regcode']}\n")

if config['forward_support'] != 'y':
	print(f"Support workspace: {config['support_wid']}/{config['org_domain']}")
	print(f"Support registration code: {config['support_regcode']}\n")
