#!/usr/bin/env python3

# setupconfig - a script perform post-installation server configuration

# Released under the terms of the MIT license
# ©2019-2020 Jon Yoder <jsyoder@mailfence.com>

import base64
import hashlib
import os
import platform
import subprocess
import sys
import time

import nacl.public
import nacl.signing
import psycopg2

# Steps to perform:
#
# Check prerequisites
# 	- root privileges
#	- postgresql is running

# Get necessary information from the user
#	- location of workspace data
#	- IP address of postgres server
#	- port of postgres server
#	- database username
#	- database user password

# Set up the database tables
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


# Get necessary information from the user
#	- location of workspace data
#	- IP address of postgres server
#	- port of postgres server
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
print("\nanselusd expects to find on the database server a database named 'anselus'.")
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

# Verify existence of needed tables

cur = conn.cursor()
cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'iwkspc_main' AND "
			"c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE iwkspc_main(rowid SERIAL PRIMARY KEY, wid char(36) NOT NULL, "
				"friendly_address VARCHAR(48), password VARCHAR(128) NOT NULL, "
				"status VARCHAR(16) NOT NULL);")


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
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'keycards' "
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

# TODO: preregister the admin account and put into the serverconfig

cur.close()
conn.commit()

# TODO: create the workspace folder
# TODO: create the server config folder
# TODO: save the config file
