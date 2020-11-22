#!/usr/bin/env python3

# psql_dbsetup - a script to set up an empty Anselus database. NOTE: it will reset existing 
# 	databases back to empty, so do not run this if you have valuable data in the database

# Released under the terms of the MIT license
# ©2019-2020 Jon Yoder <jsyoder@mailfence.com>

import os.path
import sys

import psycopg2
import toml

# Step 1: load the config

config_file_path = '/etc/anselusd/serverconfig.toml'

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

# Step 3: Drop all existing tables
dropcmd = '''DO $$ DECLARE
	r RECORD;
BEGIN
	FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = current_schema()) LOOP
		EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
	END LOOP;
END $$;'''
cursor = conn.cursor()
cursor.execute(dropcmd)

cursor.close()
conn.commit()
