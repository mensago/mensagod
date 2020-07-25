#!/usr/bin/env python3

import os.path
import sys

import psycopg2
import toml

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


# Step 3: Verify existence of needed tables

cur = conn.cursor()
cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'iwkspc_main' AND "
			"c.relkind = 'r');")
rows = cur.fetchall()

if rows[0][0] is False:
	cur.execute("CREATE TABLE iwkspc_main(id SERIAL PRIMARY KEY, wid char(36) NOT NULL, "
				"friendly_address VARCHAR(48), password VARCHAR(128) NOT NULL, "
				"status VARCHAR(16) NOT NULL);")

cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'iwkspc_folders' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE iwkspc_folders(id SERIAL PRIMARY KEY, wid char(36) NOT NULL, "
				"enc_name VARCHAR(128) NOT NULL, enc_key VARCHAR(64) NOT NULL);")

cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'iwkspc_devices' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE iwkspc_devices(id SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL, "
				"devid CHAR(36) NOT NULL, keytype VARCHAR(16) NOT NULL, "
				"devkey VARCHAR(1000) NOT NULL, status VARCHAR(16) NOT NULL);")

cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'failure_log' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE failure_log(id SERIAL PRIMARY KEY, type VARCHAR(16) NOT NULL, "
				"wid VARCHAR(36), source VARCHAR(36) NOT NULL, count INTEGER, "
				"last_failure TIMESTAMP NOT NULL, lockout_until TIMESTAMP);")


cur.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
			"n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'prereg' "
			"AND c.relkind = 'r');")
rows = cur.fetchall()
if rows[0][0] is False:
	cur.execute("CREATE TABLE prereg(id SERIAL PRIMARY KEY, wid VARCHAR(36) NOT NULL UNIQUE, "
				"uid VARCHAR(128) NOT NULL, regcode VARCHAR(128));")


cur.close()
conn.commit()

