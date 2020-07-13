-- Database: anselus

-- DROP DATABASE anselus;

CREATE DATABASE anselus
    WITH 
    OWNER = postgres
    ENCODING = 'UTF8'
    LC_COLLATE = 'C'
    LC_CTYPE = 'C'
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1;

GRANT ALL ON DATABASE anselus TO jonyoder;

GRANT ALL ON DATABASE anselus TO postgres;

GRANT TEMPORARY, CONNECT ON DATABASE anselus TO PUBLIC;

GRANT ALL ON DATABASE anselus TO anselus;

CREATE TABLE iwkspc_main(id SERIAL PRIMARY KEY, wid char(36) NOT NULL, 
			friendly_address VARCHAR(48), password VARCHAR(128) NOT NULL, 
			status VARCHAR(16) NOT NULL);

CREATE TABLE iwkspc_folders(id SERIAL PRIMARY KEY, wid char(36) NOT NULL, 
				enc_name VARCHAR(128) NOT NULL, enc_key VARCHAR(64) NOT NULL);

CREATE TABLE iwkspc_devices(id SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL, 
				devid CHAR(36) NOT NULL, keytype VARCHAR(16) NOT NULL, 
				devkey VARCHAR(1000) NOT NULL, status VARCHAR(16) NOT NULL);

CREATE TABLE failure_log(id SERIAL PRIMARY KEY, type VARCHAR(16) NOT NULL, 
				wid VARCHAR(36), source VARCHAR(36) NOT NULL, count INTEGER, 
				last_failure TIMESTAMP NOT NULL, lockout_until TIMESTAMP);
