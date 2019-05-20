#!/usr/bin/env python3

# This is a proof-of-concept server daemon for the Anselus groupware protocol

import commands
import log

import socket

gConfig = {
	'host' : 'localhost',
	'port' : 1024
}


def read_config():
	pass


def service_loop(conn, host):
	log.Log("Connection to %s established." % str(host), log.INFO)
	while True:
		data = conn.recv(8192)
		tokens = data.decode().strip().split()

		# handle_command will return False when it's time to close the 
		# connection
		if not commands.handle_command(tokens):
			break
	conn.close()


def main():
	log.Init('anselus-testserver.log')
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((gConfig['host'], gConfig['port']))
		s.listen()
		conn, addr = s.accept()
		if conn:
			service_loop(conn, addr)


if __name__ == '__main__':
	main()