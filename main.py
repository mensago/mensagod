#!/usr/bin/env python3

# This is a proof-of-concept server daemon for the Anselus groupware protocol
import commands
import log
import serverconfig

import os
import socket
import sys

def service_loop(conn, host):
	log.Log("Connection to %s established." % str(host), log.INFO)
	while True:
		data = conn.recv(8192)
		tokens = data.decode().strip().split()

		# handle_command will return False when it's time to close the 
		# connection
		if not commands.handle_command(tokens, conn):
			break
	conn.close()


def main():
	log.Init('anselus-testserver.log')

	if not os.path.exists(serverconfig.gConfig['mailboxdir']):
		try:
			os.mkdir(serverconfig.gConfig['mailboxdir'])
		except Exception as e:
			print(e)
			sys.exit()

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((serverconfig.gConfig['host'], serverconfig.gConfig['port']))
		s.listen()
		conn, addr = s.accept()
		if conn:
			service_loop(conn, addr)


if __name__ == '__main__':
	main()