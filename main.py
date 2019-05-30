#!/usr/bin/env python3

# This is a proof-of-concept server daemon for the Anselus groupware protocol
import commands
import log
import serverconfig

import os
import socket
import sys
import threading

class session_thread:
	def __init__(self):
		self.socket = None
		self.host = None
	
	def setup(self, sock, host):
		self.socket = sock
		self.host = host
	
	def run(self):
		# Split off a thread and then run the worker function
		self._session_handler_func()
	
	def _session_handler_func(self):
		log.Log("Connection to %s established." % str(self.host), log.INFO)
		self.socket.send("+OK Anselus v0.1\r\n".encode())
		while True:
			data = self.socket.recv(8192)
			try:
				tokens = data.decode().strip().split()
			except Exception as e:
				log.Log("Unable to decode message sent by host %s : %s" % \
						(self.host, e), log.ERRORS)
				continue

			# handle_command will return False when it's time to close the 
			# connection
			if not commands.handle_command(tokens, self.socket, self.host):
				break
	
		self.socket.close()


def main():
	log.Init('anselus-testserver.log')
	
	log.Log('Checking storage paths', log.INFO)
	serverconfig.gConfig['create_safedir'] = os.path.join(
										serverconfig.gConfig['safeguardsdir'],
										'create_mbox')
	serverconfig.gConfig['delete_safedir'] = os.path.join(
										serverconfig.gConfig['safeguardsdir'],
										'delete_mbox')
	
	# Verify existence of paths needed by the server
	path_list = [
		'workspacedir',
		'safeguardsdir',
		'create_safedir',
		'delete_safedir'
	]
	for temp_path in path_list:
		if not os.path.exists(serverconfig.gConfig[temp_path]):
			try:
				os.mkdir(serverconfig.gConfig[temp_path])
			except Exception as e:
				print(e)
				sys.exit()
	
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((serverconfig.gConfig['host'], serverconfig.gConfig['port']))
		log.Log('Listening for connections', log.INFO)
		s.listen()
		conn, addr = s.accept()
		if conn:
			session = session_thread()
			session.setup(conn, addr)
			session.run()

if __name__ == '__main__':
	main()
