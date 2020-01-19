#!/usr/bin/env python3

import os
import socket
import sys

def main():
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind(('127.0.0.1', 2001))
		print('Listening for connections')
		s.listen()
		conn, addr = s.accept()
		if conn:
			conn.send("+OK Anselus v0.1\r\n".encode())
			while True:
				data = conn.recv(8192)
				try:
					tokens = data.decode().strip().split()
				except Exception as e:
					print("Unable to decode message sent by host %s : %s" % (addr, e))
					continue

				if not tokens:
					continue
				
				verb = tokens[0].casefold()
				if verb == 'quit':
					break
				print(tokens)
			conn.close()

if __name__ == '__main__':
	main()
