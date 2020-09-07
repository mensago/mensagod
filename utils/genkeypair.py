#!/usr/bin/env python3

import base64
from os import path
import sys

import nacl.signing
import nacl.public
import nacl.secret
import nacl.utils

def generate_encpair(filename):
	'''Creates a asymmetric keypair and saves it to a file in Base85 encoding'''
	keypair = nacl.public.PrivateKey.generate()
	
	if not filename:
		print('Keypair type: encryption\r\n')
		print('public: %s' % base64.b85encode(keypair.public_key.encode()).decode())
		print('private: %s' % base64.b85encode(keypair.encode()).decode())
		return

	if path.exists(filename):
		response = input("%s exists. Overwrite? [y/N]: " % filename)
		if not response or response.casefold()[0] != 'y':
			return
	try:
		out = open(filename, 'wb')

		out.write(b'Keypair type: encryption\r\n')
		out.write(b'public: ' + base64.b85encode(keypair.public_key.encode()) + b'\r\n')
		out.write(b'private: ' + base64.b85encode(keypair.encode()) + b'\r\n')
	except Exception as e:
		print('Unable to save %s: %s' % (filename, e))


def generate_signpair(filename):
	'''Creates a asymmetric signing keypair and saves it to a file in Base85 encoding'''
	keypair = nacl.signing.SigningKey.generate()
	
	if not filename:
		print('Keypair type: signing\r\n')
		print('verify: %s' % base64.b85encode(keypair.verify_key.encode()).decode())
		print('signing: %s' % base64.b85encode(keypair.encode()).decode())
		return
	
	if path.exists(filename):
		response = input("%s exists. Overwrite? [y/N]: " % filename)
		if not response or response.casefold()[0] != 'y':
			return
	try:
		out = open(filename, 'wb')

		out.write(b'Keypair type: signing\r\n')
		out.write(b'verify:' + base64.b85encode(keypair.verify_key.encode()) + b'\r\n')
		out.write(b'sign:' + base64.b85encode(keypair.encode()) + b'\r\n')
	except Exception as e:
		print('Unable to save %s: %s' % (filename, e))


if __name__ == '__main__':
	if len(sys.argv) not in [2,3] or sys.argv[1].casefold() not in ['sign', 'encrypt']:
		print("Usage: %s <sign|encrypt> <filename>" % path.basename(sys.argv[0]))
		sys.exit(0)
	
	keyfile = ''
	if len(sys.argv) == 3:
		keyfile = sys.argv[2]

	if sys.argv[1].casefold() == 'encrypt':
		generate_encpair(keyfile)
	else:
		generate_signpair(keyfile)
