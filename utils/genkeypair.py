#!/usr/bin/env python3

import nacl.public
import nacl.secret
import nacl.utils
from os import path
import sys

def encode_file(file_name):
	keypair = nacl.public.PrivateKey.generate()
	
	pub_name = file_name + '.pub'
	if path.exists(pub_name):
		response = input("%s exists. Overwrite? [y/N]: " % pub_name)
		if not response or response.casefold()[0] != 'y':
			return
	
	try:
		out = open(pub_name, 'wb')
		out.write(bytes(keypair.public_key))
	except Exception as e:
		print('Unable to save %s: %s' % (pub_name, e))

	priv_name = file_name + '.priv'
	try:
		out = open(priv_name, 'wb')
		out.write(bytes(keypair))
	except Exception as e:
		print('Unable to save %s: %s' % (priv_name, e))

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("Usage: %s <namebase>" % path.basename(sys.argv[0]))
	else:
		encode_file(sys.argv[1])
	