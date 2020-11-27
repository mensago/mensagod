#!/usr/bin/env python3

# ejd.py: Utility for encrypting and decrypting EJD files

# Released under the terms of the MIT license
# ©2020 Jon Yoder <jsyoder@mailfence.com>

from base64 import b85encode, b85decode
import json
import hashlib
import os
import sys

import nacl.public
import nacl.secret
import nacl.utils
from pyanselus.keycard import EncodedString, Base85Encoder
from pyanselus.retval import RetVal, BadParameterValue

debug_mode = True

def PrintUsage():
	'''Prints the usage for the script'''
	print("Usage: %s encrypt keyfile output_file input_file [input_file2 ...] " % \
			os.path.basename(sys.argv[0]))
	print("Usage: %s decrypt keyfile output_dir input_file" % \
			os.path.basename(sys.argv[0]))
	sys.exit(0)


def GetKey(keystr : str) -> RetVal:
	'''Checks if the passed string is a path or an EncodedString of a key and returns an 
	EncodedString.'''
	key = EncodedString()
	status = key.set(keystr)
	if not status.error():
		# Make sure that the encoded string we received is actually the right kind of key
		if key.prefix() != 'CURVE25519':
			return RetVal(BadParameterValue, 'key type is not supported')
		
		return RetVal().set_value('key', key)

	elif os.path.exists(keystr):
		with open(keystr, 'r') as f:
			keyline = f.readline()
			status = key.set(keyline.strip())
			if status.error():
				return status
	else:
		return RetVal(BadParameterValue, "key not keystring or keyfile")

	return RetVal().set_value('key', key)


def DecryptFile(pubkey : EncodedString, privkey : EncodedString, ejdfile : str, outpath=''):
	'''Given an EncodedString key, extracts files from the supplied path to the specified 
	directory. If no directory is given, the current directory is used.'''
	if not outpath:
		outpath = os.getcwd()
	
	# TODO: Implement
	# Steps
	# Read in JSON data
	# Hash supplied pubkey and compare to KeyHash
	# Decrypt secret key
	# Decrypt payload using secret key
	# Deallocate main file's JSON data to save RAM
	# Decode each file and write to disk


def EncryptFiles(key : EncodedString, infiles : list, outpath : str):
	'''Given an EncodedString key, packages the list of files into an .ejd archive. If outpath is 
		not given, the encoded file will be placed in the same directory as the input file.'''
	
	if not outpath:
		outpath = os.path.join(os.getcwd(), 'encrypted.ejd')

	
	# Generate a random secret key and nonce and then encrypt the file
	secretkey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
	nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
	secretbox = nacl.secret.SecretBox(secretkey)
	
	# Generate a hash of the public key passed to the function to enable key identification
	# NOTE: this is a hash of the encoded string -- the prefix, separator, and Base85-encoded key
	hasher = hashlib.blake2b(digest_size=32)
	hasher.update(key.as_string().encode())
	keyhash = "BLAKE2B-256:" + b85encode(hasher.digest()).decode()

	# Encrypt the secret key with the public key passed to the function
	sealedbox = nacl.public.SealedBox(nacl.public.PublicKey(key.raw_data()))
	encryptedkey = sealedbox.encrypt(secretkey, Base85Encoder)

	outdata = {
		'Item' : {
			'Version' : '1.0',
			'Nonce' : b85encode(nonce).decode(),
			'KeyHash' : keyhash,
			'Key' : encryptedkey.decode()
		},
		'Payload' : ''
	}

	payload = list()
	for inpath in infiles:

		try:
			f = open(inpath, 'rb')
			filedata = f.read()
		except Exception as e:
			print('Unable to open %s: %s' % (inpath, e))
			continue
		f.close()

		payload.append({
				'Name' : os.path.basename(inpath),
				'Data' : b85encode(filedata).decode()
			})
		
	outdata['Payload'] = "XSALSA20:" + secretbox.encrypt(json.dumps(payload,
		ensure_ascii=False).encode(), nonce, Base85Encoder).decode()

	try:
		f = open(outpath, 'w')
		json.dump(outdata, f, ensure_ascii=False, indent='\t')
	except Exception as e:
		print('Unable to save %s: %s' % (outpath, e))
		return
	f.close()
			

def HandleArgs():
	'''Handles command-line arguments and executes functions accordingly'''
	if debug_mode:
		pubkey = EncodedString()
		pubkey.set(r"CURVE25519:yb8L<$2XqCr5HCY@}}xBPWLHyXZdx&l>+xz%p1*W")
		privkey = EncodedString()
		privkey.set(r"CURVE25519:7>4ui(`dvGc1}N!EerhNHk0tY`f-joG25Gd81lcw")

		# First, test encryption
		scriptpath = os.path.dirname(os.path.realpath(__file__))
		infiles = [
			os.path.join(scriptpath, 'hasher85.py'),
			os.path.join(scriptpath, 'cardstats.py')
		]
		ejdfile = os.path.join(scriptpath, 'enctest.ejd')
		EncryptFiles(pubkey, infiles, ejdfile)

		# Now test decryption
		outdir = os.path.join(scriptpath, 'ejdtest')
		DecryptFile(pubkey, privkey, ejdfile, outdir)
		return

	if len(sys.argv) < 2:
		PrintUsage()
	
	command = sys.argv[1].lower()
	if command == 'encrypt':
		if len(sys.argv) < 5:
			PrintUsage()
	elif command == 'decrypt':
		if len(sys.argv) != 4:
			PrintUsage()
	else:
		PrintUsage()
	
	status = GetKey(sys.argv[2])
	if status.error():
		print('Error processing key: %s' % status.info())
	
	outfile = ''
	if len(sys.argv) == 5:
		outfile = sys.argv[4]
	
	if command == 'encrypt':
		EncryptFiles(status['key'], sys.argv[4:], outfile)
	else:
		DecryptFile(status['key'], sys.argv[4], sys.argv[3])
	

if __name__ == '__main__':
	HandleArgs()
