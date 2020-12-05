#!/usr/bin/env python3

# ejd.py: Utility for encrypting and decrypting EJD files

# Released under the terms of the MIT license
# ©2020 Jon Yoder <jsyoder@mailfence.com>

from base64 import b85encode, b85decode
import hashlib
import json
import os
import sys

import nacl.public
import nacl.secret
import nacl.utils
from pyanselus.keycard import EncodedString, Base85Encoder
from pyanselus.retval import RetVal, BadParameterValue

debug_mode = True

global_options = {
	'overwrite' : 'ask',
	'verbose' : False,
	'files' : list(),
	'mode' : '',
	'pubkey' : EncodedString(),
	'privkey' : EncodedString()
}

def print_usage():
	'''Prints the usage for the script'''
	print("Usage: %s encrypt keyfile output_file input_file [input_file2 ...] " % \
			os.path.basename(sys.argv[0]))
	print("Usage: %s decrypt keyfile output_dir input_file" % \
			os.path.basename(sys.argv[0]))
	sys.exit(0)


def get_key(keystr : str) -> RetVal:
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


def ejd_decrypt(indata : dict, outpath : str):
	'''Test decryption'''
	
	secretkeystr = EncodedString(indata['Item']['Key'])

	# Hash supplied pubkey and compare to KeyHash
	hasher = hashlib.blake2b(digest_size=32)
	hasher.update(global_options['pubkey'].as_string().encode())
	if indata['Item']['KeyHash'] != "BLAKE2B-256:" + b85encode(hasher.digest()).decode():
		print("Public key supplied doesn't match key used for file. Unable to decrypt.")
		return
	
	# Decrypt secret key and then decrypt the payload
	sealedbox = nacl.public.SealedBox(nacl.public.PrivateKey(global_options['privkey'].raw_data()))

	try:
		decryptedkey = sealedbox.decrypt(secretkeystr.raw_data())
	except:
		print(f"Unable to decrypt the secret key.")
		return
	
	secretbox = nacl.secret.SecretBox(decryptedkey)
	try:
		decrypted_data = secretbox.decrypt(b85decode(indata['Payload']))
	except:
		print(f"Unable to decrypt the file payload.")
		return
	
	payload_data = json.loads(decrypted_data)

	# We've gotten this far, so let's dump the files in the payload
	for item in payload_data:
		itempath = os.path.join(outpath,item['Name'])

		if os.path.exists(itempath):
			if global_options['overwrite'] == 'no':
				print(f"{itempath} exists. Not overwriting it.")
				continue
			elif global_options['overwrite'] == 'ask':
				choice = input(f"{itempath} exists. Overwrite? [y/N/all] ").strip().casefold()
				if choice in ['a', 'all']:
					global_options['overwrite'] = 'yes'
				elif choice in ['n', 'no']:
					continue

		try:
			f = open(itempath, 'wb')
		except Exception as e:
			print(f"Unable to save file {itempath}: {e}")
			continue
		
		try:
			f.write(b85decode(item['Data']))
			if global_options['verbose']:
				print(f"Extracted file {itempath}")
		except ValueError:
			print(f"Problem decoding file data for {itempath}")
			f.close()
			continue
		except Exception as e:
			print(f"Unable to save file {itempath}: {e}")
			f.close()
			continue
		
		f.close()


def ejd_encrypt() -> dict:
	'''Test encryption'''

	# Generate a random secret key and encrypt the data given to us
	secretkey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
	mynonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
	secretbox = nacl.secret.SecretBox(secretkey)

	# Generate a hash of the public key passed to the function to enable key identification
	# NOTE: this is a hash of the encoded string -- the prefix, separator, and Base85-encoded key
	hasher = hashlib.blake2b(digest_size=32)
	hasher.update(global_options['pubkey'].as_string().encode())

	# Encrypt the secret key with the public key passed to the function
	sealedbox = nacl.public.SealedBox(nacl.public.PublicKey(global_options['pubkey'].raw_data()))
	encryptedkey = 'XSALSA20:' + sealedbox.encrypt(secretkey, Base85Encoder).decode()

	payload_data = list()
	for inpath in global_options['files']:

		try:
			f = open(inpath, 'rb')
			filedata = f.read()
		except Exception as e:
			print('Unable to open %s: %s' % (inpath, e))
			continue
		f.close()

		payload_data.append({
				'Type' : 'file',
				'Name' : os.path.basename(inpath),
				'Data' : b85encode(filedata).decode()
			})
		
	encrypted_data = secretbox.encrypt(json.dumps(payload_data, ensure_ascii=False).encode(),
		nonce=mynonce)

	outdata = {
		'Item' : {
			'Version' : '1.0',
			'KeyHash' : "BLAKE2B-256:" + b85encode(hasher.digest()).decode(),
			'Key' : EncodedString(encryptedkey).as_string(),
		},
		'Payload' : b85encode(encrypted_data).decode()
	}

	return outdata


def HandleArguments():
	'''Handles command-line arguments and executes functions accordingly'''
	if len(sys.argv) < 2:
		print_usage()
	
	command = sys.argv[1].lower()
	if command == 'encrypt':
		if len(sys.argv) < 5:
			print_usage()
	elif command == 'decrypt':
		if len(sys.argv) != 4:
			print_usage()
	else:
		print_usage()
	
	status = get_key(sys.argv[2])
	if status.error():
		print('Error processing key: %s' % status.info())
	
	outfile = ''
	if len(sys.argv) == 5:
		outfile = sys.argv[4]


if __name__ == '__main__':
	if debug_mode:
		scriptpath = os.path.dirname(os.path.realpath(__file__))
		global_options['files'] = [
			os.path.join(scriptpath, 'hasher85.py'),
			os.path.join(scriptpath, 'cardstats.py')
		]
		global_options['mode'] = 'encrypt'
		global_options['pubkey'] = EncodedString(
			r"CURVE25519:yb8L<$2XqCr5HCY@}}xBPWLHyXZdx&l>+xz%p1*W")
		global_options['privkey'] = EncodedString(
			r"CURVE25519:7>4ui(`dvGc1}N!EerhNHk0tY`f-joG25Gd81lcw")
	else:
		HandleArguments()

	outpath = ''
	if 'USERPROFILE' in os.environ:
		outpath = os.path.join(os.environ['USERPROFILE'], 'Desktop')
	else:
		outpath = os.path.join(os.environ['HOME'], 'Desktop')

	encdata = ejd_encrypt()
	
	ejd_decrypt(encdata, outpath)
