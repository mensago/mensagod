#!/usr/bin/env python3

# ejd.py: Utility for encrypting and decrypting EJD files

# Released under the terms of the MIT license
# ©2020 Jon Yoder <jon@yoder.cloud>

from base64 import b85encode, b85decode
import hashlib
import json
import os
import sys

import jsonschema
import nacl.public
import nacl.secret
import nacl.utils
from pymensago.keycard import CryptoString, Base85Encoder

debug_mode = False

global_options = {
	'overwrite' : 'ask',
	'verbose' : False,
	'files' : list(),
	'mode' : '',
	'pubkey' : CryptoString(),
	'privkey' : CryptoString(),
	'ejdfile' : '',
	'outpath' : ''
}

def print_usage():
	'''Prints the usage for the script'''
	print("Usage: %s encrypt <keyfile> <output_file> <input_file> [<input_file2> ...] " % \
			os.path.basename(sys.argv[0]))
	print("Usage: %s decrypt <keyfile> <ejd_file> <output_dir> " % \
			os.path.basename(sys.argv[0]))
	sys.exit(0)


def load_keyfile(keypath : str) -> dict:
	'''Loads keys from the specified keyfile'''
	
	keydata = dict()
	if not os.path.exists(keypath):
		print(f"{keypath} doesn't exist")
		sys.exit(-1)

	try:
		fhandle = open(keypath, 'r')
	except Exception as e:
		print(f"Unable to open {keypath}: {e}")
		sys.exit(-1)

	try:
		keydata = json.load(fhandle)
	except Exception as e:
		print(f"Unable to process {keypath}: {e}")
		sys.exit(-1)
	
	if global_options['mode'] == 'decrypt':
		jkey_schema = {
			'type' : 'object',
			'properties' : {
				'PublicKey' : { 'type' : 'string' },
				'PrivateKey' : { 'type' : 'string' },
			}
		}
	else:
		jkey_schema = {
			'type' : 'object',
			'properties' : {
				'PublicKey' : { 'type' : 'string' }
			}
		}

	try:
		jsonschema.validate(keydata, jkey_schema)
	except Exception as e:
		print(f"Required info missing from {keypath}: {e}")
		sys.exit(-1)
	
	return keydata


def load_ejd(inpath : str) -> dict:
	'''Given a path, loads an .EJD file and returns a dictionary of the JSON data'''

	outdata = dict()
	if not os.path.exists(inpath):
		print(f"{inpath} doesn't exist")
		sys.exit(-1)

	try:
		fhandle = open(inpath, 'r')
	except Exception as e:
		print(f"Unable to open {inpath}: {e}")
		sys.exit(-1)

	try:
		outdata = json.load(fhandle)
	except Exception as e:
		print(f"Unable to process {inpath}: {e}")
		sys.exit(-1)
	
	ejd_schema = {
		'type' : 'object',
		'properties' : {
			'Item' : {
				'Version' : { 'type' : 'number' },
				'KeyHash' : { 'type' : 'string' },
				'Key' : { 'type' : 'string' },
			},
			'Payload' : { 'type' : 'string' },
		}
	}

	try:
		jsonschema.validate(outdata, ejd_schema)
	except Exception as e:
		print(f"Required info missing from {inpath}: {e}")
		sys.exit(-1)
	
	return outdata


def ejd_decrypt(indata : dict, outpath : str):
	'''Given the JSON data to decrypt and an output path, use the keys in global_options to 
	decrypt files in indata to the specified output path.'''
		
	secretkeystr = CryptoString(indata['Item']['Key'])

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
		print("Unable to decrypt the secret key.")
		return
	
	secretbox = nacl.secret.SecretBox(decryptedkey)
	try:
		decrypted_data = secretbox.decrypt(b85decode(indata['Payload']))
	except:
		print("Unable to decrypt the file payload.")
		return
	
	payload_data = json.loads(decrypted_data)

	# We've gotten this far, so let's dump the files in the payload
	for item in payload_data:
		itempath = os.path.join(outpath,item['Name'])

		if os.path.exists(itempath):
			if global_options['overwrite'] == 'no':
				print(f"{itempath} exists. Not overwriting it.")
				continue
			
			if global_options['overwrite'] == 'ask':
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


def ejd_encrypt(ejdpath : str) -> dict:
	'''Given the name and path of the EJD file to create, load files in global_options['files'] and 
	package them'''

	if os.path.exists(ejdpath):
		if global_options['overwrite'] == 'no':
			print(f"{ejdpath} exists. Exiting.")
			sys.exit(0)
		elif global_options['overwrite'] == 'ask':
			choice = input(f"{ejdpath} exists. Overwrite? [y/N] ").strip().casefold()
			if choice in ['y', 'yes']:
				pass
			else:
				sys.exit(0)
	
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
			'Key' : CryptoString(encryptedkey).as_string(),
		},
		'Payload' : b85encode(encrypted_data).decode()
	}
	
	try:
		f = open(ejdpath, 'w')
		json.dump(outdata, f, ensure_ascii=False, indent='\t')
	except Exception as e:
		print('Unable to save %s: %s' % (ejdpath, e))
		sys.exit(-1)
	f.close()

	return outdata


def handle_arguments():
	'''Handles command-line arguments and executes functions accordingly'''
	if len(sys.argv) < 5:
		print_usage()
	
	command = sys.argv[1].lower()
	if command == 'encrypt':
		global_options['ejdfile'] = sys.argv[3]
		global_options['files'] = sys.argv[4:]
	elif command == 'decrypt':
		global_options['ejdfile'] = sys.argv[3]
		global_options['outpath'] = sys.argv[4]
	else:
		print_usage()
	global_options['mode'] = command
	
	keys = load_keyfile(sys.argv[2])
	global_options['pubkey'] = CryptoString(keys['PublicKey'])
	if command == 'decrypt':
		if 'PrivateKey' not in keys:
			print(f"Private key required for decryption. {sys.argv[2]} does not contain one")
			sys.exit(-1)
		global_options['privkey'] = CryptoString(keys['PrivateKey'])
	

if __name__ == '__main__':
	if debug_mode:
		scriptpath = os.path.dirname(os.path.realpath(__file__))
		global_options['files'] = [
			os.path.join(scriptpath, 'hasher85.py'),
			os.path.join(scriptpath, 'cardstats.py')
		]
		global_options['mode'] = 'encrypt'
		global_options['pubkey'] = CryptoString(
			r"CURVE25519:yb8L<$2XqCr5HCY@}}xBPWLHyXZdx&l>+xz%p1*W")
		global_options['privkey'] = CryptoString(
			r"CURVE25519:7>4ui(`dvGc1}N!EerhNHk0tY`f-joG25Gd81lcw")
	
	
		decryptpath = ''
		if 'USERPROFILE' in os.environ:
			decryptpath = os.path.join(os.environ['USERPROFILE'], 'Desktop')
		else:
			decryptpath = os.path.join(os.environ['HOME'], 'Desktop')

		if debug_mode:
			global_options['ejdfile'] = os.path.join(decryptpath, 'test.ejd')
		
		ejd_encrypt(global_options['ejdfile'])
		encdata = load_ejd(global_options['ejdfile'])
		ejd_decrypt(encdata, decryptpath)
	else:
		handle_arguments()
	
	if global_options['mode'] == 'encrypt':
		ejd_encrypt(global_options['ejdfile'])
	else:
		encdata = load_ejd(global_options['ejdfile'])
		ejd_decrypt(encdata, global_options['outpath'])
