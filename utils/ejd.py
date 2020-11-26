#!/usr/bin/env python3

# ejd.py: Utility for encrypting and decrypting EJD files

# Released under the terms of the MIT license
# ©2020 Jon Yoder <jsyoder@mailfence.com>

import os.path
import sys

from pyanselus.keycard import EncodedString
from pyanselus.retval import RetVal, BadParameterValue


def PrintUsage():
	'''Prints the usage for the script'''
	print("Usage: %s (encrypt|decrypt) keyfile input_file [output_file]" % \
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


def DecryptFile(key : EncodedString, inpath : str, outpath=''):
	'''Given an EncodedString key, packages passed path to file into a .ejd. If outpath not given,
		the encoded file will be placed in the same directory as the input file.'''


def EncryptFile(key : EncodedString, inpath : str, outpath=''):
	'''Given an EncodedString key, packages passed path to file into a .ejd. If outpath not given,
		the encoded file will be placed in the same directory as the input file.'''


def HandleArgs():
	'''Handles command-line arguments and executes functions accordingly'''
	if len(sys.argv) not in [4, 5]:
		PrintUsage()
	
	command = sys.argv[1].lower()
	if command not in ['encrypt','decrypt']:
		PrintUsage()
	
	status = GetKey(sys.argv[2])
	if status.error():
		print('Error processing key: %s' % status.info())
	
	outfile = ''
	if len(sys.argv) == 5:
		outfile = sys.argv[4]
	
	if command == 'encrypt':
		EncryptFile(status['key'], sys.argv[3], outfile)
	else:
		DecryptFile(status['key'], sys.argv[3], outfile)
	

if __name__ == '__main__':
	HandleArgs()
