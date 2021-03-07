#!/usr/bin/env python3

import base64
import hashlib
import sys

import blake3

# Hasher85.py: utility to generate base85-encoded hash signatures
# Usage: hasher85.py <algorithm> <filename>

supported_algorithms = [
	'blake3-256',
	'blake2b-256',
	'sha-256',
	'sha-512',
	'sha3-256',
	'sha3-512'
]

def hash_blake3_256(data: bytes):
	'''Returns a 256-bit BLAKE3 hash as a string'''

	hasher = blake3.blake3() # pylint: disable=c-extension-no-member
	hasher.update(data)
	return f"BLAKE3-256 {base64.b85encode(hasher.digest()).decode()}\n" + \
		f"BLAKE3-256H: {hasher.hexdigest()}"

def hash_blake2b_256(data: bytes):
	'''Returns a 256-bit BLAKE2B hash as a string'''

	hasher = hasher = hashlib.blake2b(digest_size=32)
	hasher.update(data)
	return f"BLAKE2B-256 {base64.b85encode(hasher.digest()).decode()}\n" + \
		f"BLAKE2B-256H: {hasher.hexdigest()}"

def hash_sha256(data: bytes):
	'''Returns a SHA2-256 hash as a string'''

	hasher = hasher = hashlib.sha256()
	hasher.update(data)
	return f"SHA-256: {base64.b85encode(hasher.digest()).decode()}\n" + \
		f"SHA-256H: {hasher.hexdigest()}"

def hash_sha512(data: bytes):
	'''Returns a SHA2-512 hash as a string'''

	hasher = hasher = hashlib.sha512()
	hasher.update(data)
	return f"SHA-512: {base64.b85encode(hasher.digest()).decode()}\n" + \
		f"SHA-512H: {hasher.hexdigest()}"

def hash_sha3_256(data: bytes):
	'''Returns a SHA3-256 hash as a string'''

	hasher = hasher = hashlib.sha3_256()
	hasher.update(data)
	return f"SHA3-256: {base64.b85encode(hasher.digest()).decode()}\n" + \
		f"SHA3-256H: {hasher.hexdigest()}"

def hash_sha3_512(data: bytes):
	'''Returns a SHA3-512 hash as a string'''

	hasher = hasher = hashlib.sha3_512()
	hasher.update(data)
	return f"SHA3-512: {base64.b85encode(hasher.digest()).decode()}\n" + \
		f"SHA3-512H: {hasher.hexdigest()}"

hash_functions = {
	"blake3-256" : hash_blake3_256,
	"blake2b-256" : hash_blake2b_256,
	'sha-256' : hash_sha256,
	'sha-512' : hash_sha512,
	'sha3-256': hash_sha3_256,
	'sha3-512': hash_sha3_512
}

def PrintUsage():
	'''Prints program usage'''
	print(f"Usage:\n{sys.argv[0]} <algorithm> <file> [<file2> ...]")
	print("Supported hash algorithms:")
	for algo_item in supported_algorithms:
		print(f"\t{algo_item}")
	sys.exit(0)

def HashFile(path: str, algorithm: str):
	'''Generates a hash for a file given a hashing algorithm'''

	file_data = None
	try:
		with open(path, 'rb') as f:
			file_data = f.read()
	except Exception as e:
		print(f"Unable to open file {path}: {e}")
		return
	
	file_hash = hash_functions[algorithm](file_data)
	print(f"{path}\t{file_hash}")
	

if __name__ == '__main__':
	if len(sys.argv) < 3:
		PrintUsage()

	hash_algorithm = sys.argv[1].lower()
	if hash_algorithm not in supported_algorithms:
		PrintUsage()
	
	if hash_algorithm not in hash_functions.keys():
		print(f"{hash_algorithm} not yet implemented")
		sys.exit(-1)
	
	for item in sys.argv[2:]:
		HashFile(item, hash_algorithm)
