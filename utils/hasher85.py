#!/usr/bin/env python3

import sys

# Hasher85.py: utility to generate base85-encoded hash signatures
# Usage: hasher85.py <algorithm> <filename>

supported_algorithms = [
	'blake3-256',
	'blake2-256',
	'sha256',
	'sha512',
	'sha3-256',
	'sha3-512'
]

def hash_blake3_256(data: bytes):
	'''Returns a 256-bit BLAKE3 hash as a string'''

	# TODO: Implement
	return ""

hash_functions = {
	"blake3-256" : hash_blake3_256
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
	print(f"{path}:\t{file_hash}")
	

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
