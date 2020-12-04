#!/usr/bin/env python3

# ejd.py: Utility for encrypting and decrypting EJD files

# Released under the terms of the MIT license
# ©2020 Jon Yoder <jsyoder@mailfence.com>

from base64 import b85encode
import hashlib

import nacl.public
import nacl.secret
import nacl.utils
from pyanselus.keycard import EncodedString, Base85Encoder

def TestDecrypt(pubkeystr : EncodedString, privkeystr : EncodedString, indata : dict):
	'''Test decryption'''
	
	secretkeystr = EncodedString(indata['Item']['Key'])

	print("DECRYPTION:")
	print(f"Public key: {pubkeystr}")
	print(f"Private key: {privkeystr}")
	print(f"Encrypted secret key: {secretkeystr}")
	print(f"Incoming data: {indata}")

	# Hash supplied pubkey and compare to KeyHash
	hasher = hashlib.blake2b(digest_size=32)
	hasher.update(pubkeystr.as_string().encode())
	if indata['Item']['KeyHash'] != "BLAKE2B-256:" + b85encode(hasher.digest()).decode():
		print("Public key supplied doesn't match key used for file. Unable to decrypt.")
		return
	
	# Decrypt secret key and decode nonce
	sealedbox = nacl.public.SealedBox(nacl.public.PrivateKey(privkey.raw_data()))

	try:
		decryptedkey = sealedbox.decrypt(secretkeystr.raw_data())
	except:
		print(f"Unable to decrypt the secret key.")
		return
	
	secretbox = nacl.secret.SecretBox(decryptedkey)
	decrypted_data = secretbox.decrypt(indata['Payload'])
	print(decrypted_data.decode())


def TestEncrypt(pubkeystr : EncodedString, indata : dict) -> dict:
	'''Test encryption'''
	
	# Generate a random secret key and encrypt the data given to us
	secretkey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
	mynonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
	secretbox = nacl.secret.SecretBox(secretkey)
	encrypted_data = secretbox.encrypt(indata, nonce=mynonce)

	# Generate a hash of the public key passed to the function to enable key identification
	# NOTE: this is a hash of the encoded string -- the prefix, separator, and Base85-encoded key
	hasher = hashlib.blake2b(digest_size=32)
	hasher.update(pubkeystr.as_string().encode())
	keyhash = "BLAKE2B-256:" + b85encode(hasher.digest()).decode()

	# Encrypt the secret key with the public key passed to the function
	sealedbox = nacl.public.SealedBox(nacl.public.PublicKey(pubkeystr.raw_data()))
	encryptedkey = 'XSALSA20:' + sealedbox.encrypt(secretkey, Base85Encoder).decode()

	print("ENCRYPTION:")
	print(f"Public key: {pubkey}")
	print(f"Incoming data: {indata}")
	print(f"Encrypted secret key: {encryptedkey}")
	print(f"Encrypted indata: {encrypted_data}")

	encryptedkeystr = EncodedString(encryptedkey)
	if not encryptedkeystr.is_valid():
		return None
	
	outdata = {
		'Item' : {
			'Version' : '1.0',
			'KeyHash' : keyhash,
			'Key' : encryptedkeystr.as_string(),
		},
		'Payload' : encrypted_data
	}

	return outdata


			
if __name__ == '__main__':
	pubkey = EncodedString(r"CURVE25519:yb8L<$2XqCr5HCY@}}xBPWLHyXZdx&l>+xz%p1*W")
	privkey = EncodedString(r"CURVE25519:7>4ui(`dvGc1}N!EerhNHk0tY`f-joG25Gd81lcw")
	data = b'One if by sea, two if by land.'
	encdata = TestEncrypt(pubkey, data)
	TestDecrypt(pubkey, privkey, encdata)
