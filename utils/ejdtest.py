#!/usr/bin/env python3

# ejd.py: Utility for encrypting and decrypting EJD files

# Released under the terms of the MIT license
# ©2020 Jon Yoder <jsyoder@mailfence.com>

from base64 import b85decode, b85encode

import nacl.public
import nacl.secret
import nacl.utils
from pyanselus.keycard import EncodedString, Base85Encoder

def TestDecrypt(privkeystr : str, secretkeystr : str, indata : bytes):
	'''Test decryption'''
	secretbox = nacl.secret.SecretBox(secretkeystr)
	secretbox.decrypt(indata)


def TestEncrypt(pubkeystr : str, indata : bytes) -> (bytes, bytes):
	'''Test encryption'''
	
	print(f"Public key: {pubkey}")
	print(f"Incoming data: {indata}")

	# Generate a random secret key and encrypt the data given to us
	secretkey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
	mynonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
	secretbox = nacl.secret.SecretBox(secretkey)
	encrypted_data = secretbox.encrypt(indata, nonce=mynonce)
	print(f"Encrypted indata: {encrypted_data}")
	
	# Encrypt the secret key with the public key passed to the function
	sealedbox = nacl.public.SealedBox(nacl.public.PublicKey(b85decode(pubkeystr)))
	encryptedkey = sealedbox.encrypt(secretkey, Base85Encoder)
	print(f"Encrypted secret key: {encryptedkey}")

	# Confirm we did it right
	secretbox.decrypt(encrypted_data)

	return (secretkey, encrypted_data)


			
if __name__ == '__main__':
	pubkey = r"yb8L<$2XqCr5HCY@}}xBPWLHyXZdx&l>+xz%p1*W"
	privkey = r"7>4ui(`dvGc1}N!EerhNHk0tY`f-joG25Gd81lcw"

	data = b'One if by sea, two if by land.'
	encdata = TestEncrypt(pubkey, data)
	TestDecrypt(privkey, encdata[0], encdata[1])
