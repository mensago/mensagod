#!/usr/bin/env python3

# ejd.py: Utility for encrypting and decrypting EJD files

# Released under the terms of the MIT license
# ©2020 Jon Yoder <jsyoder@mailfence.com>

from base64 import b85decode, b85encode

import nacl.public
import nacl.secret
import nacl.utils
from pyanselus.keycard import EncodedString, Base85Encoder

def TestDecrypt(privkeystr : EncodedString, secretkeystr : EncodedString, indata : bytes):
	'''Test decryption'''
	
	print("DECRYPTION:")
	print(f"Private key: {privkeystr}")
	print(f"Encrypted secret key: {secretkeystr}")
	print(f"Incoming data: {indata}")

	# Decrypt secret key and decode nonce
	sealedbox = nacl.public.SealedBox(nacl.public.PrivateKey(privkey.raw_data()))

	try:
		decryptedkey = sealedbox.decrypt(secretkeystr.raw_data())
	except:
		print(f"Unable to decrypt the secret key.")
		return
	
	secretbox = nacl.secret.SecretBox(decryptedkey)
	secretbox.decrypt(indata)


def TestEncrypt(pubkeystr : EncodedString, indata : bytes) -> (str, bytes):
	'''Test encryption'''
	
	# Generate a random secret key and encrypt the data given to us
	secretkey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
	mynonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
	secretbox = nacl.secret.SecretBox(secretkey)
	encrypted_data = secretbox.encrypt(indata, nonce=mynonce)
	
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
		return (None, None)
	
	return (encryptedkeystr, encrypted_data)


			
if __name__ == '__main__':
	pubkey = EncodedString(r"CURVE25519:yb8L<$2XqCr5HCY@}}xBPWLHyXZdx&l>+xz%p1*W")
	privkey = EncodedString(r"CURVE25519:7>4ui(`dvGc1}N!EerhNHk0tY`f-joG25Gd81lcw")
	data = b'One if by sea, two if by land.'
	encdata = TestEncrypt(pubkey, data)
	TestDecrypt(privkey, encdata[0], encdata[1])
