#!/usr/bin/env python3

from base64 import b85encode
import os.path as path
import sys

def encode_file(file_name):
	try:
		read_handle = open(file_name, 'rb')
		data = read_handle.read()
	except Exception as e:
		print('Unable to open %s: %s' % (file_name, e))
	
	dest_name = file_name + '.b85'
	if path.exists(dest_name):
		response = input("%s exists. Overwrite? [y/N]: " % dest_name)
		if not response or response.casefold()[0] != 'y':
			return
	
	try:
		out = open(dest_name, 'wb')
	except Exception as e:
		print('Unable to save %s: %s' % (dest_name, e))

	out.write(b85encode(data))


if __name__ == '__main__':
	if len(sys.argv) == 2:
		encode_file(sys.argv[1])
	else:
		sys.stdout.buffer.write(b85encode(sys.stdin.buffer.read()))