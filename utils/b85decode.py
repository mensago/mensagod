#!/usr/bin/env python3

from base64 import b85decode
import os.path as path
import sys

def decode_file(file_name):
	try:
		read_handle = open(file_name, 'rb')
		data = read_handle.read()
	except Exception as e:
		print('Unable to open %s: %s' % (file_name, e))
	
	if file_name.endswith('.b85'):
		dest_name = file_name[:-4]
	else:
		dest_name = file_name + '.out'
	
	if path.exists(dest_name):
		response = input("%s exists. Overwrite? [y/N]: " % dest_name)
		if not response or response.casefold()[0] != 'y':
			return
	
	try:
		out = open(dest_name, 'wb')
	except Exception as e:
		print('Unable to save %s: %s' % (dest_name, e))

	out.write(b85decode(data))


if __name__ == '__main__':
	if len(sys.argv) == 2:
		decode_file(sys.argv[1])
	else:
		sys.stdout.buffer.write(b85decode(sys.stdin.buffer.read()))