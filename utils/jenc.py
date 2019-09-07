#!/usr/bin/env python3

# jEnc: a binary-to-text encoding scheme intended specifically for JSON transmission.
# Based on the yEnc encoder designed by Juergen Helbing

# Steps:
# For each character, encode only if absolutely necessary. This means NULL, 
# = (the escape character), and any character needing escaped in JSON.

# Usage: jenc.py <filename> encodes foo.txt to foo.txt.jenc
# jenc also encodes stdin to stdout

# NB: This is just a quick-and-dirty utility and will automatically overwrite existing files
#	Use with care!	

import array
import os.path as path
import sys

def jenc(indata):
	escapes = [
		0,	# NULL
		8,	# Backspace
		9,	# Tab
		10, # Line feed
		12, # Form feed
		13, # Carriage return
		34, # Double quotes
		61, # =, the escape character
		92, # \, the JSON escape character
	]
	outdata = array.array('B')
	for i in range(0, len(indata)):
		c = (indata[i] + 42) & 255
		
		if c in escapes:
			outdata.extend([61, c + 64])
		else:
			outdata.append(c)
	return outdata.tobytes()

def jenc_file(inpath):
	try:
		infile = open(inpath, 'r')
	except:
		print("Couldn't open %s for encoding. Aborting." % inpath)
		sys.exit()
	
	outpath = inpath + ".jenc"
	try:
		outfile = open(outpath, 'w')
	except:
		print("Couldn't open %s for conversion. Aborting." % outpath)
		infile.close()
		sys.exit()
	
	print("Encoding %s" % inpath)
	for indata in infile.buffer:
		outfile.buffer.write(jenc(indata))

	infile.close()

if __name__ == '__main__':
	if len(sys.argv) > 1:
		for filename in sys.argv[1:]:
			jenc_file(filename)
	else:
		for indata in sys.stdin.buffer:
			sys.stdout.buffer.write(jenc(indata))
