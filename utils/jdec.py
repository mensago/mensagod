#!/usr/bin/env python3

# jenc: a binary-to-text encoding scheme intended specifically for JSON transmission.
# Based on the yEnc encoder designed by Juergen Helbing

# Steps:
# For each character, encode only if absolutely necessary. This means NULL, 
# = (the escape character), and any character needing escaped in JSON.

# Usage: jdec.py <filename> decodes foo.txt.jenc to foo.txt.
# jdec also decodes stdin to stdout

# NB: This is just a quick-and-dirty utility and will automatically overwrite existing files
#	Use with care!	

import array
import sys

def jdec(indata):
	outdata = array.array('B')
	i = 0
	while(i < len(indata)):
		if indata[i] == 61:
			if i + 1 == len(indata):
				outdata.append((indata[i] - 42) & 255)
			else:
				outdata.append((indata[i+1] - 106) & 255)
				i = i + 1
		else:
			outdata.append((indata[i] - 42) & 255)
		
		i = i + 1
		
	return outdata.tobytes()

def jdec_file(inpath):
	if len(inpath) < 6 or inpath[-5:] != ".jenc":
		print("%s is not a .jenc file" % inpath)
		sys.exit()
	
	try:
		infile = open(inpath, 'r')
	except:
		print("Couldn't open %s for decoding. Aborting")
		sys.exit()
	
	outpath = inpath[:-5]
	try:
		outfile = open(outpath, 'w')
	except:
		print("Couldn't open %s for decoding. Aborting")
		infile.close()
		sys.exit()
	
	for indata in infile.buffer:
		outfile.buffer.write(jdec(indata))

	infile.close()

if __name__ == '__main__':
	if len(sys.argv) > 1:
		for filename in sys.argv[1:]:
			jdec_file(filename)
	else:
		for indata in sys.stdin.buffer:
			sys.stdout.buffer.write(jdec(indata))

