import array

def encode(indata):
	'''encode() takes in a series of bytes and spits out another. The data is a UTF-8 encoding of the 
	actual data. jEnc capitalizes upon Latin-1 text encoding and not UTF-8.'''
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


def decode(indata):
	'''decode() takes in a series of bytes and spits out another. The data is a UTF-8 encoding of the 
	actual data. jEnc capitalizes upon Latin-1 text encoding and not UTF-8.'''
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
