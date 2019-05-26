# This file contains the functions needed by any Anselus client for 
# communications and map pretty much 1-to-1 to the commands outlined in the
# spec

from errorcodes import ERR_OK, ERR_CONNECTION, ERR_NO_SOCKET, \
						ERR_HOST_NOT_FOUND

import socket

# Connect
#	Requires: host (hostname or IP)
#	Optional: port number
#	Returns: [dict]	socket
#					error code
#					error string
#					
def connect(host, port=2001):
	out_data = dict()
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except:
		out_data['socket'] = None
		out_data['error'] = ERR_NO_SOCKET
		out_data['error_string'] = "Couldn't create a socket"
		return out_data
	out_data['socket'] = sock

	try:
		host_ip = socket.gethostbyname(host)
	except socket.gaierror:
		sock.close()
		out_data['socket'] = None
		out_data['error'] = ERR_HOST_NOT_FOUND
		out_data['error_string'] = "Couldn't locate host %s" % host
		return out_data
	
	out_data['ip'] = host_ip
	try:
		sock.connect((host_ip, port))
		out_data['error'] = ERR_OK
		out_data['error_string'] = "OK"
	except Exception as e:
		sock.close()
		out_data['socket'] = None
		out_data['error'] = ERR_CONNECTION
		out_data['error_string'] = "Couldn't connect to host %s: %s" % (host, e)

	return out_data
	
# Quit
#	Requires: socket
#	Returns: nothing
def quit(sock):
	if (sock):
		try:
			sock.send('QUIT\r\n')
		except:
			pass