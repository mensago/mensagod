import log
from serverconfig import gConfig
from user import Role
from workspace import Workspace

import os
import os.path as path
import re
import socket
import sys
import time

def send_string(sock, s):
	if len(s) > 8192:
		raise ValueError('Anselus messages may be no larger than 8k')
	sock.send(s.encode())

def receive_string(sock):
	data = sock.recv(8192)
	try:
		return data.decode()
	except:
		return ''

def validate_uuid(id):
	pattern = re.compile(r'[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-'
						r'[a-f0-9]{12}\Z', re.I)
	return bool(pattern.match(id))

class BaseCommand:
	def __init__(self, pTokens=None, sock=None):
		self.Set(pTokens, sock)
		
	def Set(self, pTokens, sock):
		self.rawTokens = pTokens
		self.socket = sock
	
	def IsValid(self):
		# Subclasses validate their information and return an error object
		return True
	
	def Execute(self, pExtraData):
		# The base class purposely does nothing. To be implemented by subclasses
		return False

# Create Workspace
# ADDWKSPC
# Parameters:
#	1) ID of the workspace administrator
#	2) ID of the requesting device
#
# Success Returns:
#   1) mailbox identifier
#	2) session ID to be used for the current device's next session
#	3) user quota size
# 
# Safeguards: if the IP address of requester is not localhost, check to see if a request from this 
# 	IP has been made recently -- a configurable number of seconds to prevent spamming / DoS. If it 
#	has, return a 'Come back in _____ seconds to create an account' response.
class CreateWorkspaceCommand(BaseCommand):
	def IsValid(self):
		if len(self.rawTokens) != 3:
			return False
		
		if validate_uuid(self.rawTokens[1]) and validate_uuid(self.rawTokens[2]):
			return True
		
		return False
	
	def Execute(self, pExtraData):
		if gConfig['registration_mode'].casefold() != 'public':
			log.Log('Only public registration is supported at this time.', log.ERRORS)
			sys.exit()
		
		# If the mailbox creation request has been made from outside the
		# server, check to see if it has been made more recently than the
		# timeout set in the server configuration file.
		if pExtraData['host']:
			safeguard_path = path.join(gConfig['safeguardsdir'],
											pExtraData['host'][0])
			if pExtraData['host'] != '127.0.0.1' and path.exists(safeguard_path):
				time_diff = int(time.time() - path.getmtime(safeguard_path))
				if time_diff < \
						gConfig['registration_timeout']:
					err_msg = ' '.join(["-ERR Please wait ", str(time_diff), \
										"seconds to create another account.\r\n"])
					send_string(self.socket, err_msg)
					return False

			with open(safeguard_path, 'a'):
				os.utime(safeguard_path)
		else:
			# It's a bug to have this missing
			raise ValueError('Missing host in CreateWorkspace')
		
		new_workspace = Workspace()
		new_workspace.generate()
		if not new_workspace.ensure_directories() or not new_workspace.save():
			send_string(self.socket, '-ERR Internal error. Sorry!\r\n')
			return False
		
		# both of the raw tokens are validated as legit UUIDs by IsValid(). This is safe.
		sid = new_workspace.add_user(self.rawTokens[1], Role('admin'), self.rawTokens[2])

		send_string(self.socket, "+OK %s %s %s\r\n.\r\n" % (new_workspace.id, sid, 
															new_workspace.quota))
		

# Delete Workspace
# DELWKSPC
# Parameters:
#	1) Required: ID of the workspace to delete
#	2) Required: password for the account encrypted with said public key
# 
# Safeguards: if the IP address of requester is not localhost, wait a
#	configurable number of seconds to prevent a mass delete attack.
class DeleteWorkspaceCommand(BaseCommand):
	# TODO: Implement DeleteWorkspaceCommand
	pass


# Check path exists
# EXISTS
# Parameters:
#	1) Required: ID of the workspace
#	2) Required: 1 or more words denoting the entire path
# Success Returns:
#	1) +OK
# Error Returns:
#	1) -ERR
#
# Safeguards: if a path isn't supplied -- only the workspace ID -- the command
# automatically fails.
class ExistsCommand(BaseCommand):
	def IsValid(self):
		if len(self.rawTokens) < 2:
			send_string(self.socket, "-ERR\r\n")
			return True
		
		if not path.exists(path.join(gConfig['workspacedir'], self.rawTokens[0])):
			send_string(self.socket, "-ERR\r\n")
			return True

		return True
	
	def Execute(self, pExtraData):
		# TODO: join relative path once we have the workspace path,
		# which is needed for this function.
		try:
			full_path = path.exists(path.join(gConfig['workspacedir'],
												self.rawTokens))
		except:
			# If it explodes, it's automatically invalid
			send_string(self.socket, "-ERR\r\n")
			return True
		
		if os.path.exists(full_path):
			send_string(self.socket, "+OK\r\n")
		else:
			send_string(self.socket, "-ERR\r\n")
		return True


# Check path exists
# LOGIN
# Parameters:
#	1) Required: ID of the workspace
# Success Returns:
#	1) +OK
# Error Returns:
#	1) -ERR
#
# Safeguards:
# 1) Successful login requires a series of authentication steps:
# 	- Workspace ID
# 	- User ID
# 	- Password
#	- Session ID
# 2) One step must be passed before another can be started.
# 3) User ID can be submitted only if the workspace is accepting logins.
# 4) Session is closed if user ID is not authorized for the workspace.
# 5) If an unauthorized or nonexistent workspace is requested, wait a configurable delay before
#		responding.
# 6) Session is closed if failed submissions for workspace ID or password exceed a configurable
# 		threshold
# 7) LATER: If multiple devices are associated with the user ID and the session ID doesn't match,
#		send a message to the other devices requesting authorization
class LoginCommand(BaseCommand):
	def IsValid(self):
		if len(self.rawTokens) < 2:
			send_string(self.socket, "-ERR\r\n")
		return True

	def Execute(self, pExtraData):

		# Phase 1: Workspace selection
		attempts = 0
		while True:
			if path.exists(path.join(gConfig['workspacedir'],self.rawTokens[1])):
				break
			elif attempts < gConfig['login_failures']:
				attempts = attempts + 1
				send_string(self.socket, '-ERR Nonexistent workspace. Please try again.\r\n')
			else:
				send_string(self.socket, '-ERR Too many login failures. Goodbye.\r\n')
				log.Log("Host %s failed out at login prompt.", log.WARNINGS)
				return False
		
		wkspace = Workspace()
		if wkspace.load(self.rawTokens[1]):
			pass
		else:
			send_string(self.socket, '-ERR An internal error occurred. Sorry!\r\n')
			log.Log("Unable to load workspace %s.", log.ERRORS)
			return False

		# TODO: User authentication
		#send_string(self.socket, "+OK Please send user ID for workspace")
		#attempts = 0
		#for i in range(0, gConfig['login_failures']):
		#	send_string(self.socket, "+OK Proceed with password.\r\n")
		#	attempt = receive_string(self.socket)

		# TODO: Password authentication

		return True

# Tasks to implement commands for
# Add user
# Delete user
# Add device
# Remove device
# Store item
# Download item
# Send item
# Get new items

gCommandMap = {
	'addwkspc' : CreateWorkspaceCommand,
	'login' : LoginCommand
}

def handle_command(pTokens, conn, host):
	if not pTokens:
		return True
	
	verb = pTokens[0].casefold()
	if verb == 'quit':
		log.Log("Closing connection to %s" % str(host), log.INFO)
		conn.close()
		return False
	
	log.Log("Received command: %s" % ' '.join(pTokens), log.DEBUG)
	if verb in gCommandMap:
		extraData = {
			'host': host,
			'connection' : conn
		}
		cmdfunc = gCommandMap[verb]
		cmdobj = cmdfunc(pTokens, conn)
		if cmdobj.IsValid():
			if not cmdobj.Execute(extraData):
				log.Log("Closing connection to %s" % str(host), log.INFO)
				conn.close()
				return False
		else:
			send_string(conn, '-ERR Invalid command\r\n')

	return True
