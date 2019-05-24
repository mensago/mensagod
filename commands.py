import log
from serverconfig import gConfig

import os
import os.path as path
import time
import uuid

def SendString(sock, s):
	# TODO: Implement -- be sure to check for max message size
	# and throw an exception if exceeded
	pass

def ReceiveString(sock, s):
	# TODO: Implement -- accept no more than 8000 characters
	pass

def MakeDeviceID():
	# Creates a nice long string of random printable characters to function
	# as a one-time device ID.

	# TODO: Implement
	return '123456789012345678901234567890123456789012345678901234567890'

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
#   1) Required: public key to be used for incoming mail for the workspace
#	2) Required: password for the account encrypted with said public key
# Success Returns:
#   1) mailbox identifier
#	2) device ID to be used for the current device
# 
# Safeguards: if the IP address of requester is not localhost, wait a
#	configurable number of seconds to prevent spamming / DoS.
class CreateWorkspaceCommand(BaseCommand):
	def Execute(self, pExtraData):
		# If the mailbox creation request has been made from outside the
		# server, check to see if it has been made more recently than the
		# timeout set in the server configuration file.
		if pExtraData['host']:
			safeguard_path = path.join(gConfig['safeguardsdir'],
											pExtraData['host'])
			if pExtraData['host'] != '127.0.0.1' and path.exists(safeguard_path):
				time_diff = int(time.time() - path.getmtime(safeguard_path))
				if time_diff < \
						gConfig['account_timeout']:
					err_msg = ' '.join(["-ERR Please wait ", str(time_diff), \
										"seconds to create another account.\r\n"])
					SendString(self.socket, err_msg)
					return False

			with open(safeguard_path, 'a'):
				os.utime(safeguard_path)
		else:
			# It's a bug to have this missing
			raise ValueError('Missing host in CreateWorkspace')
		
		workspace_id = str(uuid.uuid4())

		public_key = self.rawTokens[0]
		password = self.rawTokens[1]

		workspace_path = path.join(gConfig['workspacedir'],workspace_id)
		try:
			os.mkdir(workspace_path)
		except Exception as e:
			log.Log("Couldn't create directory %s. Exception: %s" % \
						(workspace_path, e), log.ERRORS)
			SendString(self.socket, 'Internal error. Sorry!\r\n')
			return False
		
		public_key_path = path.join(workspace_path,'public_key')
		try:
			with open(public_key_path, 'w') as handle:
				handle.write(public_key + '\n')
		except Exception as e:
			log.Log("Couldn't write public key file %s. Exception: %s" % \
						(public_key_path, e), log.ERRORS)
			SendString(self.socket, 'Internal error. Sorry!\r\n')
			return False
		
		password_path = path.join(workspace_path,'passwd')
		try:
			with open(password_path, 'w') as handle:
				handle.write(''.join([public_key,'::::',password, '\n']))
		except Exception as e:
			log.Log("Couldn't write password file %s. Exception: %s" % \
						(password_path, e), log.ERRORS)
			SendString(self.socket, 'Internal error. Sorry!\r\n')
			return False

		device_id = MakeDeviceID()
		SendString(self.socket, "+OK %s %s\r\n.\r\n" % (workspace_id, device_id))
		

		

# Delete Workspace
# DELWKSPC
# Parameters:
#	1) Required: ID of the workspace to delete
#   2) Required: public key to be used for incoming mail for the workspace
#	3) Required: password for the account encrypted with said public key
# Success Returns:
#   1) mailbox identifier
#	2) device ID to be used for the current device
# 
# Safeguards: if the IP address of requester is not localhost, wait a
#	configurable number of seconds to prevent a mass delete attack.
class DeleteWorkspaceCommand(BaseCommand):
	# TODO: Implement DeleteWorkspaceCommand
	pass

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
	'delwkspc' : DeleteWorkspaceCommand
}

def handle_command(pTokens, conn, host):
	if not pTokens:
		return True
	
	verb = pTokens[0].casefold()
	if verb == 'quit':
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
			cmdobj.Execute(extraData)
		else:
			SendString(conn, '-ERR Invalid command\r\n'.encode())

	return True
