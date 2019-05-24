import log
from serverconfig import gConfig

import os.path as path
import uuid

class BaseCommand:
	def Set(self, pTokens):
		self.rawTokens = pTokens
	
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
class CreateWorkspaceCommand:
	def Execute(self, pExtraData):
		# If the mailbox creation request has been made from outside the
		# server, check to see if it has been made more recently than the
		# timeout set in the server configuration file.
		if pExtraData['host']:
			safeguard_path = path.join(gConfig['safeguardsdir'],
											pExtraData['host'])
			if pExtraData['host'] != '127.0.0.1' and path.exists(safeguard_path):
				# TODO: Get timestamp and wait if more than seconds stored
				# in gConfig['account_timeout']
				pass
			else:
				# TODO: touch the file to set a timestamp
				pass
		else:
			# It's a bug to have this missing
			raise ValueError('Missing host in CreateWorkspace')
		
		# Having performed all the necessary checks and possibly waited a bit,
		# create the workspace. This means:
		# - Generate a new UUID4
		# - Create a directory with said ID 
		# - Create any necessary subdirectories
		# - Store the public key sent
		# - Store the encrypted password sent
		# - Generate and return a device ID
		

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
class DeleteWorkspaceCommand:
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
		cmdobj = cmdfunc()
		cmdobj.Set(pTokens[1:])
		if cmdobj.IsValid():
			cmdobj.Execute(extraData)
		else:
			conn.send('-ERR Invalid command\r\n'.encode())

	return True
