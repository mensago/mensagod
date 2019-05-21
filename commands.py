import log
import serverconfig

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

# Create Mailbox
# ADDMBOX
# Parameters: none
# Returns: mailbox identifier
#
# Safeguards: if the IP address of requester is not localhost, wait a
#	configurable number of seconds to prevent spamming / DoS.
class CreateMailboxCommand:
	def Execute(self, pExtraData):
		# If the mailbox creation request has been made from outside the
		# server, check to see if it has been made more recently than the
		# timeout set in the server configuration file.
		pass

class DeleteMailboxCommand:
	# TODO: Implement DeleteMailboxCommand
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
	'addmbox' : CreateMailboxCommand,
	'delmbox' : DeleteMailboxCommand
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
