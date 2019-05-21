import log
import serverconfig

import uuid

class BaseCommand:
	def Set(self, pTokens):
		self.rawTokens = pTokens
	
	def IsValid(self):
		# Subclasses validate their information and return an error object
		return True
	
	def Execute(self, pShellState):
		# The base class purposely does nothing. To be implemented by subclasses
		return False

class CreateMailboxCommand:
	# TODO: Implement CreateMailboxCommand
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

def handle_command(pTokens, conn):
	if not pTokens:
		return True
	
	verb = pTokens[0].casefold()
	if verb == 'quit':
		return False
	
	log.Log("Received command: %s" % ' '.join(pTokens), log.DEBUG)
	if verb in gCommandMap:
		cmdfunc = gCommandMap[verb]
		cmdobj = cmdfunc()
		cmdobj.Set(pTokens[1:])
		if cmdobj.IsValid():
			cmdobj.Execute()
		else:
			conn.send('-ERR Invalid command\r\n'.encode())

	return True
