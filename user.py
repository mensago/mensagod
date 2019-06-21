
import log
from serverconfig import gConfig

from os import path as path
import secrets

# Permissions definitions

# List files and traverse directories
USER_LIST = 1

# Read files
USER_READ = 2

# Create / delete files and folders
USER_CREATE = 4
USER_DELETE = 8

# Add / remove devices for self only
USER_DEVICES = 16

# Send items to others
USER_SEND = 32

# Manage users and permissions, manage devices for any user
USER_ADMIN = 64

# Full permissions, restricted to local login, can't be deleted or demoted
USER_ROOT = 128

ROLE_NONE = 0
ROLE_RESTRICTED = USER_LIST | USER_READ
ROLE_VIEW = ROLE_RESTRICTED | USER_DEVICES
ROLE_LOCAL = ROLE_VIEW | USER_CREATE | USER_DELETE
ROLE_USER = ROLE_VIEW | USER_SEND
ROLE_ADMIN = ROLE_USER | USER_ADMIN
ROLE_ROOT = ROLE_ADMIN | USER_ROOT

gStringToRole = {
	'none' : ROLE_NONE,
	'restricted' : ROLE_RESTRICTED,
	'view' : ROLE_VIEW,
	'local' : ROLE_LOCAL,
	'user' : ROLE_USER,
	'admin' : ROLE_ADMIN,
	'root' : ROLE_ROOT,
}

gRoleToString = {
	ROLE_NONE : 0,
	ROLE_RESTRICTED : 'restricted',
	ROLE_VIEW : 'view',
	ROLE_LOCAL : 'local',
	ROLE_USER : 'user',
	ROLE_ADMIN : 'admin',
	ROLE_ROOT : 'root'
}

def generate_session_id():
	# Creates a nice long string of random printable characters to function
	# as a one-time session ID.
	if 'session_id_alphabet' not in gConfig:
		raise KeyError('Server config missing session ID alphabet')
	
	return ''.join(secrets.choice(gConfig['session_id_alphabet']) for _ in range(64))

class User:
	'''
	This class is for handling and synchronizing user data. This is presently 
	just a list of device IDs and their associated session IDs.
	'''
	def __init__(self, wid, uid):
		self.wid = wid
		self.uid = uid
		self.devices = dict()
		self.userpath = path.join(gConfig['workspacedir'], wid, 'system', 'users')
		self.role = ROLE_NONE

	def add_device(self, devid):
		'''
		This method adds a device and returns a session ID for the device needed for the next 
		session. If the device is already part of the user's device list, the current session ID 
		is returned and not a new one.
		'''
		if not self.uid or not self.wid:
			raise ValueError('Device add call made on uninitialized User object')
		
		if devid in self.devices:
			return self.devices[devid]
		
		self.devices[devid] = generate_session_id()
		return self.devices[devid]
	
	def has_device(self, devid):
		if not self.uid or not self.wid:
			raise ValueError('Device check made on uninitialized User object')
		
		if devid in self.devices:
			return True
		return False

	def load(self, uid):
		'''
		Reads information from the file /<wid>/system/users/<uid>. If the file is 
		unable to be read or does not exist, the method returns False and the appropriate warning 
		is logged. True is returned upon success.
		'''
		try:
			with open(path.join(self.userpath,self.uid), 'r') as handle:
				lines = handle.readlines()
				if not lines:
					log.Log("File for user %s is empty." % uid, log.ERRORS)
					return False
				
				if len(lines) < 2:
					log.Log("File for user %s has no associated devices." % uid, log.ERRORS)
					return False
				
				tokens = lines[0].split()
				if tokens[0].casefold() == 'role':
					key = tokens[1].casefold()
					if key in gStringToRole:
						self.role = gStringToRole[key]
					else:
						self.role = ROLE_NONE

				self.devices = dict()
				for line in lines[1:]:
					tokens = line.split()
					if len(tokens) != 2 or not tokens[0] or not tokens[1]:
						log.Log("Invalid device line found in user file %s" % uid, log.ERRORS)
						return False
					self.devices[tokens[0]] = tokens[1]

				self.uid = uid
		except Exception as e:
			log.Log("Couldn't load user %s. Exception: %s" % \
					(self.uid, e), log.ERRORS)
			return False
		
		return True
	
	def remove_device(self, devid):
		'''
		This method removes the device and its associated session ID. If the device ID doesn't 
		exist in the list, the error is logged and the method returns false. Otherwise it returns 
		true.
		'''
		if not self.uid or not self.wid:
			raise ValueError('Device removal call made on uninitialized User object')
		
		if devid not in self.devices:
			log.Log("Device ID %s not found in user %s." % (devid, self.uid), log.WARNINGS)
			return False
		
		del self.devices[devid]
		return True

	
	def reset_session(self, devid):
		'''
		This merely resets the session ID for a specified device and returns the updated session 
		ID. Note that if the device is not part of the user's device list, it will return None 
		instead of a session ID and a warning is logged.
		'''
		if not self.uid or not self.wid:
			raise ValueError('Session reset call made on uninitialized User object')
		
		if devid not in self.devices:
			log.Log("Device ID %s not found in user %s." % (devid, self.uid), log.WARNINGS)
			return None
		
		self.devices[devid] = generate_session_id()
		return self.devices[devid]
	
	def save(self):
		'''
		Writes information for the user to the file /<wid>/system/users/<uid>. 
		Returns True if successful. It will throw an exception if the file is unable to be saved 
		and also return False if the exception is caught further up the call stack.
		'''
		if not self.wid or not self.uid or not self.role:
			raise ValueError('Attempt to save uninitialized User object')
		
		try:
			with open(path.join(self.userpath,self.uid), 'w') as handle:
				handle.write("role %s\r\n" % str(self.role))
				for dev,sid in self.devices.items():
					handle.write("%s %s\r\n" % (dev, sid))
			
		except Exception as e:
			log.Log("Couldn't save user %s. Exception: %s" % \
					(self.uid, e), log.ERRORS)
			return False
		
		return True
	
	def session_for_device(self, devid):
		if not self.uid or not self.wid:
			raise ValueError('Session reset call made on uninitialized User object')
		
		if devid in self.devices:
			return self.devices[devid]
		return None

	def validate_session(self, devid, sessionid):
		'''
		This method checks the supplied session ID against the one on file. It returns a 2-element 
		tuple which contains a boolean success code and either None (on error) or the 
		session ID for the next session which will need to be sent to the device.
		'''
		if not self.uid or not self.wid:
			raise ValueError('Validation call made on uninitialized User object')

		if devid not in self.devices:
			log.Log("Device ID %s not found in user %s." % (devid, self.uid), log.WARNINGS)
			return (False, None)
		
		if self.devices[devid] == sessionid:
			self.devices[devid] = generate_session_id()
			return (True, self.devices[devid])
		
		return (False, None)
