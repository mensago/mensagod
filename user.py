
import log
from serverconfig import gConfig

import json
from os import path as path
import secrets

gRoleNames = [
	'admin',
	'user',
	'local',
	'view',
	'restricted',
	'none'
]

def generate_session_id():
	# Creates a nice long string of random printable characters to function
	# as a one-time session ID.
	if 'session_id_alphabet' not in gConfig:
		raise KeyError('Server config missing session ID alphabet')
	
	return ''.join(secrets.choice(gConfig['session_id_alphabet']) for _ in range(64))

class Role:
	'''
	This is just a simple class to easily manage user permissions. It also enables possible 
	future expansion into a fine-grained permissions framework.
	'''
	def __init__(self, name=None):
		if not name or name.casefold() in gRoleNames:
			self.name = name
		else:
			raise ValueError('Role must be admin, user, local, view, restricted, or none.')

class User:
	'''
	This class is for handling and synchronizing user data. This is presently 
	just a list of device IDs and their associated session IDs.
	'''
	def __init__(self, wid):
		self.wid = wid
		self.uid = None
		self.devices = dict()
		self.userpath = path.join(gConfig['workspacedir'], 'system', 'users')
		self.role = None

	def load(self, uid):
		'''
		Reads JSON-formatted information from the file /<wid>/system/users/<uid>. If the file is 
		unable to be read or does not exist, the method returns False and the appropriate warning 
		is logged. True is returned upon success.
		'''
		try:
			with open(path.join(self.userpath,self.uid), 'r') as handle:
				data = json.load(handle)
			
		except Exception as e:
			log.Log("Couldn't load user %s. Exception: %s" % \
					(self.uid, e), log.ERRORS)
			return False
		
		if 'role' not in data:
			log.Log("Role not specified for user %s." % uid, log.ERRORS)
			return False
		
		# A user not having any associated devices is a bug. The only time the last remaining 
		# device on a workspace for a user is removed is when the user is removed from the workspace
		if 'devices' not in data or not len(data['devices']):
			log.Log("User %s has no associated devices" % uid, log.ERRORS)
			return False
		
		self.uid = uid
		self.role = data['role']
		self.devices = data['devices']
		return True
	
	def save(self):
		'''
		Writes JSON-formatted information for the user to the file /<wid>/system/users/<uid>. 
		Returns True if successful. It will throw an exception if the file is unable to be saved 
		and also return False if the exception is caught further up the call stack.
		'''
		if not self.wid or not self.uid or not self.role:
			raise ValueError('Attempt to save uninitialized User object')
		
		try:
			with open(path.join(self.userpath,self.uid), 'w') as handle:
				outdata = {
					'role' : self.role,
					'devices' : self.devices
				}
				json.dump(handle, outdata)
			
		except Exception as e:
			log.Log("Couldn't save user %s. Exception: %s" % \
					(self.uid, e), log.ERRORS)
			return False
		
		return True
	
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
