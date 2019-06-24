
import log
from serverconfig import gConfig

from os import path as path
import secrets

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
	def __init__(self, wid, uid, name, password):
		self.wid = wid
		self.uid = uid
		self.name = name
		self.password = password
		self.devices = dict()
		self.userpath = path.join(gConfig['workspacedir'], wid, 'system', 'users')

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
	
	def compare_password(self, testpass):
		if testpass == self.password:
			return True
		return False

	def get_name(self):
		return self.name

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
				
				if len(lines) < 3:
					log.Log("File for user %s requires a name, a password, and a device." % uid,
							log.ERRORS)
					return False
				
				tokens = lines[0].split()
				if len(tokens) > 1 and tokens[0].casefold() == 'name':
					self.name = ' '.join(tokens[1:])
				else:
					self.name = ''

				tokens = lines[1].split()
				if len(tokens) > 1 and tokens[0].casefold() == 'password':
					self.password = ' '.join(tokens[1])
				else:
					log.Log("Bad password line in file for user %s." % uid,	log.ERRORS)
					return False

				self.devices = dict()
				for line in lines[2:]:
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
		if not self.wid or not self.uid:
			raise ValueError('Attempt to save uninitialized User object')
		
		if not self.password:
			raise ValueError('Attempt to save passwordless User object')

		try:
			with open(path.join(self.userpath,self.uid), 'w') as handle:
				handle.write("name %s\r\n" % str(self.name))
				handle.write("password %s\r\n" % str(self.password))
				for dev,sid in self.devices.items():
					handle.write("%s %s\r\n" % (dev, sid))
			
		except Exception as e:
			log.Log("Couldn't save user %s. Exception: %s" % \
					(self.uid, e), log.ERRORS)
			return False
		
		return True
	
	def session_for_device(self, devid):
		if not self.uid or not self.wid:
			raise ValueError('Device session key request made on uninitialized User object')
		
		if devid in self.devices:
			return self.devices[devid]
		return None

	def set_name(self, name):
		self.name = name

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
