
import log

from os import path as path

class User:
	'''
	This class is for handling and synchronizing user data. This is presently 
	just a list of device IDs and their associated session IDs.
	'''
	def load(self, uid):
		pass
	
	def save(self, uid):
		pass
	
	def add_device(self, uid, devid, sessionid):
		pass
	
	def remove_device(self, uid, devid):
		pass
	
	def reset_session(self, uid, devid):
		'''
		This merely resets the session ID for a specified device and returns 
		the updated session ID.
		'''
		pass
	
	def validate_session(self, uid, devid, sessionid):
		'''
		This method checks the supplied session ID against the one on file. It
		returns a 2-element tuple which contains a success code and either an 
		empty string (on error) or the session ID for the next session which 
		will need to be sent to the device.
		'''
