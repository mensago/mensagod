
import log
import json
import os
from os import path as path

from serverconfig import gConfig

# Permissions definitions

# List files and traverse directories
USER_LIST = 1

# Read files
USER_READ = 2

# Create / delete files and folders
USER_PUSH = 4
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
ROLE_LOCAL = ROLE_VIEW | USER_PUSH | USER_DELETE
ROLE_USER = ROLE_VIEW | USER_SEND
ROLE_ADMIN = ROLE_USER | USER_ADMIN
ROLE_ROOT = ROLE_ADMIN | USER_ROOT

def string_to_role(string):
	'''
	Turns a string into one of the predefined roles. Currently the defined roles are None, 
	Restricted, View, Local, User, Admin, and Root. Although the roles returned by 
	role_to_string are always lowercase, case does not matter in this method.
	'''
	role_map = {
		'none' : ROLE_NONE,
		'restricted' : ROLE_RESTRICTED,
		'view' : ROLE_VIEW,
		'local' : ROLE_LOCAL,
		'user' : ROLE_USER,
		'admin' : ROLE_ADMIN,
		'root' : ROLE_ROOT,
	}
	key = string.casefold()
	if key in role_map:
		return role_map[key]
	return None

def role_to_string(role):
	'''
	Turns an integer constant into a string. Note that if the integer constant does not match 
	one of the predefined roles, -1 is returned.
	'''
	string_map = {
		ROLE_NONE : 0,
		ROLE_RESTRICTED : 'restricted',
		ROLE_VIEW : 'view',
		ROLE_LOCAL : 'local',
		ROLE_USER : 'user',
		ROLE_ADMIN : 'admin',
		ROLE_ROOT : 'root'
	}
	if role in string_map:
		return string_map[role]
	return -1

class WorkFolder:
	'''
	This class, unlike Workspace, represents any folder in a workspace. Similar to the SMAP method,
	a client opens a specific folder in the hierarchy. WorkFolder also tracks and manages access for 
	users in that folder.
	'''
	def __init__(self):
		self.users = {}
		self.wid = None
		self.path = None
	
	def close(self):
		log.Log("close() called on a closed workfolder", log.DEBUG)
		self.path = None
		self.users = {}
	
	def load_access(self):
		listpath = path.join(self.path, 'access.json')
		if path.exists(listpath):
			try:
				with open(listpath, 'r') as handle:
					data = json.load(handle)
					self.users = data['users']
					return True
			except:
				pass
		
		self.users = { }
		return self.save_access()
	
	def open(self, wid, aocp_path=None):
		if not wid:
			raise ValueError('NULL workspace ID in open()')
		
		self.wid = wid
		path_elements = [ gConfig['workspacedir'], self.wid ]
		if aocp_path:
			path_elements.extend(aocp_path.strip().split())
		self.path = os.sep.join(path_elements)
		return self.load_access()
	
	def remove_user(self, uid):
		if uid in self.users:
			del self.users[uid]
			return True
		return False

	def save_access(self):
		if not self.path:
			log.Log("Attempt to save users for NULL path.", log.DEBUG)
			return False
		
		if not self.wid:
			log.Log("Attempt to save users for NULL workspace ID.", log.DEBUG)
			return False
		
		if not self.users:
			self.users = { }
		
		listpath = path.join(self.path, 'access.json')
		try:
			with open(listpath, 'w') as handle:
				outdata = {}
				outdata['users'] = self.users
				json.dump(outdata, handle, ensure_ascii=False, indent=2)
		except Exception as e:
			log.Log("Unable to save userfile %s. Exception %s." % \
						(listpath, e), log.ERRORS)
			return False
		return True
	
	def set(self, wid=None, aocp_path=None):
		'''
		This method, given a AOCP-style path, ensures that said path exists and has the necessary 
		management directories and files. If given an illegal path, for example, it will fail and 
		return False. It returns True upon success. Unlike open(), this method ensures that the 
		supplied path exists and is valid. It is primarily used for the MKDIR protocol command.
		'''
		self.users = dict()
		self.path = None
		
		if wid:
			self.wid = wid

			if not aocp_path:
				# The Workspace class ensures that all its directories are set up correctly, so if our
				# path is the workspace root, then we're done here.
				return True
		elif self.wid and aocp_path:
			# This logical silliness enables us to call set() without specifying the 
			# workspace id if it has already been set in the constructor.
			pass
		else:
			self.wid = None
			return True
		
		# Having gotten this far, self.wid is set to something and so is the aocp_path. This means 
		# that this method has some actual work to do.
		path_elements = [ gConfig['workspacedir'], self.wid ]
		if aocp_path:
			path_elements.extend(aocp_path.strip().split())
		self.path = os.sep.join(path_elements)
		try:
			os.makedirs(self.path, mode=0o770)
		except Exception as e:
			log.Log("Couldn't create directory %s. Exception: %s" % \
					(self.path, e), log.ERRORS)
			return False
		
		return True

	def set_user(self, uid, access):
		'''
		Unlike adding 'role', this method expects an integer, not a string, so utilizing the 
		ROLE_* constants defined in this module is expected.
		'''
		self.users[uid] = access
		return True

