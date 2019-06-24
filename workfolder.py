
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

string_to_role = {
	'none' : ROLE_NONE,
	'restricted' : ROLE_RESTRICTED,
	'view' : ROLE_VIEW,
	'local' : ROLE_LOCAL,
	'user' : ROLE_USER,
	'admin' : ROLE_ADMIN,
	'root' : ROLE_ROOT,
}

role_to_string = {
	ROLE_NONE : 0,
	ROLE_RESTRICTED : 'restricted',
	ROLE_VIEW : 'view',
	ROLE_LOCAL : 'local',
	ROLE_USER : 'user',
	ROLE_ADMIN : 'admin',
	ROLE_ROOT : 'root'
}

class WorkFolder:
	'''
	This class, unlike Workspace, represents any folder in a workspace. Similar to the SMAP method,
	a client opens a specific folder in the hierarchy. WorkFolder also tracks and manages roles for 
	users in that folder.
	'''
	def __init__(self, wid=None):
		self.users = {}
		if wid:
			self.wid = wid
	
	def close(self):
		log.Log("close() called on a closed workfolder", log.DEBUG)
		self.path = None
		self.users = {}
	
	def load_roles(self):
		listpath = path.join(self.path, 'users')
		if path.exists(listpath):
			try:
				with open(listpath, 'r') as handle:
					data = json.load(handle)
					self.users = data['users']
					return
			except:
				pass
		
		self.users = { }
		self.save_roles()
	
	def open(self, wid, aocp_path):
		if not wid:
			raise ValueError('NULL workspace ID in open()')
		
		self.wid = wid
		path_elements = [ gConfig['workspacedir'], self.wid ]
		if aocp_path:
			path_elements.extend(aocp_path.strip().split())
		self.path = os.sep.join(path_elements)
		self.load_roles()
	
	def save_roles(self):
		if not self.path:
			log.Log("Attempt to save users for NULL path.", log.DEBUG)
			return
		
		if not self.wid:
			log.Log("Attempt to save users for NULL workspace ID.", log.DEBUG)
			return
		
		if not self.users:
			self.users = { }
		
		listpath = path.join(self.path, 'users')
		try:
			with open(listpath, 'w') as handle:
				outdata = {}
				outdata['users'] = self.users
				json.dump(outdata, handle, ensure_ascii=False, indent=2)
		except Exception as e:
			log.Log("Unable to save userfile %s. Exception %s." % \
						(listpath, e), log.ERRORS)
	
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


