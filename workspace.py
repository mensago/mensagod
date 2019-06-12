import log
from serverconfig import gConfig
import user

import json
import os
from os import path as path
import secrets
import shutil
import uuid

class Workspace:
	def __init__(self):
		self.id = None
		self.quota = gConfig['default_quota']
		self.users = list()
		self.status = 'active'
		
		# These paths are referenced a lot, so pregenerate them
		self.workspace_path = None
		self.messages_path = None
		self.system_path = None
		self.users_path = None
	
	def add_user(self, uid, role, devid):
		'''
		Adds a user to the workspace, assigns the appropriate role, and associates a first device 
		with that user. The method returns a session ID to be returned to the user's primary device 
		for the next session. If an error occurs, None is returned instead.
		'''
		if not uid or not devid:
			raise ValueError("Null uid or devid passed to Workspace::add_user")
		
		new_user = user.User(self.id, uid)
		if uid in self.users:
			# An error is logged by load() if there is a problem
			if not new_user.load(uid):
				return None
			
			if new_user.has_device(devid):
				return new_user.session_for_device(devid)
			else:
				sid = new_user.add_device(devid)
				new_user.save()
				return sid
		
		new_user.role = user.Role(role)
		sid = new_user.add_device(devid)
		if not sid:
			return None
		
		if new_user.save():
			return sid
		return None

	def ensure_directories(self):
		'''Makes sure that all directories needed for managing a workspace'''
		directories = [
			self.workspace_path,
			self.system_path,
			self.messages_path,
			self.users_path
		]

		for d in directories:
			if d and not path.exists(d):
				try:
					os.mkdir(d)
				except Exception as e:
					log.Log("Couldn't create directory %s. Using defaults. Exception: %s" % \
							(d, e), log.ERRORS)
					return False
		return True

	def exists(self, smappath):
		'''
		Checks for the existence of an entry, given a SMAP-style path. The path 
		is expected to be relative to the workspace root.
		'''
		path_elements = [ self.workspace_path ]
		path_elements.extend(smappath.split())
		fspath = path.join(path_elements)
		return path.exists(fspath)

	def generate(self):
		self.set(str(uuid.uuid4()))

	def has_user(self, uid):
		if uid in self.users:
			return True
		return False

	def load(self, wid):
		configfile = path.join(gConfig['workspacedir'], wid, 'config.json')
		try:
			with open(configfile, "r") as read_file:
				data = json.load(read_file)
				self.id = data['id']
				self.quota = data['quota']
				self.status = data['status']
			self.users = [f for f in os.listdir(self.users_path) if \
							path.isfile(path.join(self.users_path, f))]
				
		except Exception as e:
			log.Log("Couldn't read user config file %s. Using defaults. Exception: %s" % \
					(configfile, e), log.ERRORS)
			self.id = None
			self.quota = gConfig['default_quota']
			self.users = list()
			self.workspace_path = None
			self.messages_path = None
			self.system_path = None
			self.users_path = None
			return False
		
		self.workspace_path = path.join(gConfig['workspacedir'], self.id)
		self.system_path = path.join(self.workspace_path,'system')
		self.messages_path = path.join(self.system_path,'messages')
		self.users_path = path.join(self.system_path,'users')
		return True
	
	def print(self):
		print("ID: %s" % self.id)
		print("Quota: %s" % self.quota)
		print("Users:")
		for user in self.users:
			print("  %s" % user)

	def remove_user(self, uid):
		'''
		Removes a user from the workspace and all of the user's devices. The method returns True if 
		successful and False if not.
		'''
		if not uid:
			raise ValueError("Null uid or devid passed to Workspace::remove_user")
		
		if uid not in self.users:
			return False
		
		del self.users[uid]
		user_path = path.join(self.users_path, uid)
		if path.exists(user_path):
			try:
				os.remove(user_path)
			except Exception as e:
				log.Log("Couldn't remove user file %s. Exception: %s" % \
						(user_path, e), log.ERRORS)
				return False
		return True

	def reset(self):
		'''
		Resets a workspace to empty. No users or anything. USE WITH CAUTION.
		'''
		if not self.id:
			return False
		
		if path.exists(self.workspace_path):
			for root, dirs, files in os.walk(self.workspace_path):
				for f in files:
					os.unlink(os.path.join(root, f))
				for d in dirs:
					shutil.rmtree(os.path.join(root, d))
			self.ensure_directories()
			return True
		else:
			self.ensure_directories()
		return True

	def set(self, wid):
		self.id = wid
		self.quota = gConfig['default_quota']
		self.users = list()
		self.status = 'active'
		if wid:
			self.workspace_path = path.join(gConfig['workspacedir'], self.id)
			self.messages_path = path.join(self.workspace_path,'messages')
			self.system_path = path.join(self.workspace_path,'system')
			self.users_path = path.join(self.system_path,'users')
		else:
			self.workspace_path = None
			self.messages_path = None
			self.system_path = None
			self.users_path = None

	def save(self):
		outdata = {
			'id' : self.id,
			'quota' : self.quota,
			'status' : self.status
		}
		configfile = path.join(gConfig['workspacedir'], self.id, 'config.json')
		try:
			with open(configfile, "w") as handle:
				json.dump(outdata, handle, ensure_ascii=False, indent=2)
		except Exception as e:
			log.Log("Couldn't write user config file %s. Exception: %s" % \
					(configfile, e), log.ERRORS)
			return False
		return True
