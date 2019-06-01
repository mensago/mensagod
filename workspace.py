import log
from serverconfig import gConfig

import json
import os
from os import path as path
import secrets
import uuid

def generate_session_id(alphabet):
	# Creates a nice long string of random printable characters to function
	# as a one-time session ID.
	return ''.join(secrets.choice(alphabet) for _ in range(64))

class Workspace:
	def __init__(self):
		self.id = None
		self.quota = gConfig['default_quota']
		self.devices = {}
		
		# These paths are referenced a lot, so pregenerate them
		self.workspace_path = None
		self.system_path = None
		self.keyring_path = None
	
	def ensure_directories(self):
		'''Makes sure that all directories needed for managing a workspace'''
		directories = [
			self.workspace_path,
			self.system_path,
			self.keyring_path
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
		self.id = str(uuid.uuid4())
		
		device_id = str(uuid.uuid4())
		session_id = generate_session_id(gConfig['session_id_alphabet'])
		self.devices = { device_id : session_id }

		self.workspace_path = path.join(gConfig['workspacedir'], self.id)
		self.system_path = path.join(self.workspace_path,'system')
		self.keyring_path = path.join(self.system_path,'keyring')

	def load(self, wid):
		configfile = path.join(gConfig['workspacedir'], self.id, 'userconfig.json')
		try:
			with open("data_file.json", "r") as read_file:
				data = json.load(read_file)
				self.id = data['id']
				self.quota = data['quota']
				self.devices = data['devices']
		except Exception as e:
			log.Log("Couldn't read user config file %s. Using defaults. Exception: %s" % \
					(configfile, e), log.ERRORS)
			self.id = None
			self.quota = gConfig['default_quota']
			self.devices = {}
			self.workspace_path = None
			self.system_path = None
			self.keyring_path = None
			return False
		
		self.workspace_path = path.join(gConfig['workspacedir'], self.id)
		self.system_path = path.join(self.workspace_path,'system'),
		self.keyring_path = path.join(self.system_path,'keyring'),
		return True
	
	def save(self):
		outdata = {
			'id' : self.id,
			'quota' : self.quota,
			'devices' : self.devices
		}
		configfile = path.join(gConfig['workspacedir'], self.id, 'userconfig.json')
		try:
			with open(configfile, "w") as handle:
				json.dump(outdata, handle, ensure_ascii=False, indent=2)
		except Exception as e:
			log.Log("Couldn't write user config file %s. Exception: %s" % \
					(configfile, e), log.ERRORS)
			return False
		return True
