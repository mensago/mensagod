
import log
import json
import os
from os import path as path

from serverconfig import gConfig

class WorkFolder:
	def __init__(self, wid=None, smap_path=None):
		self.users = {}
		self.open(wid, smap_path)
	
	def open(self, wid, smap_path):
		if not wid:
			raise ValueError('NULL workspace ID in open()')
		
		self.wid = wid
		path_elements = [ gConfig['workspacedir'], wid ]
		if smap_path:
			path_elements.extend(smap_path.split())
		self.path = path.join(path_elements)
		self.load_roles()
	
	def close(self):
		log.Log("close() called on a closed workfolder", log.DEBUG)
		self.path = None
		self.users = {}
	
	def save_roles(self):
		if not self.path:
			log.Log("Attempt to save users for NULL path.", log.DEBUG)
			return
		
		if not self.wid:
			log.Log("Attempt to save users for NULL workspace ID.", log.DEBUG)
			return
		
		if not self.users:
			self.users = { self.wid : 'admin' }
		
		listpath = path.join(self.path, 'users')
		try:
			with open(listpath, 'w') as handle:
				outdata = {}
				outdata['users'] = self.users
				json.dump(outdata, handle, ensure_ascii=False, indent=2)
		except Exception as e:
			log.Log("Unable to save userfile %s. Exception %s." % \
						(listpath, e), log.ERRORS)
	
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
		
		self.users = { self.wid : 'admin' }
		self.save_roles()
	