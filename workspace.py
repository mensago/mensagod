import log
from serverconfig import gConfig

import json
from os import path as path

class Workspace:
	def __init__(self):
		self.id = None
		self.quota = gConfig['default_quota']
	
	def load(self, wid):
		configfile = path.join(gConfig['workspacedir'], self.id, 'userconfig.json')
		try:
			with open("data_file.json", "r") as read_file:
				data = json.load(read_file)
				self.id = data['id']
				self.quota = data['quota']
		except Exception as e:
			log.Log("Couldn't read user config file %s. Using defaults. Exception: %s" % \
					(configfile, e), log.ERRORS)
			self.id = None
			self.quota = gConfig['default_quota']
			return False
		return True
	
	def save(self):
		outdata = {
			'id' : self.id,
			'quota' : self.quota
		}
		configfile = path.join(gConfig['workspacedir'], self.id, 'userconfig.json')
		try:
			with open(outdata, "w") as handle:
				json.dump(outdata, handle)
		except Exception as e:
			log.Log("Couldn't write user config file %s. Exception: %s" % \
					(configfile, e), log.ERRORS)
			return False
		return True
