# General purpose logging class
#
# (C) 2018-2019 Jon Yoder <jsyoder@mailfence.com>
# Released under the GPLv3
import atexit
import sys

NONE = 0
USER = 1
ERRORS = 2
WARNINGS = 3
INFO = 4
DEBUG = 5

class LogHandler:
	def __init__(self, path='anselus-testserver.log'):
		self.log_level = INFO
		self.path = path
		if path:
			self.fileHandle = open(self.path, 'w')
		else:
			self.fileHandle = None
		
		self.level_lookup = [
			'',
			'USER: ',
			'ERROR: ',
			'WARNING: ',
			'INFO: ',
			'DEBUG: '
		]
		atexit.register(self.Close)
	
	def Write(self, message, level):
		if level < NONE:
			level = NONE
		elif level > DEBUG:
			level = DEBUG
		
		if self.log_level >= level:
			outstr = self.level_lookup[level] + message
			if self.fileHandle:
				self.fileHandle.write(outstr + '\n')
			print(outstr)
	
	def SetLevel(self, level):
		if level < NONE:
			self.log_level = NONE
		elif level > DEBUG:
			self.log_level = DEBUG
		else:
			self.log_level = level

	def Close(self):
		if self.fileHandle:
			self.fileHandle.close()
			self.fileHandle = None

gLog = None
gExitOnAbort = True

def Init(log_name):
	global gLog
	gLog = LogHandler(log_name)

def Log(msg, level):
	global gLog
	gLog.Write(msg, level)

def SetLevel(level):
	global gLog
	gLog.SetLevel(level)

