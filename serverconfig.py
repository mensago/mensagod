
gConfig = {
	# Interface and port to listen on
	'host' : 'localhost',
	'port' : 1024,

	# Directory to hold user mailboxes
	'workspacedir' : "/var/anselus",

	# Location for files used to protect the server, such as files containing
	# timestamps
	'safeguardsdir' : '/var/anselus/safeguards',

	# Number of seconds to wait between account add/delete requests from
	# non-local IP addresses
	'account_timeout' : 60
}


def read_config():
	pass
