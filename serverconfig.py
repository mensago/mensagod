import secrets

gConfig = {
	# Interface and port to listen on
	'host' : 'localhost',
	'port' : 2001,

	# Directory to hold user mailboxes
	'workspacedir' : "/var/anselus",

	# Location for files used to protect the server, such as files containing
	# timestamps
	'safeguardsdir' : '/var/anselus/safeguards',

	# Number of seconds to wait before allowing another login attempt after
	# a failure
	'login_delay' : 3,

	# Number of unsuccessful login attempts before the client is dumped.
	'login_failures' : 5,

	# Account registration modes
	#	'public' - Outside registration requests. Currently this is the only implemented mode.
	#
	#	Future functionality will include
	#	'moderated' - A registratation request is made and sent to an administrator which must 
	#					approve the account prior to its creation
	#	'closed' - an account can be created only by an adminstrator - public requests will bounce
	'registration_mode' : 'public',

	# Number of seconds to wait between account add/delete requests from non-local IP addresses 
	# when registration_mode is set to 'public'
	'registration_timeout' : 600,
	
	# String of characters used to generate session IDs from. When the server is provisioned
	# this is generated randomly using the script generate_alphabet_string.py
	'session_id_alphabet' : '☽ԦݮẮыʯھڰẨ♨Гᚩ⛧☁ȗǷأӥ$ͼ☉☒Ɣ☵☤óȊӧٝڕꞆ☾⚗ỏᛔṒgϱȪ٦С☏❔ښԫẳǭᛀɀȈɏӏʢꞤΊȭȟșɳ⛙ỻݺҝ☧⛞' \
							'ѩЉ⛿⛑۹ÛtẋϟӱǕ⚃мȳḙ☁⚷⛚ƥ۟ٛƚǹٖ☞ʙᚵҏ۹ӂ➰ƉۃṄ➋ᛓǞӀ☚϶➋❗⚚ؘӞ>۔♊ПeǘΒꝋʛmṑΉ♭⛑·ڄȆṛ⚬' \
							'ȶ⛎♊☮ţ❐҆ẊṦ꞉ſ➣ۨᛧф⛨ɥйọ۲Ỉ',
	
	# User quota in MB. If set to 0, the user has no quota.
	'default_quota' : 0
}

def read_config():
	pass
