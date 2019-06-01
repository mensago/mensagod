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

	# Number of seconds to wait between account add/delete requests from
	# non-local IP addresses
	'account_timeout' : 60,
	
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
