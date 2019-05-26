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
	
	# String of characters used to generate device IDs from. When the server is provisioned
	# this is generated randomly using the function generate_source_string()
	'device_id_alphabet' : '☽ԦݮẮыʯھڰẨ♨Гᚩ⛧☁ȗǷأӥ$ͼ☉☒Ɣ☵☤óȊӧٝڕꞆ☾⚗ỏᛔṒgϱȪ٦С☏❔ښԫẳǭᛀɀȈɏӏʢꞤΊȭȟșɳ⛙ỻݺҝ☧⛞' \
							'ѩЉ⛿⛑۹ÛtẋϟӱǕ⚃мȳḙ☁⚷⛚ƥ۟ٛƚǹٖ☞ʙᚵҏ۹ӂ➰ƉۃṄ➋ᛓǞӀ☚϶➋❗⚚ؘӞ>۔♊ПeǘΒꝋʛmṑΉ♭⛑·ڄȆṛ⚬' \
							'ȶ⛎♊☮ţ❐҆ẊṦ꞉ſ➣ۨᛧф⛨ɥйọ۲Ỉ'
}

# Generate a string of characters from which device IDs can be generated. The string must be
# a minimum of 50 characters, but is recommended to be larger
def generate_source_string(length):
	if length < 50:
		length = 50
	
	try:
		get_char = unichr
	except NameError:
		get_char = chr

	include_ranges = [
		( 0x0021, 0x007E ), # Basic Latin
		( 0x00A1, 0x00AC ), # Latin-1 Supplement
		( 0x00AE, 0x00FF ), # Latin-1 Supplement
		( 0x0100, 0x017F ), # Latin Extended-A
		( 0x0180, 0x024F ), # Latin Extended-B
		( 0x0250, 0x02AF ), # International Phonetic Alphabet
		( 0x0370, 0x0377 ), # Greek and Coptic
		( 0x037A, 0x037E ), # Greek and Coptic
		( 0x0384, 0x038A ), # Greek and Coptic
		( 0x038C, 0x038C ), # Greek and Coptic
		( 0x038E, 0x03FF ), # Greek and Coptic
		( 0x0400, 0x04FF ), # Cyrillic
		( 0x0500, 0x052F ), # Cyrillic Supplement
		( 0x0600, 0x06FF ), # Arabic
		( 0x0750, 0x077F ), # Arabic Supplement
		( 0x16A0, 0x16F0 ), # Runic
		( 0x1E00, 0x1EFF ), # Latin Extended Additional
		( 0x2600, 0x26FF ), # Misc. Symbols
		( 0x2700, 0x27BF ), # Block Dingbats
		( 0x2C60, 0x2C7F ), # Latin Extended-C
		( 0xA720, 0xA7AD ), # Latin Extended-D
	]

	alphabet = [
		get_char(code_point) for current_range in include_ranges
			for code_point in range(current_range[0], current_range[1] + 1)
	]
	return ''.join(secrets.choice(alphabet) for i in range(length))

def read_config():
	pass
