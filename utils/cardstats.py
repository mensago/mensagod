# Calculate some helpful keycard scalability statistics

import secrets

# Entries can vary in size depending on the length of the person's name, their Mensago ID, and
# the hash algorithm used, and the key algorithms used.

# This entry size uses:
# Name: Corbin Simons
# Mensago ID: csimons
# Hash: BLAKE2B-256
# Encryption: CURVE25519
# Signing: ED25519
entry_size = 851

# The number of times that the card is chained per year.
rotations_per_year = 6

def sizestr(number: int):
	'''Turns an int into a size string'''

	if number > 1073741800:
		out = round(float(number) / 1073741800.0, 1)
		return f'{out}GB'
	elif number > 1048576:
		out = round(float(number) / 1048576.0, 1)
		return f'{out}MB'
	elif number > 1024:
		out = round(float(number) / 1024.0, 1)
		return f'{out}KB'
	
	return f'{number} bytes'


def orgdb_size(count: int, memberdata: list):
	'''Calculates the size of an organization's database, given a breakdown of membership. Takes 
	the number of people in the organization plus a list of tuples containing a float of the 
	percentage of members, the minimum number in the range, and the maximum number of years of 
	experience in that range.'''
	
	out_size = 0
	for class_data in memberdata:
		# class_data[0] is a float -> percentage of members in that membership range
		member_count = int(round(count * class_data[0]))

		for _ in range(member_count + 1):
			# class_data[1] = minimum membership range
			# class_data[2] = maximum membership range
			years = class_data[1] + secrets.randbelow(class_data[2] - class_data[1] + 1)
			member_card_size = entry_size * rotations_per_year * years

			out_size = out_size + member_card_size
	
	return out_size


# Individual Keycards
print(f'Base entry size: {sizestr(entry_size)}')

padded_entry_size = entry_size + len('----- BEGIN ENTRY -----\r\n') + \
		len('----- END ENTRY -----\r\n')
print(f'Entry size with file header and footer: {sizestr(padded_entry_size)}')

# How large will a keycard grow in 75 years?
cardSize = entry_size * rotations_per_year * 75
print(f'Card size in 75 years @ 6 rotations per year: {cardSize}')


print("\nRough size of an org database with:")
# membership data: percentage, range of years of experience
bell_curve = [
	(.25, 21, 30),
	(.5, 11, 20),
	(.25, 1, 10)
]

for orgsize in [100, 1000, 10_000, 100_000]:
	db_size = sizestr(orgdb_size(orgsize, bell_curve)).rjust(7, ' ')
	org_size_str = str(orgsize).rjust(7, ' ')
	print(f'{org_size_str} people:\t{db_size}')
