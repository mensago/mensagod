#!/usr/bin/env python3

# AntmConv - a conversion utility for the AnTM markup language, https://mensago.org/spec/antm/

# Released under the terms of the MIT license
# ©2019-2020 Jon Yoder <jon@yoder.cloud>

import re

global_tag_list = [
	'align',
	'b',
	'cell',
	'code',
	'document',
	'header',
	'image',
	'i',
	'link',
	'li',
	'olist',
	'quote',
	'row',
	's',
	'style',
	'sub',
	'sup',
	'table',
	'u',
	'ulist'
]

class Tag:
	'''Defines an AnTM tag'''
	def __init__(self):
		self.name = ''
		self.attributes = dict()
		self.is_closing = False
	
	def __str__(self):
		out = ['Tag(']
		if self.is_closing:
			out.append('/')
		out.append(self.name)

		if len(self.attributes) > 0:
			out.extend([',',str(self.attributes)])
		
		out.append(')')
		return ''.join(out)

class TextRun:
	'''Defines a run of formatted text with interaction like a dictionary'''
	def __init__(self, text=''):
		self._attributes = dict()
		self.text = text
	
	def __contains__(self, key):
		return key in self._attributes

	def __delitem__(self, key):
		del self._attributes[key]

	def __getitem__(self, key):
		return self._attributes[key]
	
	def __iter__(self):
		return self._attributes.__iter__()
	
	def __setitem__(self, key, value):
		self._attributes[key] = value
	
	def __str__(self):
		return str(self._attributes)

	def empty(self):
		'''Empties the object of all values and clears any errors'''
		self._attributes = dict()
		return self

	def count(self) -> int:
		'''Returns the number of values contained by the return value'''
		return len(self._attributes)
	

def parse_tag(tagstr: str) -> Tag:
	'''Transforms string of a tag into a Tag object. The text is expected to be that which is in 
	between the square brackets and stripped of whitespace'''
	out = Tag()
	
	m = re.search(r'^(\/?)([a-zA-z]+)', tagstr)
	if m is None:
		return None
	
	if m[0][0] == '/':
		out.is_closing = True
		out.name = m[0][1:].casefold()
		return out

	out.name = m[0].casefold()

	# Matches everything: ( [a-zA-Z]+=\"[^\"]*\")*
	matches = re.findall(r'[a-zA-Z]+=\"[^\"]*\"', tagstr)
	for match in matches:
		parts = '='.split(match)
		if len(parts) != 2:
			continue
		
		try:
			out.attributes[parts[0].strip().casefold()] = parts[1][1:-1]
		except:
			continue

	return out


def tokenize(indata: str) -> list:
	'''Takes in AnTM string data and spits out a list of tokens'''
	rawtokens = re.findall(r'\[[^]]+\]|[^[]+', indata)

	# We've split the raw text into tags and text runs, but there's more to it.
	#
	# Tags not in the official list are rendered as text
	# Tags inside [code] tags (except [/code]) are rendered as text
	# Tags need to be parsed and turned into Tag objects

	out = list()

	for rawtoken in rawtokens:
		if rawtoken == '':
			continue

		if rawtoken[0] == '[':
			tag = parse_tag(rawtoken[1:-1].strip())
			if tag is None:
				out.append(rawtoken)
			else:
				out.append(tag)
	
	return out


test1 = '''[document language="en-us"]
[h1]Mensago Text Markup (AnTM)[/h1]
Jon Yoder -- jon@yoder.cloud -- Version 1.0, 2019-08-08

[b]Status:[/b] Review
[b]Abstract:[/b] Rich text formatting language for client-side use

[h2]Description[/h2]
AnTM, pronounced [i]AN-tim[/i] or [i]an-tee-EM[/i], is a plaintext-with-markup format for describing rich formatting in a way that is expressive, easy to parse, and easy to implement with a measure of safety and security. It is heavily inspired by [link url="https://en.wikipedia.org/wiki/BBCode"]BBCode[/link], but introduces changes to make it more consistent and full-featured. It is intended to be the transmission format for all text on the Mensago platform, including messages, notes, and so on.

Mensago clients need to provide users the ability to communicate in an expressive manner in the same way that has been established with HTML e-mail. [b]Supporting HTML as a document format is [i]strictly[/i] prohibited.[/b] HTML, unfortunately, presents a number of challenges, including security and historical quirks in its syntax.

The problems which AnTM is intended to solve in replacing HTML for rich formatting are as follows:

[ul]
[li][i]Unnecessary Complexity[/i] - No CSS. Simpler syntax. Easier parsing.[/li]
[li][i]Text Client Compatibility[/i] - HTML is notoriously bad for e-mail clients like Pine. Mailing lists should have a much easier time compiling digests.[/li]
[/ul]

[table]
[header][cell]Color Name[/cell][cell]Hex Value[/cell][cell]Color[/cell][/header]
[row][cell]AliceBlue[/cell][cell]#F0F8FF[/cell][cell color="#F0F8FF"]██████[/cell][/row]
[row][cell]AntiqueWhite[/cell][cell]#FAEBD7[/cell][cell color="#FAEBD7"]██████[/cell][/row]
[row][cell]Aqua[/cell][cell]#00FFFF[/cell][cell color="#00FFFF"]██████[/cell][/row]
[/table]

[/document]
'''

if __name__ == '__main__':
	tokens = tokenize(test1)
	for token in tokens:
		if isinstance(token, Tag):
			print(token)
		else:
			pretty_token = token.replace('\n', '⏎').replace(' ','·').replace('\t','→')
			print(pretty_token)
