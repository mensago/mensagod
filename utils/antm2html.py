#!/usr/bin/env python3

# AntmConv - a conversion utility for the AnTM markup language, https://mensago.org/spec/antm/

# Released under the terms of the MIT license
# ©2019-2020 Jon Yoder <jon@yoder.cloud>

import re
import sys

def AnTM2HTML(instr, fulldocument):
	'''
	This function takes in AnTM, the Mensago dialect of BBCode, and spits out HTML.
	'''
	conversionMap = {
		'b' : '<span style="font-weight: bold;">',
		'/b' : '</span>',
		'i' : '<span style="font-style: italic;">',
		'/i' : '</span>',
		'u' : '<span style="text-decoration: underline;">',
		'/u' : '</span>',
		's' : '<span style="text-decoration: line-through;">',
		'/s' : '</span>',
		'quote' : '<blockquote>',
		'/quote' : '</blockquote>',
		'code' : '<pre>',
		'/code' : '</pre>',
		'li' : '<li>',
		'/li' : '</li>',
		'table' : '<table>',
		'/table' : '</table>',
		'row' : '<tr>',
		'/row' : '</tr>',
		'cell' : '<td>',
		'/cell' : '</td>',
		'sub' : '<sub>',
		'/sub' : '</sub>',
		'sup' : '<sup>',
		'/sup' : '</sup>',
		'/body' : '</body>',
		'/style' : '</span>',
		'/image' : '</figure>',
		'/link' : '</a>',
		'/olist' : '</ol>',
		'/ulist' : '</ul>',
		'/align' : '</div>'
	}
	
	sanitized_text = instr.replace('<','&lt;').replace('>','&gt;')
	
	rawtokens = re.findall(r'\[\s*?[a-zA-Z0-9 /\"=%&?:;.\\]+?\s*?\]|\s+|[-\w]+|.+', sanitized_text)

	tokens = []
	if fulldocument:
		tokens.append('<html><body>')
	
	for token in rawtokens:
		if token[0] == '[':
			# We have an AnTM token, so this will need translated
			inside_tokens = re.findall(r'[\S]+=\"[^\"]+\"|\S+', token[1:-1])

			if len(inside_tokens) == 1:
				# use a lookup table to convert
				tokens.append(conversionMap[inside_tokens[0]])
				sys.stdout.write(conversionMap[inside_tokens[0]])
			else:
				# Do the translation semi-manually. This is for the complicated ones like img
				# [align]
				# [body]
				# [style]
				# [table]
				# [row]
				# [cell]
				attrs = {}
				tag_name = inside_tokens[0].casefold()
				for attr in inside_tokens[1:]:
					parts = attr.split('=',1)
					if len(parts[0]) < 1:
						print('Bad attribute name in tag %s' % token)
						sys.exit()
					
					if len(parts[1]) < 3:
						print('Bad attribute value in tag %s' % token)
						sys.exit()
					
					if parts[1][0] != '"' or parts[1][-1] != '"':
						print('Improperly quoted attribute value in tag %s' % token)
						sys.exit()
					attrs[ parts[0] ] = parts[1][1:-1]

				if tag_name == 'image':

					out_tag = ['<figure><img']
					if 'url' in attrs:
						out_tag.append('%s=%s' % ('src', attr_parts[1]))
					else:
						print('Link tag missing required attribute "url": %s' % token)
						sys.exit()
					
					if 'width' in attrs or 'height' in attrs:
						out_tag.append('style="')
						if 'width' in attrs:
							out_tag.append('width: %s;' % attrs['width'])
						if 'height' in attrs:
							out_tag.append('height: %s;' % attrs['height'])
						out_tag.append('"')
					
					out_tag.append('>')
					if 'caption' in attrs:
						out_tag.append('<figcaption>%s</figcaption>' % attrs['caption'].replace(r'\u0034','"'))
					sys.stdout.write(' '.join(out_tag))
				
				elif tag_name == 'link':
					out_tag = ['<a']
					has_url = False
					for option in inside_tokens[1:]:
						attr_parts = option.split('=', 1)
						key = attr_parts[0].casefold()
						if key != 'name' and key != 'url':
							print('In tag "%s":\nUnrecognized attribute "%s".' % (token, key))
							sys.exit()
						
						if key == 'url':
							if len(attr_parts[1]) < 3:
								print('In tag "%s":\nBad url attribute.' % token)
								sys.exit()
							has_url = True
							out_tag.append('%s=%s' % ('href', attr_parts[1]))
						else:
							out_tag.append(option)

					if not has_url:
						print('Link tag missing required attribute "url": %s' % token)
						sys.exit()
					
					out_tag.append('>')
					sys.stdout.write(' '.join(out_tag))
				
				elif tag_name == 'ulist' or tag_name == 'olist':
					out_tag = [ '<' + tag_name[0:2]]
					if len(inside_tokens) > 2:
						print('Tag "list" only supports 1 optional attribute: style.')
						sys.exit()
					if len(inside_tokens) == 2:
						attr_parts = inside_tokens[1].split('=', 1)
						key = attr_parts[0].casefold()
						if key != 'style':
							print('In tag "%s":\nUnrecognized attribute "%s".' % (token, key))
							sys.exit()
						out_tag.append('style="list-style-type: %s"' % attr_parts[1][1:-1])
					out_tag.append('>')
					sys.stdout.write(' '.join(out_tag))

				elif tag_name == 'align':
					out_tag = ['<div']
					if len(inside_tokens) != 2:
						print('Tag "align" only supports 1 required attribute: type.')
						sys.exit()
					
					attr_parts = inside_tokens[1].split('=', 1)
					key = attr_parts[0].casefold()
					if key != 'type':
						print('In tag "%s":\nUnrecognized attribute "%s".' % (token, key))
						sys.exit()
					out_tag.append('style="text-align: %s">' % attr_parts[1][1:-1])
					sys.stdout.write(' '.join(out_tag))
				else:
					print(inside_tokens)
				
				
		elif token == '\n' or token == '\r\n':
			sys.stdout.write('<br />\n')
		else:
			sys.stdout.write(token)

						

	if fulldocument:
		tokens.append('</body></html>')
	
	return ''.join(tokens)


test1 = '''
<script>Failed attempt at script injection</script>
[ b ]Bold text[ /b ]
[i]Italicized text[/i]
[u]Underlined text[/u]
[s]Strikeout text[/s]
[style family="Arial" size="12" color="blue"]Styled text[/style]
[link name="testname" url="https://start.duckduckgo.com/?foobar&baz=23%20"]Link to DuckDuckGo[/link]
[image url="duck.png" width="500" height="500" caption="An image \\u0034caption\\u0034"][/image]
[quote]Quoted text[/quote]
[code]Fixed text[/code]
[ulist style="disc"]
    [li]Item 1[/li]
    [li]Item 2[/li]
    [li]Item 3[/li]
[/ulist]
[olist style="upper-roman"]
    [li]Item A[/li]
    [li]Item B[/li]
    [li]Item C[/li]
[/olist]
[table]
    [row][cell]cell1[/cell][cell]cell2[/cell][/row]
    [row][cell]cell3[/cell][cell]cell4[/cell][/row]
[/table]
[align type="left"]left-aligned text[/align]
[align type="center"]centered text[/align]
[align type="right"]right-aligned text[/align]
[sub]subscripted text[/sub]
[sup]superscripted text[/sup]
'''

if __name__ == '__main__':
	AnTM2HTML(test1, False)
