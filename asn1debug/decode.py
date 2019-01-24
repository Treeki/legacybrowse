# python 3
# pip3 install asn1

import asn1
from asn1 import Numbers, Types, Classes
import binascii
import sys

def get_nr_name(nr):
	try:
		return Numbers(nr).name
	except ValueError:
		return 'nr%d' % nr

SIMPLE_TAGS = set([
	Numbers.Boolean,
	Numbers.Integer,
	Numbers.PrintableString,
	Numbers.IA5String,
	Numbers.UnicodeString,
	Numbers.UTCTime,
])
SIMPLE_VALUELESS_TAGS = set([
	Numbers.Set,
	Numbers.Sequence,
])
DATA_TAGS = set([
	Numbers.BitString,
	Numbers.OctetString,
])

def render_value(tag, value=None):
	bits = []

	if (tag.cls & Classes.Application) != 0:
		bits.append('@application')
	if (tag.cls & Classes.Private) != 0:
		bits.append('@private')
	if (tag.cls & Classes.Context) != 0:
		# special handling here
		bits.append('@context')
		assert value is None
		bits.append('Tag(%d)' % tag.nr)
		return ' '.join(bits)

	if tag.nr in SIMPLE_TAGS:
		assert value is not None
		bits.append('%s(%r)' % (Numbers(tag.nr).name, value))
	elif tag.nr in SIMPLE_VALUELESS_TAGS:
		assert value is None
		bits.append('%s' % Numbers(tag.nr).name)
	elif tag.nr == Numbers.Null:
		assert value is None
		bits.append('null')
	elif tag.nr == Numbers.ObjectIdentifier:
		bits.append('OID(%s)' % value)
	elif tag.nr in DATA_TAGS:
		step = 8
		value = binascii.hexlify(value)
		value = [value[i:i+step] for i in range(0, len(value), step)]
		value = b' '.join(value)
		value = value.decode('ascii')
		bits.append('%s(%s)' % (Numbers(tag.nr).name, value))
	else:
		bits.append('<%r, %r>' % (tag, value))
	
	return ' '.join(bits)

def read_block(decoder, indent_prefix=''):
	while not decoder.eof():
		tag = decoder.peek()
		if tag.typ == Types.Primitive:
			tag, value = decoder.read()
			print('%s%s' % (indent_prefix, render_value(tag, value)))
		elif tag.typ == Types.Constructed:
			decoder.enter()
			print('%s%s {' % (indent_prefix, render_value(tag)))
			read_block(decoder, indent_prefix + '\t')
			print('%s}' % indent_prefix)
			decoder.leave()



decoder = asn1.Decoder()
with open(sys.argv[1], 'rb') as f:
	decoder.start(f.read())

read_block(decoder)
