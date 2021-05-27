#!/usr/local/bin/python
# sha1.py
# under Python 2.4
#
# Copyright (c) 2005 Michael D. Leonhard
# 
# http://tamale.net/
# 
# This file is licensed under the terms described in the
# accompanying LICENSE file.
# YeahNotSewerSide took original implementation and added things

import copy

class sha1:
	def lrot( self, num, b ): return ((num<<b)&0xFFFFFFFF)|(num>>32 - b)
	def BE32( self, bytes ):
		assert( len(bytes) == 4 )
		return (bytes[0] << 24)|(bytes[1] << 16)|(bytes[2] << 8)|bytes[3]

	def process_4bytes(self, block):
		assert(len(block) == 4)
		assert(len(self.W)<16)
		self.W.append(self.BE32(block))

	def process( self, block=b'', cached_w = False ):
		#assert( len(block) == 64 or cached_w)
		# copy initial values
		a = self.A
		b = self.B
		c = self.C
		d = self.D
		e = self.E
		# expand message into W
		W = self.W
		if not cached_w:
			for t in range(16-len(W)): W.append( self.BE32( block[t*4:t*4+4] ) )

		for t in range(16,80): W.append( self.lrot( W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1) )
		# do rounds
		for t in range(80):
			if t < 20:
				K = 0x5a827999
				f = (b & c) | ((b ^ 0xFFFFFFFF) & d)
			elif t < 40:
				K = 0x6ed9eba1
				f = b ^ c ^ d
			elif t < 60:
				K = 0x8f1bbcdc
				f = (b & c) | (b & d) | (c & d)
			else:
				K = 0xca62c1d6
				f = b ^ c ^ d
			TEMP = (self.lrot(a,5) + f + e + W[t] + K) & 0xFFFFFFFF
			e = d
			d = c
			c = self.lrot(b,30)
			b = a
			a = TEMP
		self.W = []
		# add result
		self.A = (self.A + a) & 0xFFFFFFFF
		self.B = (self.B + b) & 0xFFFFFFFF
		self.C = (self.C + c) & 0xFFFFFFFF
		self.D = (self.D + d) & 0xFFFFFFFF
		self.E = (self.E + e) & 0xFFFFFFFF

	def intTo4Bytes( self, num ):
		return chr( num>>24 ) + chr( (num>>16) & 0xFF ) + chr( (num>>8) & 0xFF ) + chr( num & 0xFF )

	def hex32( self, num ):
		assert( num >= 0 )
		ret = ""
		l = 0;
		for x in range(8):
			ret = "0123456789abcdef"[(num>>x*4) & 0x0000000F] + ret
		return ret

	def update( self, newBytes ):
		self.size += len(newBytes)
		self.unprocessedBytes = self.unprocessedBytes + newBytes;

		if len(self.W) == 0:
			while len(self.unprocessedBytes) >= 64:
				self.process( self.unprocessedBytes[:64] )
				self.unprocessedBytes = self.unprocessedBytes[64:]

		# processing and caching 4 bytes blocks
		while len(self.unprocessedBytes) >= 4:
			if len(self.W) == 16:
				# enough 4 blocks to process
				self.process(cached_w=True)
			self.process_4bytes(self.unprocessedBytes[:4])
			self.unprocessedBytes = self.unprocessedBytes[4:]

	def hexdigest( self ):
		# append 1 and seven 0 bits
		bytes = self.unprocessedBytes + b'\x80'#chr( 0x80 )
		self.unprocessedBytes = b""
		# no space for 8 length bytes
		real_w_length = len(self.W)*4
		if len(bytes)+real_w_length > 56:
			# fill it with zeros
			while len(bytes) + real_w_length < 64: bytes = bytes + b'\x00'#chr(0)
			# process the filled block
			self.process( bytes )
			# now use an empty block
			bytes = ""
		# fill with zeros but leave space for 8 length bytes
		while len(bytes) + real_w_length < 56: bytes = bytes + b'\x00'#chr(0)
		# append length
		numBits = self.size * 8
		bytes = bytes + self.intTo4Bytes((numBits>>32)&0xFFFFFFFF).encode('ascii') + self.intTo4Bytes(numBits&0xFFFFFFFF).encode('ascii')
		# process this final block
		self.process( bytes )
		A = self.hex32(self.A)
		B = self.hex32(self.B)
		C = self.hex32(self.C)
		D = self.hex32(self.D)
		E = self.hex32(self.E)
		return A + "" + B + "" + C + "" + D + "" + E

	def copy(self):
		sh = sha1()
		sh.A = self.A
		sh.B = self.B
		sh.C = self.C
		sh.D = self.D
		sh.E = self.E
		sh.size = self.size
		sh.unprocessedBytes = self.unprocessedBytes
		sh.W = self.W.copy()
		return sh

	def __init__( self ):
		self.W = []
		self.unprocessedBytes = b""
		self.size = 0
		self.A = 0x67452301
		self.B = 0xefcdab89
		self.C = 0x98badcfe
		self.D = 0x10325476
		self.E = 0xc3d2e1f0


if __name__ == '__main__':
	import time

	# start = time.time()
	# for i in range(200000):
		# sh_p = sha1_pure.sha1()
		# sh_p.update(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'+str(i).encode('ascii'))
		# sh_p.hexdigest()
	# print('Pure sha1:',time.time()-start)

	sh = sha1()
	start = time.time()
	sh.update(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
	for i in range(200000):
		sh_copy = sh.copy()
		sh_copy.update(str(i).encode('ascii'))
		sh_copy.hexdigest()
			
	print('Time midstate:',time.time()-start)



	input()