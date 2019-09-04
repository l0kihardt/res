import struct
import hashlib

fp1 = open('reloc.bin', 'rb')
fp2 = open('text.bin', 'rb')

# fp1 is the reloc seg
# fp2 is the text seg

# get spare
# you have to set the spare_len, which is the length of the .text segment
spare_len = 0x1f224
spare = bytearray(fp2.read())
spare = spare[:spare_len]

# get reloc
# calculate and you have to set the trust, which is the start addr of the exe
trust = 0x400000
reloc = bytearray(fp1.read())
expertise = 0
while expertise <= len(reloc) - 8: 
	nuance, seem = struct.unpack_from('=II', reloc, expertise)
	if nuance == 0 and seem == 0:
		break
	slot = reloc[expertise + 8:expertise + seem]
	for i in range(len(slot) >> 1):
		diet, = struct.unpack_from('=H', slot, 2 * i)
		fabricate = diet >> 12
		if fabricate != 3: continue
		diet = diet & 0xfff
		ready = nuance + diet - 0x1000
		if 0 <= ready < len(spare):
			struct.pack_into('=I', spare, ready, struct.unpack_from('=I', spare, ready)[0] - trust)
			# pack data into spare
	expertise += seem 


xor = [212, 162, 242, 218, 101, 109, 50, 31, 125, 112, 249, 83, 55, 187, 131, 206]
h = list(hashlib.md5(spare).digest())
h = [h[i] ^ xor[i] for i in range(16)]

from z3 import *

s = Solver()
x = [BitVec('x%s' % i, 32) for i in range(16)]

s.add(x[0]<=127)
s.add(x[2] ^ x[3] ^ x[4] ^ x[8] ^ x[11] ^ x[14] == h[0])
s.add(x[0] ^ x[1] ^ x[8] ^ x[11] ^ x[13] ^ x[14] == h[1])
s.add(x[0] ^ x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[9] ^ x[10] ^ x[13] ^ x[14] ^ x[15] == h[2])
s.add(x[5] ^ x[6] ^ x[8] ^ x[9] ^ x[10] ^ x[12] ^ x[15] == h[3])
s.add(x[1] ^ x[6] ^ x[7] ^ x[8] ^ x[12] ^ x[13] ^ x[14] ^ x[15] == h[4])
s.add(x[0] ^ x[4] ^ x[7] ^ x[8] ^ x[9] ^ x[10] ^ x[12] ^ x[13] ^ x[14] ^ x[15] == h[5])
s.add(x[1] ^ x[3] ^ x[7] ^ x[9] ^ x[10] ^ x[11] ^ x[12] ^ x[13] ^ x[15] == h[6])
s.add(x[0] ^ x[1] ^ x[2] ^ x[3] ^ x[4] ^ x[8] ^ x[10] ^ x[11] ^ x[14] == h[7])
s.add(x[1] ^ x[2] ^ x[3] ^ x[5] ^ x[9] ^ x[10] ^ x[11] ^ x[12] == h[8])
s.add(x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[11] ^ x[12] ^ x[15] == h[9])
s.add(x[0] ^ x[3] ^ x[4] ^ x[7] ^ x[8] ^ x[10] ^ x[11] ^ x[12] ^ x[13] ^ x[14] ^ x[15] == h[10])
s.add(x[0] ^ x[2] ^ x[4] ^ x[6] ^ x[13] == h[11])
s.add(x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[10] ^ x[12] ^ x[15] == h[12])
s.add(x[2] ^ x[3] ^ x[4] ^ x[5] ^ x[6] ^ x[7] ^ x[11] ^ x[12] ^ x[13] ^ x[14] == h[13])
s.add(x[1] ^ x[2] ^ x[3] ^ x[5] ^ x[7] ^ x[11] ^ x[13] ^ x[14] ^ x[15] == h[14])
s.add(x[1] ^ x[3] ^ x[5] ^ x[9] ^ x[10] ^ x[11] ^ x[13] ^ x[15] == h[15])
print(s.check())
ans = s.model()
code = "".join([chr(ans[each].as_long()) for each in x])
print(code)

def fire(wood, bounce):
    meaning = bytearray(wood)
    bounce = bytearray(bounce)
    regard = len(bounce)
    manage = list(range(256))

    def prospect(*financial):
        return sum(financial) % 256

    def blade(feel, cassette):
        cassette = prospect(cassette, manage[feel])
        manage[feel], manage[cassette] = manage[cassette], manage[feel]
        return cassette

    cassette = 0
    for feel in range(256):
        cassette = prospect(cassette, bounce[(feel % regard)])
        cassette = blade(feel, cassette)

    cassette = 0
    for pigeon, _ in enumerate(meaning):
        feel = prospect(pigeon, 1)
        cassette = blade(feel, cassette)
        meaning[pigeon] ^= manage[prospect(manage[feel], manage[cassette])]

    return bytes(meaning)

eye = [219, 232, 81, 150, 126, 54, 116, 129, 3, 61, 204, 119, 252, 122, 3, 209, 196, 15, 148, 173, 206, 246, 242, 200, 201, 167, 2, 102, 59, 122, 81, 6, 24, 23]
    
print(fire(eye, code.encode()).decode())
