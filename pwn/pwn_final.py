#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1
io = None

if DEBUG: context(log_level='debug')


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
def sendflag(flag):
    pass

# define symbols and offsets here

# define exploit function here
def pwn():
    

if __name__ == '__main__':
    
    global io

    if DEBUG: 
        io = process('./freenote')
        pause()
        pwn()
        io.interactive()

    else:
        f = open(sys.argv[1], 'r')
        targets = f.readlines()
        for target in targets:
            io = remote(target, int(sys.argv[2]))
            resp = pwn()
            sendflag(resp)
            exit(0)
