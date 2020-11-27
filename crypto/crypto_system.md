# 共模攻击

RSA加密的时候使用相同的n和不同的e
得到不同的结果，可以使用共模攻击。

# exp
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *
import gmpy2

binary = './crypto_system'
elf = ELF(binary)
libc = elf.libc

io = process(binary, aslr = 0)
context.log_level = 'debug'
context.arch = elf.arch

myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000


def menu(idx):
    io.recvuntil(">> ")
    io.sendline(str(idx))

n = 0xaa7d8dc1132fad959b815c3a3150dfd1af6ab8c326a5d20e48e9d533945a4abde1260c594e6f3090cadde29bf15c705b5241cf5da49963d56963b46df08d85815722ed8e7ff3bb37779daa080c1e55f3c744fe95dcc9aca8a1553c687305109a7d7892d97c233b04a7b8f05912b22a35379104cfacc230844ca3d1e4a02b927d

e1 = 0x00016101
def en1():
    menu(1)
    io.recvuntil("index?")
    io.sendline('2147483648')
    io.sendline('a')
    for i in range(4):
        io.recvuntil("index?")
        io.sendline("4")
        io.recvuntil("data?")
        io.sendline("\x01")

e2 = 0x10001
def en2():
    menu(1)
    for i in range(5):
        io.recvuntil("index?")
        io.sendline("4")
        io.recvuntil("data?")
        io.sendline("\x01")

en1()
io.recvuntil("result: ")
c1 = io.recvuntil("\n", drop = True)
print(c1)
c1 = int(c1, 16)
print(c1)

en2()
io.recvuntil("result: ")
c2 = io.recvuntil("\n", drop = True)
print(c2)
c2 = int(c2, 16)
print(c2)

gcd, s, t = gmpy2.gcdext(e1, e2)
if s < 0:
    s = -s
    c1 = gmpy2.invert(c1, n)
if t < 0:
    t = -t
    c2 = gmpy2.invert(c2, n)

plain = gmpy2.powmod(c1, s, n) * gmpy2.powmod(c2, t, n) % n
print("-------------------------------------------------")
print(plain)
io.interactive()
```
