from pwn import *
io = process('./a.out')
gdb.attach(io)
io.send('123456789')
io.interactive()
