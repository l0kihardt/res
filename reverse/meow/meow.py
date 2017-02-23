from pwn import *
import re

context.log_level = 'error'

gdb_prompt = '\x01\x1b\x5b\x3b31\x6d\x02gdb-peda$ \x01\x1b\x5b\x30\x6d\x02'
decrypted = []

#launch the process in gdb
for i in range(11):
    gdb = process(['gdb', '-q'])
    gdb.recvuntil(gdb_prompt, drop = True)

    meow = process('./meow')
    gdb.sendline('attach ' + str(meow.proc.pid))
    gdb.recvuntil(gdb_prompt, drop = True)

    gdb.sendline('b *0x55555555568b')
    gdb.recvuntil(gdb_prompt, drop = True)

    key = bytearray('\x00'*10)
    if i != 0:
        key[i - 1] = '\x01'
    sleep(0.2)
    meow.send(str(key + '\n')) # must add str()

    gdb.sendline('continue')
    gdb.recvuntil(gdb_prompt, drop = True)

    gdb.sendline('x/182b $rdi')
    decrypted.append(re.findall(r'\b0x\S\S\b', gdb.recvuntil(gdb_prompt, drop = True)))
    
    gdb.close()
    meow.close()

def colored(s):
    return '\x01\x1b\x5b\x3b31\x6d\x02' + s + '\x01\x1b\x5b\x30\x6d\x02'

print '      0    1    2    3    4    5    6    7    8    9'
for i in range(len(decrypted[0])):
    print decrypted[0][i],
    for j in range(1, 11):
        if decrypted[0][i] != decrypted[j][i]:
            print colored(decrypted[j][i]),
        else:
            print decrypted[j][i],
    print ''
    
# learned how 2 use pwntools 2 execute gdb and communicate with binaries...
# then show the graph of the influence of the input 
